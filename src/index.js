/**
 * Clinic AI Receptionist — Worker
 * One deploy of this = one clinic.
 *
 * Everything is configured from the dashboard after deploy — no Wrangler
 * secrets needed. First person to open the dashboard sets the admin
 * password; that becomes the "root admin" login for this clinic's system.
 *
 * Routes:
 *   GET  /api/setup-status         <- public: has an admin password been set yet?
 *   POST /api/setup                <- public, but only works ONCE: sets the first admin password
 *   POST /api/login                <- public: password -> session token
 *   GET  /api/settings             <- admin: read clinic/Twilio/Resend/VAPI config
 *   POST /api/settings             <- admin: update clinic/Twilio/Resend/VAPI config
 *   POST /api/settings/regenerate-vapi-secret <- admin: rotate the VAPI webhook secret
 *   GET  /api/appointments, POST, PATCH /:id, PUT /:id
 *   GET  /api/calls
 *   GET  /api/messages
 *   GET  /api/summary
 *   GET  /api/export
 *   POST /webhook/vapi             <- VAPI calls this; verified via stored secret, not admin auth
 */

// ── Helpers ────────────────────────────────────────────────────

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json",
      "Access-Control-Allow-Origin": "*", // tighten to your dashboard domain in production
      "Access-Control-Allow-Headers": "Content-Type, Authorization",
      "Access-Control-Allow-Methods": "GET, POST, PATCH, PUT, OPTIONS",
    },
  });
}

function bytesToHex(buf) {
  return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

function randomHex(len = 32) {
  const arr = new Uint8Array(len);
  crypto.getRandomValues(arr);
  return bytesToHex(arr);
}

async function sha256Hex(text) {
  const data = new TextEncoder().encode(text);
  const digest = await crypto.subtle.digest("SHA-256", data);
  return bytesToHex(digest);
}

async function hmacHex(secret, message) {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const sig = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(message));
  return bytesToHex(sig);
}

async function getSettings(env) {
  const row = await env.DB.prepare(`SELECT * FROM settings WHERE id = 1`).first();
  return row || {};
}

// ── Auth: password hashing, session tokens ─────────────────────

async function hashPassword(password, salt) {
  return sha256Hex(salt + ":" + password);
}

async function issueToken(env, sessionSecret) {
  const payload = JSON.stringify({ exp: Date.now() + 30 * 24 * 60 * 60 * 1000 });
  const payloadB64 = btoa(payload);
  const sig = await hmacHex(sessionSecret, payloadB64);
  return `${payloadB64}.${sig}`;
}

async function verifyToken(token, sessionSecret) {
  if (!token || !sessionSecret) return false;
  const [payloadB64, sig] = token.split(".");
  if (!payloadB64 || !sig) return false;
  const expected = await hmacHex(sessionSecret, payloadB64);
  if (expected !== sig) return false;
  try {
    const payload = JSON.parse(atob(payloadB64));
    return payload.exp > Date.now();
  } catch {
    return false;
  }
}

async function requireAdmin(request, env) {
  const settings = await getSettings(env);
  if (!settings.session_secret) return false; // setup not completed yet
  const auth = request.headers.get("Authorization") || "";
  const token = auth.replace("Bearer ", "");
  return verifyToken(token, settings.session_secret);
}

// ── Setup / login ────────────────────────────────────────────

async function handleSetupStatus(env) {
  const settings = await getSettings(env);
  return json({ setup_complete: !!settings.admin_password_hash });
}

async function handleSetup(request, env) {
  const settings = await getSettings(env);
  if (settings.admin_password_hash) {
    return json({ error: "Setup already completed. Use /api/login instead." }, 400);
  }

  const { password, clinic_name } = await request.json();
  if (!password || password.length < 8) {
    return json({ error: "Password must be at least 8 characters." }, 400);
  }

  const salt = randomHex(16);
  const hash = await hashPassword(password, salt);
  const sessionSecret = randomHex(32);
  const vapiSecret = randomHex(24);

  await env.DB.prepare(
    `UPDATE settings SET admin_password_hash = ?, admin_password_salt = ?,
     session_secret = ?, vapi_webhook_secret = ?, clinic_name = COALESCE(?, clinic_name)
     WHERE id = 1`
  )
    .bind(hash, salt, sessionSecret, vapiSecret, clinic_name || null)
    .run();

  const token = await issueToken(env, sessionSecret);
  return json({ token });
}

async function handleLogin(request, env) {
  const settings = await getSettings(env);
  if (!settings.admin_password_hash) {
    return json({ error: "Setup not completed yet." }, 400);
  }

  const { password } = await request.json();
  const hash = await hashPassword(password || "", settings.admin_password_salt);

  if (hash !== settings.admin_password_hash) {
    return json({ error: "Incorrect password." }, 401);
  }

  const token = await issueToken(env, settings.session_secret);
  return json({ token });
}

// ── Notifications (Twilio SMS + Resend email) ──────────────────

async function sendSMS(env, toPhone, body) {
  const s = await getSettings(env);
  if (!s.twilio_account_sid || !s.twilio_auth_token || !s.twilio_from_number) return;

  const url = `https://api.twilio.com/2010-04-01/Accounts/${s.twilio_account_sid}/Messages.json`;
  const creds = btoa(`${s.twilio_account_sid}:${s.twilio_auth_token}`);

  await fetch(url, {
    method: "POST",
    headers: {
      Authorization: `Basic ${creds}`,
      "Content-Type": "application/x-www-form-urlencoded",
    },
    body: new URLSearchParams({ To: toPhone, From: s.twilio_from_number, Body: body }),
  });

  await env.DB.prepare(
    `INSERT INTO messages (patient_phone, direction, body) VALUES (?, 'outbound', ?)`
  )
    .bind(toPhone, body)
    .run();
}

async function sendEmail(env, toEmail, subject, body) {
  const s = await getSettings(env);
  if (!s.resend_api_key || !s.resend_from_email || !toEmail) return;

  await fetch("https://api.resend.com/emails", {
    method: "POST",
    headers: {
      Authorization: `Bearer ${s.resend_api_key}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ from: s.resend_from_email, to: toEmail, subject, text: body }),
  });
}

async function notify(env, { kind, patientName, patientPhone, dateTime }) {
  const settings = await getSettings(env);

  const smsText = {
    booked: `Hi ${patientName}, your appointment is confirmed for ${new Date(dateTime).toLocaleString()}.`,
    cancelled: `Hi ${patientName}, your appointment has been cancelled. Call us if you'd like to rebook.`,
    rescheduled: `Hi ${patientName}, your appointment has been moved to ${new Date(dateTime).toLocaleString()}.`,
  }[kind];

  const emailSubject = {
    booked: `New appointment booked — ${patientName}`,
    cancelled: `Appointment cancelled — ${patientName}`,
    rescheduled: `Appointment rescheduled — ${patientName}`,
  }[kind];

  const emailBody = `${patientName} (${patientPhone}) — ${kind} for ${new Date(dateTime).toLocaleString()}.`;

  if (settings.sms_enabled && patientPhone) await sendSMS(env, patientPhone, smsText);
  if (settings.email_enabled && settings.notify_email) await sendEmail(env, settings.notify_email, emailSubject, emailBody);
}

// ── VAPI webhook ────────────────────────────────────────────────

async function handleVapiWebhook(request, env) {
  const settings = await getSettings(env);
  const provided = request.headers.get("x-vapi-secret") || "";
  if (!settings.vapi_webhook_secret || provided !== settings.vapi_webhook_secret) {
    return json({ error: "invalid signature" }, 401);
  }

  const payload = await request.json();
  const type = payload?.message?.type || payload?.type;

  if (type === "end-of-call-report" || type === "call-ended") {
    const call = payload.message?.call || payload.call || {};
    const status = call.endedReason?.includes("missed") ? "missed" : "answered";

    await env.DB.prepare(
      `INSERT INTO call_logs (caller_phone, call_status, duration_seconds, transcript_summary, vapi_call_id)
       VALUES (?, ?, ?, ?, ?)`
    )
      .bind(call.customer?.number || "unknown", status, Math.round(call.duration || 0), payload.message?.summary || null, call.id || null)
      .run();

    if (status === "missed" && settings.sms_enabled && call.customer?.number) {
      await sendSMS(
        env,
        call.customer.number,
        `Hi, sorry we missed your call at ${settings.clinic_name || "our office"}. Reply here or call us back and we'll help you right away.`
      );
    }
  }

  if (type === "function-call" || type === "tool-calls") {
    const fnName = payload.message?.functionCall?.name || payload.message?.toolCalls?.[0]?.function?.name;
    const rawArgs = payload.message?.functionCall?.parameters || payload.message?.toolCalls?.[0]?.function?.arguments || {};
    const args = typeof rawArgs === "string" ? JSON.parse(rawArgs) : rawArgs;

    if (fnName === "book_appointment") {
      const { patient_name, phone, date_time, reason } = args;

      if (!patient_name || !phone || !date_time) {
        return json({ result: "Missing patient name, phone, or date/time — could not book." });
      }
      if (isNaN(Date.parse(date_time))) {
        return json({ result: "That date/time wasn't understood — could not book." });
      }

      const conflict = await env.DB.prepare(`SELECT id FROM appointments WHERE date_time = ? AND status = 'booked'`)
        .bind(date_time)
        .first();
      if (conflict) {
        return json({ result: `That time slot is already booked — please suggest a different time.` });
      }

      let patient = await env.DB.prepare(`SELECT id FROM patients WHERE phone = ?`).bind(phone).first();
      if (!patient) {
        patient = await env.DB.prepare(`INSERT INTO patients (name, phone) VALUES (?, ?) RETURNING id`).bind(patient_name, phone).first();
      }

      await env.DB.prepare(`INSERT INTO appointments (patient_id, date_time, reason) VALUES (?, ?, ?)`)
        .bind(patient.id, date_time, reason || null)
        .run();

      await notify(env, { kind: "booked", patientName: patient_name, patientPhone: phone, dateTime: date_time });

      return json({ result: `Appointment booked for ${patient_name} on ${date_time}.` });
    }
  }

  return json({ received: true });
}

// ── Admin API: settings ─────────────────────────────────────────

async function handleGetSettings(env) {
  const s = await getSettings(env);
  // Never send the password hash/salt or session secret back to the browser.
  const { admin_password_hash, admin_password_salt, session_secret, ...safe } = s;
  return json(safe);
}

async function handleUpdateSettings(request, env) {
  const body = await request.json();
  const fields = [
    "clinic_name", "clinic_timezone",
    "twilio_account_sid", "twilio_auth_token", "twilio_from_number",
    "resend_api_key", "resend_from_email",
    "notify_email",
  ];
  const sets = [];
  const values = [];
  for (const f of fields) {
    if (f in body) {
      sets.push(`${f} = ?`);
      values.push(body[f]);
    }
  }
  if ("email_enabled" in body) { sets.push("email_enabled = ?"); values.push(body.email_enabled ? 1 : 0); }
  if ("sms_enabled" in body) { sets.push("sms_enabled = ?"); values.push(body.sms_enabled ? 1 : 0); }

  if (sets.length === 0) return json({ error: "nothing to update" }, 400);

  sets.push(`updated_at = datetime('now')`);
  await env.DB.prepare(`UPDATE settings SET ${sets.join(", ")} WHERE id = 1`).bind(...values).run();
  return json({ ok: true });
}

async function handleRegenerateVapiSecret(env) {
  const newSecret = randomHex(24);
  await env.DB.prepare(`UPDATE settings SET vapi_webhook_secret = ? WHERE id = 1`).bind(newSecret).run();
  return json({ vapi_webhook_secret: newSecret });
}

// ── Admin API: appointments, calls, messages, summary, export ──

async function handleAppointments(request, env, url) {
  if (request.method === "GET") {
    const { results } = await env.DB.prepare(
      `SELECT a.id, a.date_time, a.status, a.reason, p.name, p.phone
       FROM appointments a JOIN patients p ON a.patient_id = p.id
       ORDER BY a.date_time DESC LIMIT 200`
    ).all();
    return json({ appointments: results });
  }

  if (request.method === "POST") {
    const body = await request.json();
    const { patient_name, phone, date_time, reason } = body;

    if (!patient_name || !phone || !date_time || isNaN(Date.parse(date_time))) {
      return json({ error: "patient_name, phone, and a valid date_time are required" }, 400);
    }

    const conflict = await env.DB.prepare(`SELECT id FROM appointments WHERE date_time = ? AND status = 'booked'`)
      .bind(date_time)
      .first();
    if (conflict) return json({ error: "That time slot is already booked" }, 409);

    let patient = await env.DB.prepare(`SELECT id FROM patients WHERE phone = ?`).bind(phone).first();
    if (!patient) {
      patient = await env.DB.prepare(`INSERT INTO patients (name, phone) VALUES (?, ?) RETURNING id`).bind(patient_name, phone).first();
    }

    const appt = await env.DB.prepare(`INSERT INTO appointments (patient_id, date_time, reason) VALUES (?, ?, ?) RETURNING id`)
      .bind(patient.id, date_time, reason || null)
      .first();

    return json({ id: appt.id }, 201);
  }

  const idMatch = url.pathname.match(/\/api\/appointments\/(\d+)/);

  if (request.method === "PATCH" && idMatch) {
    const { status } = await request.json();
    await env.DB.prepare(`UPDATE appointments SET status = ? WHERE id = ?`).bind(status, idMatch[1]).run();

    if (status === "cancelled") {
      const appt = await env.DB.prepare(
        `SELECT a.date_time, p.name, p.phone FROM appointments a JOIN patients p ON a.patient_id = p.id WHERE a.id = ?`
      ).bind(idMatch[1]).first();
      if (appt) await notify(env, { kind: "cancelled", patientName: appt.name, patientPhone: appt.phone, dateTime: appt.date_time });
    }
    return json({ ok: true });
  }

  if (request.method === "PUT" && idMatch) {
    const { date_time } = await request.json();
    await env.DB.prepare(`UPDATE appointments SET date_time = ? WHERE id = ?`).bind(date_time, idMatch[1]).run();

    const appt = await env.DB.prepare(
      `SELECT p.name, p.phone FROM appointments a JOIN patients p ON a.patient_id = p.id WHERE a.id = ?`
    ).bind(idMatch[1]).first();
    if (appt) await notify(env, { kind: "rescheduled", patientName: appt.name, patientPhone: appt.phone, dateTime: date_time });

    return json({ ok: true });
  }

  return json({ error: "not found" }, 404);
}

async function handleCalls(env) {
  const { results } = await env.DB.prepare(`SELECT * FROM call_logs ORDER BY created_at DESC LIMIT 200`).all();
  return json({ calls: results });
}

async function handleMessages(env) {
  const { results } = await env.DB.prepare(`SELECT * FROM messages ORDER BY created_at DESC LIMIT 200`).all();
  return json({ messages: results });
}

async function handleSummary(env) {
  const today = new Date().toISOString().slice(0, 10);
  const totalCalls = await env.DB.prepare(`SELECT COUNT(*) as n FROM call_logs WHERE date(created_at) = ?`).bind(today).first();
  const missedCalls = await env.DB.prepare(`SELECT COUNT(*) as n FROM call_logs WHERE date(created_at) = ? AND call_status = 'missed'`).bind(today).first();
  const bookedToday = await env.DB.prepare(`SELECT COUNT(*) as n FROM appointments WHERE date(created_at) = ?`).bind(today).first();
  const upcoming = await env.DB.prepare(`SELECT COUNT(*) as n FROM appointments WHERE date_time >= datetime('now') AND status = 'booked'`).first();

  return json({
    calls_today: totalCalls.n,
    missed_today: missedCalls.n,
    booked_today: bookedToday.n,
    upcoming_appointments: upcoming.n,
  });
}

async function handleExport(env) {
  const { results } = await env.DB.prepare(
    `SELECT a.id, a.date_time, a.status, a.reason, p.name, p.phone, p.email
     FROM appointments a JOIN patients p ON a.patient_id = p.id ORDER BY a.date_time DESC`
  ).all();

  const header = "id,date_time,status,reason,patient_name,phone,email\n";
  const rows = results
    .map((r) => [r.id, r.date_time, r.status, r.reason || "", r.name, r.phone, r.email || ""]
      .map((v) => `"${String(v).replace(/"/g, '""')}"`).join(","))
    .join("\n");

  return new Response(header + rows, {
    headers: {
      "Content-Type": "text/csv",
      "Content-Disposition": "attachment; filename=appointments_export.csv",
      "Access-Control-Allow-Origin": "*",
    },
  });
}

async function sendUpcomingReminders(env) {
  const settings = await getSettings(env);
  if (!settings.sms_enabled) return;

  const { results } = await env.DB.prepare(
    `SELECT a.id, a.date_time, p.name, p.phone FROM appointments a
     JOIN patients p ON a.patient_id = p.id
     WHERE a.status = 'booked' AND a.date_time BETWEEN datetime('now', '+23 hours') AND datetime('now', '+25 hours')`
  ).all();

  for (const appt of results) {
    await sendSMS(env, appt.phone, `Reminder: ${appt.name}, you have an appointment tomorrow at ${new Date(appt.date_time).toLocaleString()}. Reply or call us if you need to reschedule.`);
  }
}

// ── Router ────────────────────────────────────────────────────

export default {
  async fetch(request, env) {
    try {
      const url = new URL(request.url);

      if (request.method === "OPTIONS") return json({});

      // Public routes (no admin token required)
      if (url.pathname === "/webhook/vapi" && request.method === "POST") return handleVapiWebhook(request, env);
      if (url.pathname === "/api/setup-status" && request.method === "GET") return handleSetupStatus(env);
      if (url.pathname === "/api/setup" && request.method === "POST") return handleSetup(request, env);
      if (url.pathname === "/api/login" && request.method === "POST") return handleLogin(request, env);

      // Everything else under /api/ requires a valid session token
      if (url.pathname.startsWith("/api/")) {
        if (!(await requireAdmin(request, env))) return json({ error: "unauthorized" }, 401);

        if (url.pathname === "/api/settings" && request.method === "GET") return handleGetSettings(env);
        if (url.pathname === "/api/settings" && request.method === "POST") return handleUpdateSettings(request, env);
        if (url.pathname === "/api/settings/regenerate-vapi-secret" && request.method === "POST") return handleRegenerateVapiSecret(env);
        if (url.pathname.startsWith("/api/appointments")) return handleAppointments(request, env, url);
        if (url.pathname === "/api/calls") return handleCalls(env);
        if (url.pathname === "/api/messages") return handleMessages(env);
        if (url.pathname === "/api/summary") return handleSummary(env);
        if (url.pathname === "/api/export") return handleExport(env);
      }

      return json({ error: "not found" }, 404);
    } catch (err) {
      console.error(err);
      return json({ error: "internal error", detail: String(err.message || err) }, 500);
    }
  },

  async scheduled(event, env, ctx) {
    ctx.waitUntil(sendUpcomingReminders(env));
  },
};
