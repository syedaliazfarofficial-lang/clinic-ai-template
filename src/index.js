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

    // Newer VAPI accounts send toolCalls (with an id) and expect the response
    // wrapped as { results: [{ toolCallId, result }] }. Older accounts send
    // functionCall (no id) and just want { result }. Support both.
    const toolCallId = payload.message?.toolCalls?.[0]?.id;
    const respond = (text) => (toolCallId ? json({ results: [{ toolCallId, result: text }] }) : json({ result: text }));

    if (fnName === "book_appointment") {
      const { patient_name, phone, date_time, reason, service, duration_minutes } = args;

      if (!patient_name || !phone || !date_time) {
        return respond("Missing patient name, phone, or date/time — could not book.");
      }
      if (isNaN(Date.parse(date_time))) {
        return respond("That date/time wasn't understood — could not book.");
      }

      const conflict = await env.DB.prepare(`SELECT id FROM appointments WHERE date_time = ? AND status = 'booked'`)
        .bind(date_time)
        .first();
      if (conflict) {
        return respond(`That time slot is already booked — please suggest a different time.`);
      }

      let patient = await env.DB.prepare(`SELECT id FROM patients WHERE phone = ?`).bind(phone).first();
      if (!patient) {
        patient = await env.DB.prepare(`INSERT INTO patients (name, phone) VALUES (?, ?) RETURNING id`).bind(patient_name, phone).first();
      }

      await env.DB.prepare(`INSERT INTO appointments (patient_id, date_time, reason, service, duration_minutes) VALUES (?, ?, ?, ?, ?)`)
        .bind(patient.id, date_time, reason || null, service || null, duration_minutes || 60)
        .run();

      await notify(env, { kind: "booked", patientName: patient_name, patientPhone: phone, dateTime: date_time });

      return respond(`Appointment booked for ${patient_name} on ${date_time}.`);
    }

    if (fnName === "check_availability") {
      const { date } = args; // expected format: YYYY-MM-DD
      if (!date || isNaN(Date.parse(date))) {
        return respond("I need a specific date to check availability for.");
      }

      const allSlots = ["09:00", "10:00", "11:00", "12:00", "13:00", "14:00", "15:00", "16:00"];

      const { results: booked } = await env.DB.prepare(
        `SELECT date_time FROM appointments WHERE date(date_time) = date(?) AND status = 'booked'`
      )
        .bind(date)
        .all();

      const bookedTimes = booked.map((b) => new Date(b.date_time).toTimeString().slice(0, 5));
      const available = allSlots.filter((s) => !bookedTimes.includes(s));

      return respond(
        available.length
          ? `Available times on ${date}: ${available.join(", ")}.`
          : `Sorry, ${date} is fully booked — would you like to try another day?`
      );
    }

    if (fnName === "get_appointments") {
      const { phone } = args;
      if (!phone) return respond("I need a phone number to look that up.");

      const { results } = await env.DB.prepare(
        `SELECT a.date_time, a.reason, a.service, a.duration_minutes FROM appointments a
         JOIN patients p ON a.patient_id = p.id
         WHERE p.phone = ? AND a.status = 'booked' ORDER BY a.date_time ASC`
      )
        .bind(phone)
        .all();

      if (!results.length) {
        return respond("I don't see any upcoming appointments under that number.");
      }

      const list = results.map((r) => `${new Date(r.date_time).toLocaleString()} — ${r.service || r.reason || "visit"} (${r.duration_minutes || 60} min)`).join("; ");
      return respond(`Upcoming appointments: ${list}.`);
    }

    if (fnName === "reschedule_appointment") {
      const { phone, new_date_time } = args;
      if (!phone || !new_date_time || isNaN(Date.parse(new_date_time))) {
        return respond("I need the phone number and a valid new date/time to reschedule.");
      }

      const appt = await env.DB.prepare(
        `SELECT a.id, p.name FROM appointments a JOIN patients p ON a.patient_id = p.id
         WHERE p.phone = ? AND a.status = 'booked' ORDER BY a.date_time ASC LIMIT 1`
      )
        .bind(phone)
        .first();

      if (!appt) return respond("I couldn't find an upcoming appointment under that number.");

      const conflict = await env.DB.prepare(`SELECT id FROM appointments WHERE date_time = ? AND status = 'booked'`)
        .bind(new_date_time)
        .first();
      if (conflict) return respond("That new time is already booked — can you suggest another?");

      await env.DB.prepare(`UPDATE appointments SET date_time = ? WHERE id = ?`).bind(new_date_time, appt.id).run();
      await notify(env, { kind: "rescheduled", patientName: appt.name, patientPhone: phone, dateTime: new_date_time });

      return respond(`Done — your appointment has been moved to ${new_date_time}.`);
    }

    if (fnName === "cancel_appointment") {
      const { phone } = args;
      if (!phone) return respond("I need a phone number to find that appointment.");

      const appt = await env.DB.prepare(
        `SELECT a.id, a.date_time, p.name FROM appointments a JOIN patients p ON a.patient_id = p.id
         WHERE p.phone = ? AND a.status = 'booked' ORDER BY a.date_time ASC LIMIT 1`
      )
        .bind(phone)
        .first();

      if (!appt) return respond("I couldn't find an upcoming appointment under that number.");

      await env.DB.prepare(`UPDATE appointments SET status = 'cancelled' WHERE id = ?`).bind(appt.id).run();
      await notify(env, { kind: "cancelled", patientName: appt.name, patientPhone: phone, dateTime: appt.date_time });

      return respond("Your appointment has been cancelled.");
    }

    if (fnName === "get_clinic_info") {
      const info = await handleGetClinicInfo(env);
      const data = await info.json();
      const lines = [
        `📍 ${data.clinic_address}`,
        `🕐 ${data.clinic_hours}`,
        `📞 ${data.clinic_phone}`,
        `📧 ${data.clinic_email}`,
        `🅿️ ${data.parking_info}`,
        `🩺 Services: ${data.services_offered}`,
        `💳 Insurance: ${data.insurance_info}`,
        `🚨 For emergencies: ${data.emergency_phone}`,
      ];
      return respond(lines.join("\n"));
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

async function handleGetClinicInfo(env) {
  const s = await getSettings(env);
  return json({
    clinic_name: s.clinic_name || 'Aspen Dental',
    clinic_address: s.clinic_address || '123 Main Street, Suite 200, Toronto, ON M5V 2T6',
    clinic_hours: s.clinic_hours || 'Mon–Fri 9:00 AM – 5:00 PM, Sat 10:00 AM – 2:00 PM',
    clinic_phone: s.clinic_phone || '+1 (416) 555-0147',
    clinic_email: s.clinic_email || 'info@aspendentaltoronto.com',
    insurance_info: s.insurance_info || 'We accept most major insurance plans.',
    parking_info: s.parking_info || 'Free parking available behind the building.',
    services_offered: s.services_offered || 'General dentistry, cleanings, fillings, crowns, root canals.',
    emergency_phone: s.emergency_phone || '+1 (416) 555-0199',
  });
}

async function handleUpdateSettings(request, env) {
  const body = await request.json();
  const fields = [
    "clinic_name", "clinic_timezone", "clinic_address", "clinic_hours",
    "clinic_phone", "clinic_email", "insurance_info", "parking_info",
    "services_offered", "emergency_phone",
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
    const from = url.searchParams.get("from");
    const to = url.searchParams.get("to");
    let sql = `SELECT a.id, a.date_time, a.status, a.reason, a.service, a.duration_minutes, p.name, p.phone
       FROM appointments a JOIN patients p ON a.patient_id = p.id`;
    const binds = [];
    const wheres = [];
    if (from) { wheres.push("date(a.date_time) >= date(?)"); binds.push(from); }
    if (to) { wheres.push("date(a.date_time) <= date(?)"); binds.push(to); }
    if (wheres.length) sql += " WHERE " + wheres.join(" AND ");
    sql += " ORDER BY a.date_time DESC LIMIT 200";
    const { results } = await env.DB.prepare(sql).bind(...binds).all();
    return json({ appointments: results });
  }

  if (request.method === "POST") {
    const body = await request.json();
    const { patient_name, phone, date_time, reason, service, duration_minutes } = body;

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

    const appt = await env.DB.prepare(`INSERT INTO appointments (patient_id, date_time, reason, service, duration_minutes) VALUES (?, ?, ?, ?, ?) RETURNING id`)
      .bind(patient.id, date_time, reason || null, service || null, duration_minutes || 60)
      .first();

    return json({ id: appt.id }, 201);
  }

  const idMatch = url.pathname.match(/\/api\/appointments\/(\d+)/);

  if (request.method === "PATCH" && idMatch) {
    const { status, service, duration_minutes } = await request.json();
    const sets = [];
    const vals = [];
    if (status) { sets.push("status = ?"); vals.push(status); }
    if (service !== undefined) { sets.push("service = ?"); vals.push(service); }
    if (duration_minutes !== undefined) { sets.push("duration_minutes = ?"); vals.push(duration_minutes); }
    if (sets.length) {
      vals.push(idMatch[1]);
      await env.DB.prepare(`UPDATE appointments SET ${sets.join(", ")} WHERE id = ?`).bind(...vals).run();
    }

    if (status === "cancelled") {
      const appt = await env.DB.prepare(
        `SELECT a.date_time, p.name, p.phone FROM appointments a JOIN patients p ON a.patient_id = p.id WHERE a.id = ?`
      ).bind(idMatch[1]).first();
      if (appt) await notify(env, { kind: "cancelled", patientName: appt.name, patientPhone: appt.phone, dateTime: appt.date_time });
    }
    return json({ ok: true });
  }

  if (request.method === "PUT" && idMatch) {
    const { date_time, service, duration_minutes } = await request.json();
    const sets = ["date_time = ?"];
    const vals = [date_time];
    if (service !== undefined) { sets.push("service = ?"); vals.push(service); }
    if (duration_minutes !== undefined) { sets.push("duration_minutes = ?"); vals.push(duration_minutes); }
    vals.push(idMatch[1]);
    await env.DB.prepare(`UPDATE appointments SET ${sets.join(", ")} WHERE id = ?`).bind(...vals).run();

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
    `SELECT a.id, a.date_time, a.status, a.reason, a.service, a.duration_minutes, p.name, p.phone, p.email
     FROM appointments a JOIN patients p ON a.patient_id = p.id ORDER BY a.date_time DESC`
  ).all();

  const header = "id,date_time,status,service,duration_min,reason,patient_name,phone,email\n";
  const rows = results
    .map((r) => [r.id, r.date_time, r.status, r.service || "", r.duration_minutes || 60, r.reason || "", r.name, r.phone, r.email || ""]
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

// ── Demo seed data ─────────────────────────────────────────────

async function handleSeedDemo(env) {
  // Seed clinic info
  await env.DB.prepare(`UPDATE settings SET
    clinic_name = 'Aspen Dental',
    clinic_timezone = 'America/Toronto',
    clinic_address = '123 Main Street, Suite 200, Toronto, ON M5V 2T6',
    clinic_hours = 'Mon–Fri 9:00 AM – 5:00 PM, Sat 10:00 AM – 2:00 PM',
    clinic_phone = '+1 (416) 555-0147',
    clinic_email = 'info@aspendentaltoronto.com',
    insurance_info = 'We accept most major insurance plans including Sun Life, Manulife, Great-West Life, Canada Life, and Greenshield.',
    parking_info = 'Free parking available in the lot behind the building. Street parking also available. 5-min walk from Main Street subway station.',
    services_offered = 'General dentistry, routine cleanings, fillings, crowns & bridges, root canals, extractions, teeth whitening, dental implants, emergency dentistry, pediatric dentistry.',
    emergency_phone = '+1 (416) 555-0199'
    WHERE id = 1`).run();

  // Seed patients
  const patients = [
    { name: 'James Mitchell', phone: '+14165551234', email: 'james.mitchell@gmail.com' },
    { name: 'Sarah Thompson', phone: '+14165555678', email: 'sarah.t@outlook.com' },
    { name: 'Michael Chen', phone: '+14165559012', email: 'mchen@rogers.com' },
    { name: 'Emily Rodriguez', phone: '+14165553456', email: 'emily.r@gmail.com' },
    { name: 'David Park', phone: '+14165557890', email: 'dpark@sympatico.ca' },
    { name: 'Lisa Johnson', phone: '+14165551122', email: 'lisa.johnson@bell.ca' },
  ];
  for (const p of patients) {
    await env.DB.prepare(`INSERT OR IGNORE INTO patients (name, phone, email) VALUES (?, ?, ?)`)
      .bind(p.name, p.phone, p.email).run();
  }

  // Get patient IDs
  const { results: allPatients } = await env.DB.prepare(`SELECT id, name FROM patients`).all();
  const pid = (name) => allPatients.find(p => p.name === name)?.id;

  // Seed appointments
  const now = new Date();
  const day = (offset, hour) => {
    const d = new Date(now);
    d.setDate(d.getDate() + offset);
    d.setHours(hour, 0, 0, 0);
    return d.toISOString().slice(0, 19);
  };

  const serviceList = ['Cleaning', 'Fillings', 'Root Canal', 'Checkup', 'Whitening', 'Crown', 'Extraction', 'Consultation'];
  const appointments = [
    { patient: 'James Mitchell', date: day(1, 9), status: 'booked', reason: 'Routine cleaning', service: 'Cleaning', dur: 30 },
    { patient: 'Sarah Thompson', date: day(1, 10), status: 'booked', reason: 'Fillings', service: 'Fillings', dur: 60 },
    { patient: 'Michael Chen', date: day(1, 14), status: 'booked', reason: 'Root canal consultation', service: 'Consultation', dur: 45 },
    { patient: 'Emily Rodriguez', date: day(2, 9), status: 'booked', reason: 'Teeth whitening', service: 'Whitening', dur: 60 },
    { patient: 'David Park', date: day(2, 11), status: 'booked', reason: 'Annual checkup', service: 'Checkup', dur: 30 },
    { patient: 'Lisa Johnson', date: day(2, 15), status: 'booked', reason: 'Crown fitting', service: 'Crown', dur: 60 },
    { patient: 'James Mitchell', date: day(-5, 10), status: 'completed', reason: 'Cleaning', service: 'Cleaning', dur: 30 },
    { patient: 'Sarah Thompson', date: day(-3, 14), status: 'completed', reason: 'X-rays and exam', service: 'Checkup', dur: 45 },
    { patient: 'Michael Chen', date: day(-7, 9), status: 'cancelled', reason: 'Consultation', service: 'Consultation', dur: 30 },
    { patient: 'Emily Rodriguez', date: day(-1, 11), status: 'no_show', reason: 'Follow-up', service: 'Checkup', dur: 30 },
  ];
  for (const a of appointments) {
    const id = pid(a.patient);
    if (!id) continue;
    await env.DB.prepare(`INSERT INTO appointments (patient_id, date_time, status, reason, service, duration_minutes) VALUES (?, ?, ?, ?, ?, ?)`)
      .bind(id, a.date, a.status, a.reason, a.service, a.dur).run();
  }

  // Seed call logs
  const calls = [
    { phone: '+14165551234', status: 'answered', dur: 215, summary: 'Patient booked routine cleaning for tomorrow.' },
    { phone: '+14165555678', status: 'answered', dur: 310, summary: 'Patient inquired about filling costs. Escalated to staff.' },
    { phone: '+14165559012', status: 'answered', dur: 180, summary: 'Booked root canal consultation.' },
    { phone: '+14165557890', status: 'missed', dur: 0, summary: null },
    { phone: '+14165553456', status: 'answered', dur: 145, summary: 'Patient asked about teeth whitening pricing. Escalated.' },
  ];
  for (const c of calls) {
    await env.DB.prepare(`INSERT INTO call_logs (caller_phone, call_status, duration_seconds, transcript_summary) VALUES (?, ?, ?, ?)`)
      .bind(c.phone, c.status, c.dur, c.summary).run();
  }

  // Seed messages
  const msgs = [
    { phone: '+14165551234', dir: 'outbound', body: 'Hi James, your appointment is confirmed for tomorrow at 9:00 AM.' },
    { phone: '+14165555678', dir: 'outbound', body: 'Hi Sarah, your appointment has been cancelled. Call us if you would like to rebook.' },
  ];
  for (const m of msgs) {
    await env.DB.prepare(`INSERT INTO messages (patient_phone, direction, body) VALUES (?, ?, ?)`)
      .bind(m.phone, m.dir, m.body).run();
  }

  return json({ ok: true, message: 'Demo data seeded successfully!' });
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
      if (url.pathname === "/api/seed-demo" && request.method === "POST") return handleSeedDemo(env);

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
