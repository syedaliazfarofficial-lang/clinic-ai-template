# Clinic AI Receptionist — Sellable Client Template

One deploy of this = one clinic. Everything (clinic name, Twilio, Resend,
VAPI, admin password) is configured **from inside the dashboard** after
deploy — no Wrangler CLI, no `secret put` commands, nothing to edit in code
except one line (the Worker URL, explained below).

This is designed so you (or a non-technical buyer) can set up a new clinic
end-to-end using just a Cloudflare account and a browser.

## What's inside
- `wrangler.toml` — Worker + D1 config (barely needs touching)
- `schema.sql` — all tables, including `settings` which holds every
  configurable value (Twilio keys, Resend keys, VAPI secret, admin password
  hash, clinic name, notification toggles)
- `src/index.js` — the Worker: VAPI webhook handler, dashboard API, and the
  setup/login system
- `dashboard/index.html` — the admin dashboard, deployed to Cloudflare Pages

## How the "no CLI" setup works

1. **First time the dashboard is opened**, it detects no admin password has
   been set yet and shows a **"Create your admin password"** screen instead
   of a login screen. Whoever fills that in becomes the root admin for this
   clinic's system — this password is hashed and stored in D1, never in
   plain text.
2. Once logged in, the **"Backend Settings"** link (top right) opens a panel
   where you enter: clinic name, timezone, Twilio Account SID/Auth
   Token/From Number, Resend API key/From Email, and where the auto-generated
   **VAPI webhook secret** is shown for you to copy into VAPI's dashboard.
3. All of this is stored in D1 and read by the Worker on every request — no
   redeploying, no CLI, ever, after the initial deploy.

## What genuinely can't be avoided (Cloudflare/VAPI's own requirements)

Being upfront about this so you don't oversell it:

- **You still need a Cloudflare account** and to click "Deploy" once — see
  option A or B below. This is one click/command, not a code edit.
- **Custom domain**: to use your own domain for the dashboard, that domain
  has to be added to Cloudflare (nameservers pointed at Cloudflare, or bought
  through Cloudflare Registrar directly). This is a Cloudflare account-level
  step done in their dashboard UI — no way around it, but it's a few clicks,
  not code.
- **VAPI has no "connect to Cloudflare" button** — pasting the webhook URL +
  secret into VAPI's assistant config is a one-time manual step on VAPI's
  side. The dashboard shows you exactly what to paste.
- **One line of code**: `dashboard/index.html` needs `WORKER_URL` set to
  wherever the Worker ends up living. This can only be known after the
  Worker is deployed, so it can't be pre-filled — but it's the only
  hand-edit left in the whole template.

## Option A — Deploy to Cloudflare button (easiest for buyers)

Put this template in a **public GitHub repo**, then anyone can deploy their
own copy by visiting:

```
https://deploy.workers.cloudflare.com/?url=<your-github-repo-url>
```

Cloudflare reads `wrangler.toml`, creates the D1 database automatically, and
deploys the Worker — the person just connects their Cloudflare account and
clicks through. No terminal needed for the Worker/database part.

After that, they still need to:
1. Deploy `dashboard/index.html` to Cloudflare Pages (drag-and-drop upload in
   the Cloudflare dashboard works — also no terminal).
2. Edit that one `WORKER_URL` line first (in a text editor, before uploading).
3. Open the dashboard → create their admin password → fill in Backend
   Settings → paste the VAPI webhook URL/secret into VAPI.

## Option B — Manual deploy (if you're doing it yourself, or teaching CLI)

```bash
npm install -g wrangler
wrangler login

cd dental-ai-template
wrangler d1 create clinic-ai-db          # copy the database_id into wrangler.toml
wrangler d1 execute clinic-ai-db --file=./schema.sql --remote
wrangler deploy                          # prints your Worker URL
```

Then edit `dashboard/index.html`'s `WORKER_URL`, upload the `dashboard`
folder as a Cloudflare Pages project, and open it in a browser to run setup.

## Security notes — read before selling this

- Twilio/Resend credentials are stored as **plain columns in D1**, not as
  Wrangler secrets. This is what makes the "set it from the dashboard, no
  CLI" flow possible, but it means anyone with access to that Cloudflare
  account's D1 dashboard can read them. For solo/small-scale use (the "one
  Cloudflare account per client" model you're using) this is a reasonable
  trade-off — just don't share Cloudflare account access with anyone you
  don't fully trust.
- The admin password is hashed (SHA-256 + random salt) before storage —
  reasonable for this scale, though not as strong as bcrypt/Argon2. Fine for
  a single-admin clinic tool; if this were handling many admins or larger
  scale, it'd be worth upgrading.
- Session tokens expire after 30 days; logging out just means clearing the
  browser's local storage (there's no server-side "log out" yet — minor gap,
  not a big risk for a single-admin tool).
- `Access-Control-Allow-Origin: *` in `src/index.js` is left open for ease of
  setup. Once your dashboard's final domain is known, tighten this to that
  exact domain.

## Notification system
- Booking, cancellation, and reschedule each SMS the patient (Twilio) and
  email the staff (Resend) — if enabled in Backend Settings.
- Missed calls auto-text the caller back.
- 24-hour appointment reminders run automatically every hour via Cloudflare
  Cron Trigger (free on the Workers Free plan).

## Dashboard features
- Cancel / Reschedule buttons on each appointment (auto-notifies).
- "+ Add Appointment" for walk-ins/phone bookings.
- Search box (name or phone).
- Export CSV.
- Backend Settings panel (clinic info, Twilio, Resend, VAPI secret + rotate
  button, notification toggles) — all editable without redeploying.

## Reliability
- Double-booking prevention (rejects a new booking at an already-booked time).
- Input validation (name, phone, and a parseable date/time are required).
- The whole Worker is wrapped in try/catch — a bad request returns a clean
  error instead of taking the system down.

## Still not built (say the word if you want these next)
- Two-way SMS (patient texts back to confirm/cancel/reschedule themselves).
- VAPI-side cancel/reschedule over the phone call itself (currently voice can
  only *book*; cancelling by voice needs a second VAPI function + handler).
- 6-month recall reminders for regular checkups.
- Multiple staff logins (currently one shared admin password per clinic).
- Calendar sync (Google Calendar/Outlook).
