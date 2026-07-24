-- Run this once per new client with:
-- npx wrangler d1 execute CHANGE-ME-clinic-name-db --file=./schema.sql --remote

CREATE TABLE IF NOT EXISTS patients (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  phone TEXT NOT NULL,
  email TEXT,
  notes TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS appointments (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  patient_id INTEGER NOT NULL,
  date_time TEXT NOT NULL,           -- ISO 8601, e.g. 2026-07-25T14:30:00
  status TEXT NOT NULL DEFAULT 'booked',  -- booked | cancelled | completed | no_show
  reason TEXT,
  service TEXT,
  duration_minutes INTEGER DEFAULT 60,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  FOREIGN KEY (patient_id) REFERENCES patients(id)
);

CREATE TABLE IF NOT EXISTS call_logs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  caller_phone TEXT NOT NULL,
  call_status TEXT NOT NULL,          -- answered | missed | voicemail
  duration_seconds INTEGER DEFAULT 0,
  transcript_summary TEXT,
  vapi_call_id TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS messages (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  patient_phone TEXT NOT NULL,
  direction TEXT NOT NULL,            -- inbound | outbound
  body TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_appointments_date ON appointments(date_time);
CREATE INDEX IF NOT EXISTS idx_calls_created ON call_logs(created_at);
CREATE INDEX IF NOT EXISTS idx_messages_phone ON messages(patient_phone);

-- Single row (id = 1) holding this clinic's entire configuration.
-- Everything here is set from the dashboard's "Backend Settings" screen —
-- no Wrangler CLI / secrets needed after the initial deploy.
CREATE TABLE IF NOT EXISTS settings (
  id INTEGER PRIMARY KEY CHECK (id = 1),

  -- Admin login (set on first run via the setup wizard)
  admin_password_hash TEXT,
  admin_password_salt TEXT,
  session_secret TEXT,             -- auto-generated on first run, signs login tokens

  -- Clinic details
  clinic_name TEXT DEFAULT 'Aspen Dental',
  clinic_timezone TEXT DEFAULT 'America/Toronto',
  clinic_address TEXT DEFAULT '123 Main Street, Suite 200, Toronto, ON M5V 2T6',
  clinic_hours TEXT DEFAULT 'Mon–Fri 9:00 AM – 5:00 PM, Sat 10:00 AM – 2:00 PM',
  clinic_phone TEXT DEFAULT '+1 (416) 555-0147',
  clinic_email TEXT DEFAULT 'info@aspendentaltoronto.com',
  insurance_info TEXT DEFAULT 'We accept most major insurance plans including Sun Life, Manulife, Great-West Life, Canada Life, and Greenshield. Please bring your insurance card to your visit.',
  parking_info TEXT DEFAULT 'Free parking available in the lot behind the building. Street parking is also available. We are a 5-minute walk from the Main Street subway station.',
  services_offered TEXT DEFAULT 'General dentistry, routine cleanings, fillings, crowns & bridges, root canals, extractions, teeth whitening, dental implants, emergency dentistry, and pediatric dentistry.',
  emergency_phone TEXT DEFAULT '+1 (416) 555-0199',

  -- Twilio (SMS) — entered via dashboard
  twilio_account_sid TEXT,
  twilio_auth_token TEXT,
  twilio_from_number TEXT,

  -- Resend (email) — entered via dashboard
  resend_api_key TEXT,
  resend_from_email TEXT,

  -- VAPI — secret is auto-generated on first run; you copy it INTO VAPI's
  -- assistant config as a custom header. VAPI has no "connect account" API,
  -- so this one paste-in step on VAPI's side can't be automated away.
  vapi_webhook_secret TEXT,

  -- Notification toggles
  notify_email TEXT,
  email_enabled INTEGER NOT NULL DEFAULT 1,
  sms_enabled INTEGER NOT NULL DEFAULT 1,

  updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

INSERT OR IGNORE INTO settings (id) VALUES (1);
