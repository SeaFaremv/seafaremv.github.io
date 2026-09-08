/**
 * Reference API layer for the SeaFare app, backed by Neon Postgres.
 *
 * Contract expected by the front-end (index.html):
 *   GET  /api/data/:boatId/:key   -> { value: <json or null> }
 *   PUT  /api/data/:boatId/:key   body { value: <json> }  -> upserts, returns { value }
 *
 * This example uses Express + the Neon serverless driver (HTTP-based, works
 * anywhere -- Node, Vercel Functions, Cloudflare Workers with small tweaks).
 * Swap the Express wrapper for your platform's handler signature as needed;
 * the Neon query logic in the middle stays the same.
 *
 * Setup:
 *   npm install express @neondatabase/serverless cors
 *   export DATABASE_URL="postgresql://<user>:<password>@<host>/<db>?sslmode=require"
 *   node server.js
 */

const express = require('express');
const cors = require('cors');
const compression = require('compression');
const crypto = require('crypto');
const nodemailer = require('nodemailer');
const twilio = require('twilio');
const { authenticator } = require('otplib');
const { google } = require('googleapis');
const { neon } = require('@neondatabase/serverless');
const webpush = require('web-push');

const sql = neon(process.env.DATABASE_URL);
const app = express();

// Every response here is JSON text -- shipment lists, settings, invoices --
// which gzip compresses extremely well (typically 60-80% smaller on the
// wire). This was previously being sent completely uncompressed. This
// compresses the browser<->server leg specifically; it doesn't change what
// Neon itself transfers (that's addressed separately, at the query level,
// for the shipments-photo case below), but it directly cuts the data every
// device on a slow connection actually has to download.
app.use(compression());

// The default express.json() body limit is 100kb. Shipments now carry
// compressed photos (base64) inside the same JSON blob, and even a handful
// of them across different shipments comfortably exceeds that -- once it
// does, every save silently starts failing with a 413. 25mb gives plenty of
// headroom for many photos in a single save.
app.use(express.json({ limit: '25mb', verify: (req, res, buf) => { req.rawBody = buf; } }));

// --- Owner PIN reset (emailed via Gmail) -----------------------------------
// GMAIL_USER / GMAIL_APP_PASSWORD are the credentials the app itself sends
// FROM (a Gmail account with an "App Password" generated at
// https://myaccount.google.com/apppasswords — this requires 2-Step
// Verification to be on). The reset link is sent TO whatever address the
// Owner has registered in Settings ("Registered Gmail"). APP_URL is the
// public URL of the front-end (your GitHub Pages site), used to build the
// link, e.g. https://YOUR-USERNAME.github.io
const GMAIL_USER = process.env.GMAIL_USER;
const GMAIL_APP_PASSWORD = process.env.GMAIL_APP_PASSWORD;
const APP_URL = (process.env.APP_URL || '').replace(/\/+$/, '');
const RESET_TOKEN_TTL_MS = 30 * 60 * 1000; // 30 minutes

const mailer = (GMAIL_USER && GMAIL_APP_PASSWORD)
  ? nodemailer.createTransport({
      service: 'gmail',
      auth: { user: GMAIL_USER, pass: GMAIL_APP_PASSWORD },
    })
  : null;

// --- Owner PIN reset (texted via Twilio SMS) --------------------------------
// TWILIO_ACCOUNT_SID / TWILIO_AUTH_TOKEN come from your Twilio console.
// TWILIO_PHONE_NUMBER is the Twilio number the text is sent FROM (must be
// SMS-capable). The reset link is texted TO whatever number the Owner has
// registered in Settings ("Registered Phone").
const TWILIO_ACCOUNT_SID = process.env.TWILIO_ACCOUNT_SID;
const TWILIO_AUTH_TOKEN = process.env.TWILIO_AUTH_TOKEN;
const TWILIO_PHONE_NUMBER = process.env.TWILIO_PHONE_NUMBER;

const smsClient = (TWILIO_ACCOUNT_SID && TWILIO_AUTH_TOKEN)
  ? twilio(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN)
  : null;

// --- Owner PIN reset (authenticator app code) -------------------------------
// TOTP_SECRET is a base32 secret known only to this server (set as a Render
// env var, never returned by any API response) and to whatever authenticator
// app (OneAuth, Google Authenticator, Authy, etc.) the Owner entered it into.
// Unlike the email/phone paths, this needs no outside service to work -- the
// 6-digit code the app shows is verified locally against the same secret.
const TOTP_SECRET = process.env.TOTP_SECRET;
authenticator.options = { window: 1 }; // allow 1 step (\u00b130s) of clock drift

// Restrict this to your actual GitHub Pages origin in production,
// e.g. cors({ origin: 'https://seafaremv.github.io' })
app.use(cors());

// Never let browsers or intermediate CDNs cache these responses -- this data
// changes constantly (new check-ins, staff PIN changes, etc), and a cached
// stale response can make the app look broken even when the DB is fine.
app.use((req, res, next) => {
  res.set('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
  res.set('Pragma', 'no-cache');
  res.set('Expires', '0');
  next();
});

const ALLOWED_KEYS = new Set(['shipments', 'rates', 'settings', 'trips']);

// Phase 3: every shipments/rates/settings/trips read & write is now scoped
// to a specific boat_id, so each boat's dispatch data is private to it.
// boatId isn't re-verified against a passkey here -- same low-auth model as
// the rest of this API (see README) -- but it does have to be a real,
// existing boat, which at least rules out typos/garbage IDs silently
// creating orphaned data.
// Simple public lookup of a boat's display name -- used client-side to
// build things like auto-generated staff usernames (name.boatname).
app.get('/api/boats/:id/name', async (req, res) => {
  try {
    const rows = await sql`SELECT name FROM boats WHERE id = ${req.params.id}`;
    if (!rows.length) return res.status(404).json({ error: 'unknown boat' });
    res.json({ name: rows[0].name });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'db error' });
  }
});

app.get('/api/data/:boatId/:key', async (req, res) => {
  const { boatId, key } = req.params;
  if (!ALLOWED_KEYS.has(key)) return res.status(400).json({ error: 'unknown key' });
  try {
    const boatRows = await sql`SELECT status, suspension_note FROM boats WHERE id = ${boatId}`;
    if (boatRows.length && boatRows[0].status === 'suspended') {
      return res.status(403).json({ error: 'This boat has been suspended.', note: boatRows[0].suspension_note || null });
    }
    // Routine polling only needs to know whether anything changed, not the
    // embedded photo on every shipment -- and shipments can carry a lot of
    // those. Stripping the 'photo' field *inside* the query (rather than
    // fetching everything and trimming it before responding) means Neon
    // never has to transfer that data out of the database at all, which is
    // what actually counts against the data transfer quota -- not just
    // what reaches the browser. Writes, the initial full load, and photo
    // viewing/downloading all still go through the normal path below,
    // completely unaffected.
    if (key === 'shipments' && req.query.photos === 'exclude') {
      const rows = await sql`
        SELECT
          CASE WHEN jsonb_typeof(value) = 'array' THEN COALESCE(
            (SELECT jsonb_agg(elem - 'photo' ORDER BY ord)
             FROM jsonb_array_elements(value) WITH ORDINALITY AS t(elem, ord)),
            '[]'::jsonb
          ) ELSE value END AS value
        FROM app_data
        WHERE boat_id = ${boatId} AND key = ${key}
      `;
      return res.json({ value: rows.length ? rows[0].value : null });
    }
    const rows = await sql`SELECT value FROM app_data WHERE boat_id = ${boatId} AND key = ${key}`;
    let value = rows.length ? rows[0].value : null;
    if (key === 'settings') {
      const orgRows = await sql`
        SELECT o.is_pro, o.pro_started_at, o.pro_expires_at, o.plan_limits_enabled, b.created_at AS boat_created_at FROM boats b
        JOIN organizations o ON o.id = b.organization_id
        WHERE b.id = ${boatId}
      `;
      if (orgRows.length) {
        value = value || {};
        value.isPro = orgRows[0].is_pro;
        value.proStartedAt = orgRows[0].pro_started_at;
        value.proExpiresAt = orgRows[0].pro_expires_at;
        value.planLimitsEnabled = orgRows[0].plan_limits_enabled;
        // When this boat was created -- lets the client show its
        // first-day-only onboarding copy (see renderStaffManagement in
        // index.html) exactly once, on the actual calendar day the boat
        // signed up, rather than on every visit to Settings forever.
        value.boatCreatedAt = orgRows[0].boat_created_at;
      }
      value = sanitizeSettingsForClient(value, boatId);
    }
    if (key === 'shipments' && Array.isArray(value)) {
      value = value.map(s => (s && s.photo) ? { ...s, photo: decryptField(s.photo, boatId) } : s);
    }
    res.json({ value });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'db error' });
  }
});

app.put('/api/data/:boatId/:key', async (req, res) => {
  const { boatId, key } = req.params;
  if (!ALLOWED_KEYS.has(key)) return res.status(400).json({ error: 'unknown key' });
  const { value } = req.body || {};
  if (value === undefined) return res.status(400).json({ error: 'missing value' });
  try {
    const boatRows = await sql`SELECT id, status, suspension_note FROM boats WHERE id = ${boatId}`;
    if (boatRows.length === 0) return res.status(404).json({ error: 'unknown boat' });
    if (boatRows[0].status === 'suspended') return res.status(403).json({ error: 'This boat has been suspended.', note: boatRows[0].suspension_note || null });
    let storedValue = value;
    if (key === 'settings' && storedValue && typeof storedValue === 'object') {
      // Free/Pro plan caps (staff and manager counts per boat) -- only
      // for organizations created after this feature shipped
      // (plan_limits_enabled); every organization that existed before
      // that stays grandfathered in as unlimited, same as everywhere
      // else this feature touches. Checked here rather than in a
      // dedicated "invite staff" endpoint because staff/manager lists
      // are edited as part of the whole settings object, not through
      // their own endpoint.
      const staffCount = Array.isArray(storedValue.staffUsers) ? storedValue.staffUsers.length : 0;
      const managerCount = Array.isArray(storedValue.managerUsers) ? storedValue.managerUsers.length : 0;
      if(staffCount > 0 || managerCount > 0){
        const planRows = await sql`
          SELECT o.plan_limits_enabled, o.is_pro FROM boats b JOIN organizations o ON o.id = b.organization_id WHERE b.id = ${boatId}
        `;
        const plan = planRows[0];
        if(plan && plan.plan_limits_enabled){
          const staffCap = plan.is_pro ? 10 : 2;
          const managerCap = plan.is_pro ? 2 : 0;
          if(staffCount > staffCap){
            return res.status(400).json({ error: `Your plan allows up to ${staffCap} staff per boat.` });
          }
          if(managerCount > managerCap){
            return res.status(400).json({ error: managerCap === 0 ? 'Managers require the Pro plan.' : `Your plan allows up to ${managerCap} managers per boat.` });
          }
        }
      }
      storedValue = hashRawPinsInSettings({ ...storedValue });
      if (storedValue.bankAccountName) storedValue.bankAccountName = encryptField(storedValue.bankAccountName, boatId);
      if (storedValue.bankAccountNumber) storedValue.bankAccountNumber = encryptField(storedValue.bankAccountNumber, boatId);
    }
    if (key === 'shipments' && Array.isArray(storedValue)) {
      storedValue = storedValue.map(s => (s && s.photo) ? { ...s, photo: encryptField(s.photo, boatId) } : s);
    }
    await sql`
      INSERT INTO app_data (boat_id, key, value, updated_at)
      VALUES (${boatId}, ${key}, ${JSON.stringify(storedValue)}::jsonb, now())
      ON CONFLICT (boat_id, key) DO UPDATE SET value = ${JSON.stringify(storedValue)}::jsonb, updated_at = now()
    `;
    // Respond with what the client actually sent (pre-hash/pre-encrypt) --
    // it already has the plaintext it just submitted, no need to make it
    // wait for a round trip through sanitizeSettingsForClient just to get
    // back the same thing it already has in memory.
    res.json({ value });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'db error' });
  }
});

// Staff/Manager PIN sign-in -- PINs are hashed at rest (see
// hashRawPinsInSettings above) and never sent to the client, so matching
// an entered PIN against a boat's staff/manager list has to happen here
// instead of in the browser. Returns just enough for the client to start a
// session (name/username) -- never the PIN or its hash.
app.post('/api/staff-login/:boatId', async (req, res) => {
  const { boatId } = req.params;
  const entered = (req.body && req.body.pin) || '';
  if (!entered) return res.status(400).json({ ok: false, error: 'PIN is required.' });
  try {
    const boatRows = await sql`SELECT status, suspension_note FROM boats WHERE id = ${boatId}`;
    if (!boatRows.length) return res.status(404).json({ ok: false, error: 'Unknown boat.' });
    if (boatRows[0].status === 'suspended') return res.status(403).json({ ok: false, error: 'This boat has been suspended.', note: boatRows[0].suspension_note || null });
    const rows = await sql`SELECT value FROM app_data WHERE boat_id = ${boatId} AND key = 'settings'`;
    const settings = rows.length ? rows[0].value : {};
    const users = settings.staffUsers || [];
    const match = users.find(u => u.pin && verifySecret(entered, u.pin));
    if (match) return res.json({ ok: true, name: match.name || null, username: match.username || null });
    // Legacy fallback: a single shared staff PIN, only while no named staff
    // accounts exist yet -- same rule the old client-side check used.
    if (users.length === 0 && settings.staffPin && verifySecret(entered, settings.staffPin)) {
      return res.json({ ok: true, name: null, username: null });
    }
    res.status(401).json({ ok: false, error: 'Incorrect PIN. Try again.' });
  } catch (e) {
    console.error(e);
    res.status(500).json({ ok: false, error: 'db error' });
  }
});

// Owner PIN sign-in for a specific boat (#owner/<boatId> direct links) --
// distinct from /api/org-login, which uses the organization-wide
// boatName+passkey. Same hashed-at-rest, verified-server-side pattern as
// staff/manager above.
app.post('/api/owner-pin-login/:boatId', async (req, res) => {
  const { boatId } = req.params;
  const entered = (req.body && req.body.pin) || '';
  if (!entered) return res.status(400).json({ ok: false, error: 'PIN is required.' });
  try {
    const boatRows = await sql`SELECT status, suspension_note FROM boats WHERE id = ${boatId}`;
    if (!boatRows.length) return res.status(404).json({ ok: false, error: 'Unknown boat.' });
    if (boatRows[0].status === 'suspended') return res.status(403).json({ ok: false, error: 'This boat has been suspended.', note: boatRows[0].suspension_note || null });
    const rows = await sql`SELECT value FROM app_data WHERE boat_id = ${boatId} AND key = 'settings'`;
    const settings = rows.length ? rows[0].value : {};
    if (settings.ownerPin && verifySecret(entered, settings.ownerPin)) {
      return res.json({ ok: true });
    }
    res.status(401).json({ ok: false, error: 'Incorrect PIN. Try again.' });
  } catch (e) {
    console.error(e);
    res.status(500).json({ ok: false, error: 'db error' });
  }
});

app.post('/api/manager-login/:boatId', async (req, res) => {
  const { boatId } = req.params;
  const entered = (req.body && req.body.pin) || '';
  if (!entered) return res.status(400).json({ ok: false, error: 'PIN is required.' });
  try {
    const boatRows = await sql`SELECT status, suspension_note FROM boats WHERE id = ${boatId}`;
    if (!boatRows.length) return res.status(404).json({ ok: false, error: 'Unknown boat.' });
    if (boatRows[0].status === 'suspended') return res.status(403).json({ ok: false, error: 'This boat has been suspended.', note: boatRows[0].suspension_note || null });
    const rows = await sql`SELECT value FROM app_data WHERE boat_id = ${boatId} AND key = 'settings'`;
    const settings = rows.length ? rows[0].value : {};
    const users = settings.managerUsers || [];
    const match = users.find(u => u.pin && verifySecret(entered, u.pin));
    if (match) return res.json({ ok: true, name: match.name || null, username: match.username || null });
    res.status(401).json({ ok: false, error: 'Incorrect PIN. Try again.' });
  } catch (e) {
    console.error(e);
    res.status(500).json({ ok: false, error: 'db error' });
  }
});

// --- Swipe payment integration (Pro upgrade) --------------------------------
// Lets the Pro-upgrade popup offer a real payment link (via Swipe's Merchants
// API) alongside the existing manual bank-transfer + screenshot flow. Swipe
// confirms payment through a webhook, which grants/renews Pro on this boat's
// settings automatically -- no admin approval needed for this path (the
// manual bank-transfer path is untouched and still requires it).
//
// SWIPE_CLIENT_ID / SWIPE_CLIENT_SECRET: from the Swipe Merchant Portal
// (merchant.swipe.mv) -> Settings -> API Access -> Create.
// SWIPE_WEBHOOK_SECRET: the "Webhook HMAC Key" shown on that same page.
// SWIPE_ENV: 'production' (default) or 'development' -- selects which of
// Swipe's two API base URLs to use.
// SWIPE_PRO_AMOUNT: MVR amount charged for a 30-day Pro period (defaults to
// the same ރ500 shown in the manual bank-transfer flow).
// MALDEXPRESS_SWIPE_WEBHOOK_URL: this Swipe client/wallet
// (greenwoodsinvestment@swipe) is shared with a second app, Maldexpress,
// for its own Pro-tier payments. Swipe allows only one webhook URL per
// client and it points at this server, so /api/webhooks/swipe relays any
// event that belongs to Maldexpress (transaction_code prefixed
// "maldexpress_") on to this URL untouched. Leave unset to disable the
// relay entirely -- every event then falls through to SeaFare's own logic.
const SWIPE_CLIENT_ID = process.env.SWIPE_CLIENT_ID;
const SWIPE_CLIENT_SECRET = process.env.SWIPE_CLIENT_SECRET;
const SWIPE_WEBHOOK_SECRET = process.env.SWIPE_WEBHOOK_SECRET;
const MALDEXPRESS_SWIPE_WEBHOOK_URL = process.env.MALDEXPRESS_SWIPE_WEBHOOK_URL;
// Shared secret Maldexpress sends (as X-Internal-Secret) when registering a
// Swipe reference it just created -- see POST /api/internal/register-swipe-reference
// below. Must match the value set on Maldexpress's Supabase Edge Function secrets.
const SEAFARE_INTERNAL_SECRET = process.env.SEAFARE_INTERNAL_SECRET;
const SWIPE_BASE_URL = process.env.SWIPE_ENV === 'development'
  ? 'https://merchant-api.swipeapp.dev'
  : 'https://api.swipe.mv';
// Token endpoint is on the production host even in development per Swipe's
// own docs example -- both environments' credentials are exchanged there.
const SWIPE_TOKEN_URL = 'https://api.swipe.mv/oauth2/token';
const SWIPE_PRO_AMOUNT = Number(process.env.SWIPE_PRO_AMOUNT) || 500;

// Swipe's live API reports a completed payment's status as 'FULFILLED' --
// not 'COMPLETED', which is what this integration originally assumed (a
// common status name for other providers, but not what Swipe actually
// sends). That mismatch meant a real, successful payment never matched the
// `=== 'COMPLETED'` checks below, so Pro was never granted no matter how
// many times the payment was confirmed on Swipe's side, and it never
// showed up in the Super Admin's "Paid via Swipe" tab either (that list is
// filtered on pro_payments.status = 'COMPLETED'). Treat either spelling as
// "done" on the way in, but always store/report our own canonical
// 'COMPLETED' afterwards so every other place in the app only ever has to
// compare against one value.
const SWIPE_DONE_STATUSES = new Set(['COMPLETED', 'FULFILLED']);
function isSwipeStatusDone(status){
  return SWIPE_DONE_STATUSES.has(String(status || '').toUpperCase());
}

// Cached in memory (per server process) rather than fetched fresh on every
// request -- client-credentials tokens are normally valid for a while, and
// refetching one per payment link would be wasteful. Refreshed a minute
// before actual expiry to avoid a request failing right at the boundary.
let _swipeToken = null;
let _swipeTokenExpiresAt = 0;
async function getSwipeAccessToken(){
  if(!SWIPE_CLIENT_ID || !SWIPE_CLIENT_SECRET){
    throw new Error('Swipe is not configured (SWIPE_CLIENT_ID / SWIPE_CLIENT_SECRET missing).');
  }
  if(_swipeToken && Date.now() < _swipeTokenExpiresAt - 60000) return _swipeToken;
  const res = await fetch(SWIPE_TOKEN_URL, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type: 'client_credentials',
      client_id: SWIPE_CLIENT_ID,
      client_secret: SWIPE_CLIENT_SECRET,
    }),
  });
  if(!res.ok) throw new Error(`Swipe token request failed (HTTP ${res.status})`);
  const data = await res.json();
  _swipeToken = data.access_token;
  _swipeTokenExpiresAt = Date.now() + (Number(data.expires_in) || 3600) * 1000;
  return _swipeToken;
}
async function swipeApiRequest(method, path, body){
  const token = await getSwipeAccessToken();
  const res = await fetch(`${SWIPE_BASE_URL}${path}`, {
    method,
    headers: {
      'Authorization': `Bearer ${token}`,
      'Content-Type': 'application/json',
    },
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });
  const data = await res.json().catch(() => ({}));
  if(!res.ok){
    const detail = (data && (data.detail || data.type)) || `HTTP ${res.status}`;
    throw new Error(`Swipe API error: ${detail}`);
  }
  return data;
}

// Verifies a Swipe webhook per the Standard Webhooks spec: the signed
// content is "{webhook-id}.{webhook-timestamp}.{raw body}", HMAC-SHA256'd
// with the webhook secret (Standard Webhooks secrets are given as
// "whsec_<base64>" -- the part after the prefix is what actually gets
// base64-decoded into key bytes). The header can carry multiple
// space-separated "v1,<sig>" values; matching any one of them counts as
// verified. Also rejects anything older than 5 minutes to guard against a
// replayed request.
function verifySwipeWebhookSignature(headers, rawBody){
  if(!SWIPE_WEBHOOK_SECRET) return false;
  const id = headers['webhook-id'];
  const timestamp = headers['webhook-timestamp'];
  const signatureHeader = headers['webhook-signature'];
  if(!id || !timestamp || !signatureHeader) return false;

  const ageSeconds = Math.abs(Date.now() / 1000 - Number(timestamp));
  if(!Number.isFinite(ageSeconds) || ageSeconds > 300) return false;

  const secretBytes = Buffer.from(
    SWIPE_WEBHOOK_SECRET.startsWith('whsec_') ? SWIPE_WEBHOOK_SECRET.slice('whsec_'.length) : SWIPE_WEBHOOK_SECRET,
    'base64'
  );
  const signedContent = `${id}.${timestamp}.${rawBody}`;
  const expected = crypto.createHmac('sha256', secretBytes).update(signedContent).digest('base64');

  return signatureHeader.split(' ').some(part => {
    const sig = part.includes(',') ? part.split(',')[1] : part;
    if(!sig) return false;
    try{
      return crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expected));
    }catch(e){ return false; } // length mismatch -- definitely not equal
  });
}

// Same grant/renew math as the Super Admin's manual approval (adminApproveProForBoat
// in index.html): extends 30 days from the boat's existing expiry if it has
// one (so a renewal never loses days), otherwise 30 days from now.
async function grantProToBoat(boatId){
  const boatRows = await sql`SELECT organization_id FROM boats WHERE id = ${boatId}`;
  if(!boatRows.length) return;
  await grantProToOrganization(boatRows[0].organization_id);
}
async function grantProToOrganization(organizationId){
  const rows = await sql`SELECT pro_expires_at FROM organizations WHERE id = ${organizationId}`;
  if(!rows.length) return;
  const periodStart = rows[0].pro_expires_at ? new Date(rows[0].pro_expires_at) : new Date();
  const periodEnd = new Date(periodStart.getTime() + 30 * 24 * 60 * 60 * 1000);
  await sql`
    UPDATE organizations SET is_pro = true, pro_started_at = ${periodStart.toISOString()}, pro_expires_at = ${periodEnd.toISOString()}
    WHERE id = ${organizationId}
  `;
}
// Grants Pro for a completed Swipe payment AND raises an admin
// notification -- shared by the webhook and the manual "Check Now"
// fallback so both notify the same way regardless of which one actually
// caught the completion first.
async function grantProForSwipePayment(record){
  await grantProToBoat(record.boat_id);
  const orgRows = await sql`
    SELECT o.id AS organization_id, o.boat_name AS org_boat_name, o.owner_name FROM boats b
    JOIN organizations o ON o.id = b.organization_id
    WHERE b.id = ${record.boat_id}
  `;
  const orgLabel = orgRows.length ? `${orgRows[0].owner_name} (${orgRows[0].org_boat_name})` : record.boat_id;
  await notifyAdmin('pro_paid_via_swipe', `${orgLabel} paid \u0783${record.amount} via Swipe \u2014 Pro granted automatically, no approval needed.`, orgRows.length ? { type:'organization', id: orgRows[0].organization_id } : undefined);
}

// Creates a Swipe payment link for this boat's Pro upgrade/renewal. The
// `reference` Swipe returns (its transaction code) is stored alongside the
// boat ID so the webhook -- which only knows that reference, not anything
// about SeaFare -- can find its way back to the right boat.
app.post('/api/pro/payment-link', async (req, res) => {
  try{
    const { boatId } = req.body || {};
    if(!boatId) return res.status(400).json({ ok:false, error:'boatId is required.' });
    const boatRows = await sql`SELECT id FROM boats WHERE id = ${boatId}`;
    if(!boatRows.length) return res.status(404).json({ ok:false, error:'Unknown boat.' });

    const payment = await swipeApiRequest('POST', '/api/v1/payments', {
      amount: SWIPE_PRO_AMOUNT,
      currency: 'MVR',
      type: 'LINK',
      description: `SeaFare Pro upgrade -- boat ${boatId}`,
    });

    await sql`
      INSERT INTO pro_payments (id, boat_id, swipe_payment_id, reference, amount, currency, status, payment_url)
      VALUES (${'pp-' + Date.now() + '-' + Math.random().toString(36).slice(2,8)}, ${boatId}, ${payment.id}, ${payment.reference}, ${payment.amount}, ${payment.currency}, ${payment.status}, ${payment.payment_url || null})
    `;

    res.status(201).json({ ok:true, paymentUrl: payment.payment_url, swipePaymentId: payment.id, reference: payment.reference || null, status: payment.status });
  }catch(e){
    console.error('create payment link failed', e);
    res.status(502).json({ ok:false, error: 'Could not create a Swipe payment link. Try again, or use the bank transfer option.' });
  }
});

// Manual fallback check (used by a "Check payment status" button in the
// popup) -- polls Swipe directly for this reference's current status,
// rather than only ever waiting on the webhook. Grants Pro here too if it
// turns out to already be COMPLETED and this reference hasn't been
// processed yet, in case the webhook was missed or isn't configured yet.
app.get('/api/pro/payment-link/:reference/status', async (req, res) => {
  try{
    const rows = await sql`SELECT * FROM pro_payments WHERE swipe_payment_id = ${req.params.reference}`;
    if(!rows.length) return res.status(404).json({ ok:false, error:'Unknown payment reference.' });
    const record = rows[0];
    if(record.status === 'COMPLETED'){
      return res.json({ ok:true, status: 'COMPLETED' });
    }
    const remote = await swipeApiRequest('GET', `/api/v1/payments/${record.swipe_payment_id}`);
    if(isSwipeStatusDone(remote.status) && record.status !== 'COMPLETED'){
      await sql`UPDATE pro_payments SET status = 'COMPLETED', completed_at = now() WHERE swipe_payment_id = ${req.params.reference}`;
      if(record.purpose !== 'due_clearance') await grantProForSwipePayment(record);
      return res.json({ ok:true, status: 'COMPLETED' });
    } else if(remote.status !== record.status){
      await sql`UPDATE pro_payments SET status = ${remote.status} WHERE swipe_payment_id = ${req.params.reference}`;
    }
    res.json({ ok:true, status: remote.status });
  }catch(e){
    console.error('payment status check failed', e);
    res.status(502).json({ ok:false, error:'Could not check payment status.' });
  }
});

// --- Blocked Users: pay off an outstanding balance to unblock ---------------
// Mirrors the Pro-upgrade Swipe flow above (same pro_payments table, same
// token/webhook plumbing), but for clearing the due_amount on a
// suspended organization so its numbers can be freed -- see
// resolveDuePayment() and neon-schema.sql for the full picture. Reached
// from the "blocked number" popup shown on a blocked signup attempt.
app.post('/api/blocked-numbers/due-payment-link', async (req, res) => {
  try{
    const { organizationId } = req.body || {};
    if(!organizationId) return res.status(400).json({ ok:false, error:'organizationId is required.' });
    const orgRows = await sql`SELECT id, due_amount, due_currency FROM organizations WHERE id = ${organizationId}`;
    if(!orgRows.length) return res.status(404).json({ ok:false, error:'This account no longer exists.' });
    const amount = Number(orgRows[0].due_amount) || SWIPE_PRO_AMOUNT;
    const currency = orgRows[0].due_currency || 'MVR';

    const payment = await swipeApiRequest('POST', '/api/v1/payments', {
      amount, currency, type: 'LINK',
      description: `SeaFare outstanding balance -- organization ${organizationId}`,
    });

    await sql`
      INSERT INTO pro_payments (id, boat_id, organization_id, purpose, swipe_payment_id, reference, amount, currency, status, payment_url)
      VALUES (${'pp-' + Date.now() + '-' + Math.random().toString(36).slice(2,8)}, NULL, ${organizationId}, 'due_clearance', ${payment.id}, ${payment.reference}, ${payment.amount}, ${payment.currency}, ${payment.status}, ${payment.payment_url || null})
    `;

    res.status(201).json({ ok:true, paymentUrl: payment.payment_url, swipePaymentId: payment.id, reference: payment.reference || null, status: payment.status, amount, currency });
  }catch(e){
    console.error('create due-payment link failed', e);
    res.status(502).json({ ok:false, error: 'Could not create a payment link. Try again in a moment.' });
  }
});

app.get('/api/blocked-numbers/due-payment-link/:reference/status', async (req, res) => {
  try{
    const rows = await sql`SELECT * FROM pro_payments WHERE swipe_payment_id = ${req.params.reference} AND purpose = 'due_clearance'`;
    if(!rows.length) return res.status(404).json({ ok:false, error:'Unknown payment reference.' });
    const record = rows[0];
    if(record.status === 'COMPLETED') return res.json({ ok:true, status:'COMPLETED' });
    const remote = await swipeApiRequest('GET', `/api/v1/payments/${record.swipe_payment_id}`);
    if(isSwipeStatusDone(remote.status) && record.status !== 'COMPLETED'){
      await sql`UPDATE pro_payments SET status = 'COMPLETED', completed_at = now() WHERE swipe_payment_id = ${req.params.reference}`;
      return res.json({ ok:true, status:'COMPLETED' });
    } else if(remote.status !== record.status){
      await sql`UPDATE pro_payments SET status = ${remote.status} WHERE swipe_payment_id = ${req.params.reference}`;
    }
    res.json({ ok:true, status: remote.status });
  }catch(e){
    console.error('due-payment status check failed', e);
    res.status(502).json({ ok:false, error:'Could not check payment status.' });
  }
});

// Called once the owner picks "continue with my previous account" or
// "start fresh" after a due-clearance payment completes. Either way every
// number tied to the organization is freed; 'existing' also reactivates
// the account, 'new' removes it entirely (paid up, but not resumed) so
// the person can sign up clean -- and, since a brand-new organization
// always starts on the free tier by default, that fresh signup is
// automatically not Pro.
app.post('/api/blocked-numbers/resolve', async (req, res) => {
  try{
    const { reference, choice } = req.body || {};
    if(!reference || !['existing','new'].includes(choice)){
      return res.status(400).json({ ok:false, error:'reference and a valid choice are required.' });
    }
    const rows = await sql`SELECT * FROM pro_payments WHERE swipe_payment_id = ${reference} AND purpose = 'due_clearance'`;
    if(!rows.length) return res.status(404).json({ ok:false, error:'Unknown payment reference.' });
    const record = rows[0];
    if(record.status !== 'COMPLETED') return res.status(400).json({ ok:false, error:'Payment has not completed yet.' });
    if(record.resolved) return res.status(400).json({ ok:false, error:'This payment has already been used.' });
    await resolveDuePayment(record, choice);
    await sql`UPDATE pro_payments SET resolved = true WHERE id = ${record.id}`;
    res.json({ ok:true, choice });
  }catch(e){
    console.error('resolve due payment failed', e);
    res.status(500).json({ ok:false, error:'Could not complete this action.' });
  }
});

// Maldexpress registers a Swipe reference here the moment it creates a
// payment link, before ever handing that link back to its own client --
// closing the race where a webhook could fire before this row exists.
// Gated by a shared secret header, not a Supabase session, since the
// caller is a server (Maldexpress's edge function), not a browser.
app.post('/api/internal/register-swipe-reference', async (req, res) => {
  try{
    if(!SEAFARE_INTERNAL_SECRET || req.headers['x-internal-secret'] !== SEAFARE_INTERNAL_SECRET){
      return res.status(401).json({ registered:false, error:'Invalid internal secret.' });
    }
    const { reference, source } = req.body || {};
    if(!reference || typeof reference !== 'string'){
      return res.status(400).json({ registered:false, error:'reference is required.' });
    }
    await sql`
      INSERT INTO external_swipe_references (reference, source)
      VALUES (${reference}, ${source || 'unknown'})
      ON CONFLICT (reference) DO NOTHING
    `;
    res.json({ registered:true });
  }catch(e){
    console.error('register-swipe-reference failed', e);
    res.status(500).json({ registered:false, error:'Could not register reference.' });
  }
});

// Swipe calls this whenever a transaction's status changes. Only
// transaction.state_changed events with status COMPLETED, for a reference
// we actually created a link for, ever grant Pro -- and only once (the
// pro_payments.status check makes this safe against Swipe retrying/
// redelivering the same webhook).
app.post('/api/webhooks/swipe', async (req, res) => {
  try{
    const rawBody = req.rawBody ? req.rawBody.toString('utf8') : JSON.stringify(req.body);
    if(!verifySwipeWebhookSignature(req.headers, rawBody)){
      return res.status(401).json({ ok:false, error:'Invalid webhook signature.' });
    }

    // --- Maldexpress relay ------------------------------------------------
    // The Swipe client/wallet behind this webhook is shared with a second
    // app (Maldexpress) for its own Pro payments, and Swipe only allows one
    // webhook URL per client. Swipe assigns its own opaque transaction id --
    // Maldexpress can never set a recognizable prefix on it -- so instead of
    // pattern-matching the reference, check whether Maldexpress registered
    // this exact id with us in advance (via
    // POST /api/internal/register-swipe-reference, called right after it
    // creates the payment link). A match means the event is not ours:
    // forward the original request verbatim (same raw body, same
    // webhook-id/webhook-timestamp/webhook-signature headers) to
    // Maldexpress's own endpoint and mirror that call's outcome back to
    // Swipe, so a failure there still gets retried by Swipe. SeaFare does no
    // further processing for these events. Unregistered events fall
    // straight through to SeaFare's own logic below, unchanged. If
    // MALDEXPRESS_SWIPE_WEBHOOK_URL is unset the relay is inert.
    const swipeTxId = (req.body && req.body.data && (req.body.data.transaction_id || req.body.data.id)) || '';
    let isMaldexpressRef = false;
    if(MALDEXPRESS_SWIPE_WEBHOOK_URL && swipeTxId){
      const registered = await sql`SELECT 1 FROM external_swipe_references WHERE reference = ${swipeTxId}`;
      isMaldexpressRef = registered.length > 0;
    }
    if(isMaldexpressRef){
      if(!req.rawBody){
        // Only the exact bytes Swipe signed can be forwarded -- a
        // re-serialized body would fail Maldexpress's signature check.
        // Treat a missing raw body as a failed delivery so Swipe retries.
        console.error('swipe->maldexpress relay: raw body unavailable, not forwarding');
        return res.status(502).json({ ok:false, error:'relay body unavailable' });
      }
      try{
        const relayed = await fetch(MALDEXPRESS_SWIPE_WEBHOOK_URL, {
          method: 'POST',
          headers: {
            'content-type': 'application/json',
            'webhook-id': req.headers['webhook-id'],
            'webhook-timestamp': req.headers['webhook-timestamp'],
            'webhook-signature': req.headers['webhook-signature'],
          },
          body: req.rawBody,
          signal: AbortSignal.timeout(10000),
        });
        if(relayed.ok) return res.json({ ok:true, relayed:true });
        console.error(`swipe->maldexpress relay: upstream returned HTTP ${relayed.status}`);
        return res.status(502).json({ ok:false, relayed:true, upstreamStatus: relayed.status });
      }catch(e){
        // Network error or the 10s timeout -- non-2xx so Swipe retries.
        console.error('swipe->maldexpress relay failed', e);
        return res.status(502).json({ ok:false, relayed:true });
      }
    }

    const { eventType, data } = req.body || {};
    if(eventType !== 'transaction.state_changed' || !data){
      return res.json({ ok:true }); // acknowledged, nothing to do
    }
    // transaction_id (Swipe's own payment ID, always present) is the
    // reliable correlation key -- transaction_code/reference isn't always
    // assigned at creation time, so a stored row's reference column can
    // be NULL, and "WHERE reference = <code>" would never match a NULL
    // column even if Swipe does send a code here. Try the ID first, fall
    // back to the code for older rows that do have one on record.
    const txId = data.transaction_id || data.id || null;
    const txCode = data.transaction_code || null;
    if(!txId && !txCode) return res.json({ ok:true });

    let rows = txId ? await sql`SELECT * FROM pro_payments WHERE swipe_payment_id = ${txId}` : [];
    if(!rows.length && txCode) rows = await sql`SELECT * FROM pro_payments WHERE reference = ${txCode}`;
    if(!rows.length) return res.json({ ok:true }); // not one of ours (or a different payment type)
    const record = rows[0];

    if(isSwipeStatusDone(data.status) && record.status !== 'COMPLETED'){
      await sql`UPDATE pro_payments SET status = 'COMPLETED', completed_at = now(), reference = COALESCE(reference, ${txCode}) WHERE id = ${record.id}`;
      // due_clearance payments don't auto-grant Pro or auto-reactivate the
      // account -- the owner still has to pick "continue" or "start
      // fresh" via POST /api/blocked-numbers/resolve after this.
      if(record.purpose !== 'due_clearance') await grantProForSwipePayment(record);
    } else if(data.status !== record.status){
      await sql`UPDATE pro_payments SET status = ${data.status}, reference = COALESCE(reference, ${txCode}) WHERE id = ${record.id}`;
    }
    res.json({ ok:true });
  }catch(e){
    console.error('swipe webhook handling failed', e);
    res.status(500).json({ ok:false });
  }
});

// --- RedotPay crypto payment integration (Pro upgrade) -----------------------
// A second, independent "Pay by Crypto" option alongside Swipe -- same
// pro_payments table, same overall shape (create a link, poll/webhook,
// grant Pro on completion), but RedotPay's own API instead of Swipe's:
// RSA-signed requests instead of an OAuth bearer token, and an order
// serial number (orderSn) instead of a Swipe payment id. Rows from this
// provider are distinguished by pro_payments.provider = 'redotpay' and use
// the redotpay_order_sn column as their correlation key (swipe_payment_id
// stays NULL on these rows).
//
// REDOTPAY_APP_KEY: from the RedotPay Connect merchant platform's
// Developer settings (the "appKey" shown after uploading your RSA public
// key there).
// REDOTPAY_PRIVATE_KEY: the PEM private key half of that same RSA pair
// (paste the whole "-----BEGIN PRIVATE KEY-----...-----END PRIVATE
// KEY-----" block, or a single-line value with literal \n's -- both are
// handled below). Never upload this anywhere; only the public key goes to
// RedotPay.
// REDOTPAY_KEY_VERSION: the "X-R-Key-Version" of that key pair on
// RedotPay's side (defaults to 1 -- only changes after a key rotation).
// REDOTPAY_ENV: 'production' (default) or 'sandbox' -- selects which of
// RedotPay's two API hosts to use.
// REDOTPAY_WEBHOOK_KEY_VERSION is NOT a separate setting -- webhooks carry
// their own X-R-Key-Version header, matched against RedotPay's published
// platform public keys below (selected by REDOTPAY_ENV).
// REDOTPAY_PRO_AMOUNT / REDOTPAY_PRO_CURRENCY: the fiat amount+currency
// charged for a 30-day Pro period via this path. Defaults to 35 USD rather
// than reusing the ރ500 Swipe/bank-transfer figure -- set
// REDOTPAY_PRO_AMOUNT/REDOTPAY_PRO_CURRENCY to whatever your RedotPay
// merchant account actually supports.
const REDOTPAY_APP_KEY = process.env.REDOTPAY_APP_KEY;
const REDOTPAY_PRIVATE_KEY = process.env.REDOTPAY_PRIVATE_KEY
  ? process.env.REDOTPAY_PRIVATE_KEY.includes('BEGIN PRIVATE KEY')
    ? process.env.REDOTPAY_PRIVATE_KEY.replace(/\\n/g, '\n')
    : `-----BEGIN PRIVATE KEY-----\n${process.env.REDOTPAY_PRIVATE_KEY.replace(/\\n/g, '\n')}\n-----END PRIVATE KEY-----\n`
  : null;
const REDOTPAY_KEY_VERSION = process.env.REDOTPAY_KEY_VERSION || '1';
const REDOTPAY_BASE_URL = process.env.REDOTPAY_ENV === 'sandbox'
  ? 'https://acquirersandbox.rp-2023app.com'
  : 'https://acquirer.redotpay.com';
const REDOTPAY_PRO_AMOUNT = Number(process.env.REDOTPAY_PRO_AMOUNT) || 35;
const REDOTPAY_PRO_CURRENCY = process.env.REDOTPAY_PRO_CURRENCY || 'USD';


// RedotPay's own published platform public keys, used to verify the
// X-R-Signature header on incoming webhooks -- these are fixed per RedotPay's
// docs (one pair per environment, keyed by X-R-Key-Version), not something
// this deployment generates, so they're safe to hardcode here rather than
// pull from an env var. Selected by REDOTPAY_ENV + the X-R-Key-Version the
// webhook actually carries.
const REDOTPAY_PLATFORM_PUBLIC_KEYS = {
  sandbox: {
    '1': `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuctrVK3eP8hpoJf7FMet
lcR77FYcj9HtrkySyGDRt5HHwdwgM8jK0kfE4ag/zI8goe8M0iJ2o7n3VCfTzn8O
yfU0bu6KzDti1WOJV9fv4XtSmhm9W4WKjIc8uDQViR7E8trzcrbKFVbKVGng1+z0
KobQBDtWhjUeXKktUq1lpiejTS+XjXej26ANPfwbqbY+/6kBB3sWbt9BLDI/WhPY
XnFV9oJWod9I/dYUgUUA/b/+bI1wlobNntBDxiNmX0kbqpGZbzO6l9wWFXZiFCD2
5QtBOZlMbn9noH4KW3DnKGc2nKNz/f2FEM9DJKn3P7NGFVy6O/Q5NzcbFs+DI6nT
ywIDAQAB
-----END PUBLIC KEY-----`,
  },
  production: {
    '1': `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAzMn4r06M/cp2amkbCxIs
PSr030JoCFeymwjTZrBnI8kW4mtL6JtUPYpJTFgCB8ZQoV75lEmUw8gSLbN770Cc
5EOi1dF4ekmLQ7Ez0SFUbQgJa7Vg5wBdSKcbUmkKGviJt+iZRJ0tZsPpXMPqIo9Y
OWJagfPbDhEwT2t1ANP4ou98sCqLqELI80iYm8+W4B9IvBW4lc+H5BAPtXpYMtlZ
6stCnvHXd1EjvlTak25v5xJ8AInEeAy8/D2glunmz/VfPyoB5OHPgnYVU66HyeQc
O1ZY/jzB5d6I/zX4JENG1xrP8ThPZ9qMWtmputJ0XYKymiZgZP6vh0L+G6P/Z98v
lQIDAQAB
-----END PUBLIC KEY-----`,
  },
};
function redotpayEnvName(){ return process.env.REDOTPAY_ENV === 'sandbox' ? 'sandbox' : 'production'; }

// RedotPay's order status is a small integer (see docs), not a status word
// like Swipe's -- normalized here to the same canonical strings this app
// already stores in pro_payments.status ('PENDING' / 'COMPLETED' / 'FAILED'
// / 'CLOSED') so every other place that reads that column doesn't need to
// know which provider a row came from.
function normalizeRedotPayOrderStatus(orderStatus){
  switch(Number(orderStatus)){
    case 1: return 'PENDING';
    case 2: return 'COMPLETED';
    case 3: return 'FAILED';
    case 4: return 'CLOSED';
    default: return 'PENDING';
  }
}

// Builds the SHA256withRSA signature RedotPay requires on every signed
// request: base64(sign("{METHOD} {uri}\n{appKey}.{ts}.{compactJsonBody}")).
// Sandbox doesn't actually check this (per RedotPay's docs, signature
// verification is off there to ease testing), but it's generated the same
// way regardless so switching REDOTPAY_ENV to production later doesn't
// silently break.
function signRedotPayRequest(method, uri, appKey, timestamp, bodyString){
  const stringToSign = `${method} ${uri}\n${appKey}.${timestamp}.${bodyString}`;
  const signer = crypto.createSign('RSA-SHA256');
  signer.update(stringToSign, 'utf8');
  return signer.sign(REDOTPAY_PRIVATE_KEY).toString('base64');
}
async function redotpayApiRequest(method, path, body){
  if(!REDOTPAY_APP_KEY) throw new Error('RedotPay is not configured (REDOTPAY_APP_KEY missing).');
  const bodyString = JSON.stringify(body);
  const timestamp = String(Date.now());
  const headers = {
    'Content-Type': 'application/json',
    'X-R-Ak': REDOTPAY_APP_KEY,
    'X-R-Ts': timestamp,
    'X-R-Key-Version': REDOTPAY_KEY_VERSION,
  };
  // Signing is only possible (and only required outside sandbox) once a
  // private key is configured -- omitted entirely rather than sent empty,
  // since RedotPay treats a present-but-invalid header differently from a
  // missing one.
  if(REDOTPAY_PRIVATE_KEY){
    headers['X-R-Signature'] = signRedotPayRequest(method, path, REDOTPAY_APP_KEY, timestamp, bodyString);
  }
  const res = await fetch(`${REDOTPAY_BASE_URL}${path}`, { method, headers, body: bodyString });
  const data = await res.json().catch(() => ({}));
  if(!res.ok || data.code !== 'SUCCESS'){
    throw new Error(`RedotPay API error: ${(data && data.msg) || `HTTP ${res.status}`}`);
  }
  return data.data || {};
}

// Verifies a RedotPay webhook per its signature guide: the signed content
// is "{appKey}.{X-R-Ts}.{raw body}" (note -- unlike outgoing requests, the
// callback signature omits the HTTP method/URI), SHA256withRSA-verified
// against RedotPay's own published platform public key for this
// environment and the X-R-Key-Version the webhook carries -- never against
// this deployment's own key pair, which only signs outgoing requests.
// Also rejects anything older than 5 minutes to guard against replay.
function verifyRedotPayWebhookSignature(headers, rawBody){
  if(!REDOTPAY_APP_KEY) return false;
  const timestamp = headers['x-r-ts'];
  const signature = headers['x-r-signature'];
  const keyVersion = headers['x-r-key-version'] || '1';
  if(!timestamp || !signature) return false;

  const ageMs = Math.abs(Date.now() - Number(timestamp));
  if(!Number.isFinite(ageMs) || ageMs > 5 * 60 * 1000) return false;

  const publicKeyPem = (REDOTPAY_PLATFORM_PUBLIC_KEYS[redotpayEnvName()] || {})[String(keyVersion)];
  if(!publicKeyPem) return false;

  try{
    const stringToVerify = `${REDOTPAY_APP_KEY}.${timestamp}.${rawBody}`;
    const verifier = crypto.createVerify('RSA-SHA256');
    verifier.update(stringToVerify, 'utf8');
    return verifier.verify(publicKeyPem, Buffer.from(signature, 'base64'));
  }catch(e){ return false; } // malformed signature -- definitely not valid
}

// Same grant + admin-notification pairing as grantProForSwipePayment above,
// just labelled for the "Paid via RedotPay" case so the Super Admin's
// notification feed and Pro-payments list can tell the two apart.
async function grantProForRedotPayPayment(record){
  await grantProToBoat(record.boat_id);
  const orgRows = await sql`
    SELECT o.id AS organization_id, o.boat_name AS org_boat_name, o.owner_name FROM boats b
    JOIN organizations o ON o.id = b.organization_id
    WHERE b.id = ${record.boat_id}
  `;
  const orgLabel = orgRows.length ? `${orgRows[0].owner_name} (${orgRows[0].org_boat_name})` : record.boat_id;
  await notifyAdmin('pro_paid_via_redotpay', `${orgLabel} paid ${record.currency}${record.amount} via crypto (RedotPay) \u2014 Pro granted automatically, no approval needed.`, orgRows.length ? { type:'organization', id: orgRows[0].organization_id } : undefined);
}

// Creates a RedotPay crypto-payment order for this boat's Pro upgrade/renewal.
// outerOrderSn is this row's own pro_payments id -- RedotPay requires it to
// be 6-32 chars of letters/numbers/_-|*, which the existing 'pp-<ts>-<rand>'
// id shape already satisfies, so it doubles as the correlation key the
// webhook uses to find this row back (see /api/webhooks/redotpay below).
app.post('/api/pro/redotpay-payment-link', async (req, res) => {
  try{
    const { boatId } = req.body || {};
    if(!boatId) return res.status(400).json({ ok:false, error:'boatId is required.' });
    const boatRows = await sql`SELECT id FROM boats WHERE id = ${boatId}`;
    if(!boatRows.length) return res.status(404).json({ ok:false, error:'Unknown boat.' });

    const paymentId = 'pp-' + Date.now() + '-' + Math.random().toString(36).slice(2,8);
    const order = await redotpayApiRequest('POST', '/openapi/v2/order/create', {
      outerOrderSn: paymentId,
      outerUid: boatId,
      orderAmount: REDOTPAY_PRO_AMOUNT,
      orderCurrency: REDOTPAY_PRO_CURRENCY,
      env: 'WEB',
      orderDesc: `SeaFare Pro upgrade -- boat ${boatId}`,
      goods: [{
        goodsType: '02',
        goodsCategory: 'Z000',
        goodsCode: 'SEAFARE-PRO-30D',
        goodsName: 'SeaFare Pro (30 days)',
        goodsCount: 1,
        goodsAmount: REDOTPAY_PRO_AMOUNT,
        goodsCoin: REDOTPAY_PRO_CURRENCY,
      }],
      merchantName: 'SeaFare',
    });

    await sql`
      INSERT INTO pro_payments (id, boat_id, provider, redotpay_order_sn, amount, currency, status, payment_url)
      VALUES (${paymentId}, ${boatId}, 'redotpay', ${order.orderSn}, ${REDOTPAY_PRO_AMOUNT}, ${REDOTPAY_PRO_CURRENCY}, 'PENDING', ${order.webUrl || order.h5Url || null})
    `;

    res.status(201).json({ ok:true, paymentUrl: order.webUrl || order.h5Url || null, orderSn: order.orderSn, status: 'PENDING' });
  }catch(e){
    console.error('create RedotPay payment link failed', e);
    res.status(502).json({ ok:false, error: 'Could not create a crypto payment link. Try again, or use the bank transfer option.' });
  }
});

// Manual fallback check (same role as the Swipe status endpoint) -- polls
// RedotPay directly for this order's current status rather than only ever
// waiting on the webhook, and grants Pro here too if it's already
// COMPLETED and this order hasn't been processed yet.
app.get('/api/pro/redotpay-payment-link/:orderSn/status', async (req, res) => {
  try{
    const rows = await sql`SELECT * FROM pro_payments WHERE redotpay_order_sn = ${req.params.orderSn} AND provider = 'redotpay'`;
    if(!rows.length) return res.status(404).json({ ok:false, error:'Unknown payment reference.' });
    const record = rows[0];
    if(record.status === 'COMPLETED'){
      return res.json({ ok:true, status: 'COMPLETED' });
    }
    const remote = await redotpayApiRequest('POST', '/openapi/v2/order/detail', { orderSn: record.redotpay_order_sn });
    const remoteStatus = normalizeRedotPayOrderStatus(remote.orderStatus);
    if(remoteStatus === 'COMPLETED' && record.status !== 'COMPLETED'){
      await sql`UPDATE pro_payments SET status = 'COMPLETED', completed_at = now() WHERE redotpay_order_sn = ${req.params.orderSn}`;
      if(record.purpose !== 'due_clearance') await grantProForRedotPayPayment(record);
      return res.json({ ok:true, status: 'COMPLETED' });
    } else if(remoteStatus !== record.status){
      await sql`UPDATE pro_payments SET status = ${remoteStatus} WHERE redotpay_order_sn = ${req.params.orderSn}`;
    }
    res.json({ ok:true, status: remoteStatus });
  }catch(e){
    console.error('RedotPay payment status check failed', e);
    res.status(502).json({ ok:false, error:'Could not check payment status.' });
  }
});

// RedotPay calls this once a payment succeeds (see the Webhook doc -- it
// only fires on success, unlike Swipe's every-state-change callback).
// outerOrderSn is this app's own pro_payments.id, set as such at order
// creation, so it's the reliable correlation key here (no fallback needed
// the way Swipe's txCode-vs-txId split required, since RedotPay always
// echoes it back). Idempotent against retries via the same
// status !== 'COMPLETED' guard used on the Swipe webhook.
app.post('/api/webhooks/redotpay', async (req, res) => {
  try{
    const rawBody = req.rawBody ? req.rawBody.toString('utf8') : JSON.stringify(req.body);
    if(!verifyRedotPayWebhookSignature(req.headers, rawBody)){
      return res.status(401).json({ code:'FAIL', requestId: crypto.randomUUID(), msg:'Invalid webhook signature.' });
    }
    const data = req.body || {};
    const paymentId = data.outerOrderSn || data.outerOrder || null;
    if(!paymentId) return res.json({ code:'SUCCESS', requestId: crypto.randomUUID() });

    const rows = await sql`SELECT * FROM pro_payments WHERE id = ${paymentId} AND provider = 'redotpay'`;
    if(!rows.length) return res.json({ code:'SUCCESS', requestId: crypto.randomUUID() }); // not one of ours
    const record = rows[0];

    // The Transaction and Refund webhooks share this same endpoint/body
    // shape (see Developer settings), but only a Transaction event carries
    // orderStatus -- a Refund event echoes outerOrderSn back with no
    // orderStatus field at all. Number(undefined) is NaN, which
    // normalizeRedotPayOrderStatus defaults to 'PENDING', so without this
    // guard a refund notification for an already-COMPLETED payment would
    // silently downgrade it back to PENDING. This app doesn't process
    // refunds yet, so a refund event is just acknowledged and ignored here.
    if(data.orderStatus === undefined || data.orderStatus === null){
      return res.json({ code:'SUCCESS', requestId: crypto.randomUUID() });
    }

    const status = normalizeRedotPayOrderStatus(data.orderStatus);
    if(status === 'COMPLETED' && record.status !== 'COMPLETED'){
      await sql`UPDATE pro_payments SET status = 'COMPLETED', completed_at = now() WHERE id = ${record.id}`;
      if(record.purpose !== 'due_clearance') await grantProForRedotPayPayment(record);
    } else if(status !== record.status){
      await sql`UPDATE pro_payments SET status = ${status} WHERE id = ${record.id}`;
    }
    res.json({ code:'SUCCESS', requestId: crypto.randomUUID() });
  }catch(e){
    console.error('RedotPay webhook handling failed', e);
    res.status(500).json({ code:'FAIL', requestId: crypto.randomUUID(), msg:'internal error' });
  }
});


// the email matches, whether Gmail is configured, or whether sending
// succeeds -- this endpoint must never reveal what the registered address
// is or whether an account exists.
// Returns the currently configured authenticator secret (or null if
// TOTP_SECRET hasn't been set on this deployment), so the Owner Settings
// screen can show it for setting up a new device. Note: like every other
// endpoint in this API, there is no server-side login check here -- anyone
// with the API URL can call this, consistent with the rest of this app's
// security model (see README).
app.get('/api/totp-secret', (req, res) => {
  res.json({ secret: TOTP_SECRET || null });
});

app.post('/api/reset-pin/request', async (req, res) => {
  const generic = { ok: true };
  const raw = (req.body && (req.body.identifier || req.body.email) || '').trim();
  if (!raw) return res.json(generic);

  try {
    const rows = await sql`SELECT value FROM app_data WHERE key = 'settings'`;
    const settings = rows.length ? rows[0].value : {};
    const registeredEmail = (settings.ownerEmail || '').trim().toLowerCase();
    const registeredPhone = (settings.ownerPhone || '').replace(/\D/g, '');

    const inputLower = raw.toLowerCase();
    const inputDigits = raw.replace(/\D/g, '');

    const matchedEmail = !!(registeredEmail && registeredEmail === inputLower);
    const matchedPhone = !!(registeredPhone && inputDigits && registeredPhone === inputDigits);

    if ((!matchedEmail && !matchedPhone) || !APP_URL) {
      if (!APP_URL) console.error('Reset requested but APP_URL is not set.');
      return res.json(generic);
    }

    // Housekeeping: drop old tokens so the table doesn't grow forever.
    await sql`DELETE FROM pin_resets WHERE expires_at < now() - interval '1 day'`;

    const token = crypto.randomBytes(24).toString('hex');
    const expiresAt = new Date(Date.now() + RESET_TOKEN_TTL_MS).toISOString();
    await sql`
      INSERT INTO pin_resets (token, role, expires_at)
      VALUES (${token}, 'owner', ${expiresAt})
    `;

    const link = `${APP_URL}/#reset-pin/${token}`;

    // Email and SMS are both best-effort bonuses, not requirements -- if
    // either isn't configured or fails to send, the link is still returned
    // directly below so the Owner (who just proved they know a registered
    // email or phone) can open it themselves or share it via WhatsApp.
    if (matchedEmail && mailer) {
      mailer.sendMail({
        from: `"SeaFare" <${GMAIL_USER}>`,
        to: registeredEmail,
        subject: 'Reset your SeaFare Owner PIN',
        text: `A reset was requested for your SeaFare Owner PIN.\n\nOpen this link to set a new PIN (it expires in 30 minutes):\n${link}\n\nIf you didn't request this, you can safely ignore this email.`,
        html: `<p>A reset was requested for your SeaFare Owner PIN.</p>
               <p><a href="${link}">Click here to set a new PIN</a> (expires in 30 minutes).</p>
               <p>If you didn't request this, you can safely ignore this email.</p>`,
      }).catch(e => console.error('reset-pin email send failed (link is still returned to the app)', e));
    } else if (matchedEmail && !mailer) {
      console.error('Reset matched by email but GMAIL_USER/GMAIL_APP_PASSWORD are not set -- link returned directly to the app instead.');
    }

    if (matchedPhone && smsClient && TWILIO_PHONE_NUMBER) {
      smsClient.messages.create({
        body: `SeaFare: reset your Owner PIN here (expires in 30 min): ${link}`,
        from: TWILIO_PHONE_NUMBER,
        to: settings.ownerPhone,
      }).catch(e => console.error('reset-pin SMS send failed (link is still returned to the app)', e));
    } else if (matchedPhone && (!smsClient || !TWILIO_PHONE_NUMBER)) {
      console.error('Reset matched by phone but TWILIO_ACCOUNT_SID/TWILIO_AUTH_TOKEN/TWILIO_PHONE_NUMBER are not fully set -- link returned directly to the app instead.');
    }

    res.json({ ok: true, link });
  } catch (e) {
    console.error(e);
    res.json(generic); // never leak failure details to the client
  }
});

// Verify an authenticator-app code. If it matches TOTP_SECRET, issue a
// reset token directly (no email/SMS round-trip needed) -- this path works
// even if Gmail/Twilio are misconfigured or unreachable, since it's fully
// self-contained on this server.
app.post('/api/reset-pin/totp-verify', async (req, res) => {
  const code = (req.body && req.body.code || '').trim();
  const boatId = (req.body && req.body.boatId || '').trim();
  if (!code || !/^\d{6}$/.test(code)) {
    return res.status(400).json({ ok: false, error: 'Enter the 6-digit code from your authenticator app.' });
  }
  try {
    // Each organization got its own totp_secret at signup. If a boatId is
    // given, use THAT organization's secret; otherwise fall back to the
    // single legacy TOTP_SECRET env var (kept only for backward safety).
    let secret = TOTP_SECRET;
    let ownerBoatId = boatId || null;
    if (boatId) {
      const rows = await sql`
        SELECT o.totp_secret FROM boats b
        JOIN organizations o ON o.id = b.organization_id
        WHERE b.id = ${boatId}
      `;
      if (rows.length && rows[0].totp_secret) secret = rows[0].totp_secret;
    }
    if (!secret) {
      return res.status(400).json({ ok: false, error: 'Authenticator reset is not set up for this boat yet.' });
    }
    const valid = authenticator.verify({ token: code, secret });
    if (!valid) {
      return res.status(400).json({ ok: false, error: 'That code is incorrect or expired. Try the latest code shown in your app.' });
    }

    await sql`DELETE FROM pin_resets WHERE expires_at < now() - interval '1 day'`;

    const token = crypto.randomBytes(24).toString('hex');
    const expiresAt = new Date(Date.now() + RESET_TOKEN_TTL_MS).toISOString();
    await sql`
      INSERT INTO pin_resets (token, role, expires_at, boat_id)
      VALUES (${token}, 'owner', ${expiresAt}, ${ownerBoatId})
    `;

    res.json({ ok: true, token });
  } catch (e) {
    console.error(e);
    res.status(500).json({ ok: false, error: 'Something went wrong. Try again.' });
  }
});

// Confirm a reset: consumes the token and sets the new Owner PIN, scoped to
// whichever boat the token was issued for (falls back to the legacy
// unscoped settings row only for very old tokens with no boat_id, which
// will no longer occur going forward).
app.post('/api/reset-pin/confirm', async (req, res) => {
  const { token, newPin } = req.body || {};
  if (!token || !newPin || !/^\d{4,6}$/.test(String(newPin))) {
    return res.status(400).json({ ok: false, error: 'Enter a valid 4\u20136 digit PIN.' });
  }
  try {
    const rows = await sql`SELECT * FROM pin_resets WHERE token = ${token}`;
    const record = rows[0];
    if (!record || record.used || new Date(record.expires_at) < new Date()) {
      return res.status(400).json({ ok: false, error: 'That link is invalid or expired. Request a new one.' });
    }
    if (!record.boat_id) {
      return res.status(400).json({ ok: false, error: 'This reset link is outdated. Request a new one.' });
    }

    const settingsRows = await sql`SELECT value FROM app_data WHERE boat_id = ${record.boat_id} AND key = 'settings'`;
    const settings = settingsRows.length ? settingsRows[0].value : {};
    settings.ownerPin = hashSecret(String(newPin));

    await sql`
      INSERT INTO app_data (boat_id, key, value, updated_at)
      VALUES (${record.boat_id}, 'settings', ${JSON.stringify(settings)}::jsonb, now())
      ON CONFLICT (boat_id, key) DO UPDATE SET value = ${JSON.stringify(settings)}::jsonb, updated_at = now()
    `;
    await sql`UPDATE pin_resets SET used = true WHERE token = ${token}`;

    res.json({ ok: true });
  } catch (e) {
    console.error(e);
    res.status(500).json({ ok: false, error: 'Something went wrong. Try again.' });
  }
});

// --- Super Admin dashboard (Phase 1 of multi-tenant rebuild) ---------------
// ADMIN_USERNAME / ADMIN_PASSWORD are set once as Render env vars, known
// only to you. There's no session system here (consistent with the rest of
// this API's low-auth model) -- the admin dashboard resends both values with
// every request, and each request is checked against these env vars fresh.
// This is fine for a single admin user; it would need a real session/JWT
// layer before adding more admin accounts.
const ADMIN_USERNAME = process.env.ADMIN_USERNAME;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;

// Reuses the same scrypt hashing already used for owner passkeys (see
// hashPasskey/verifyPasskey further down) -- defined early here since
// checkAdmin needs it above their definition.
function hashSecret(secret){
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.scryptSync(String(secret), salt, 64).toString('hex');
  return `${salt}:${hash}`;
}
function verifySecret(secret, stored){
  if(!stored || !stored.includes(':')) return false;
  const [salt, hash] = stored.split(':');
  const check = crypto.scryptSync(String(secret), salt, 64).toString('hex');
  try{ return crypto.timingSafeEqual(Buffer.from(hash,'hex'), Buffer.from(check,'hex')); }
  catch(e){ return false; }
}

// ---------------------------------------------------------------------------
// Field-level encryption for sensitive-but-must-be-readable data (shipment
// photos, bank account details) -- separate from hashSecret/verifySecret
// above, which is for one-way secrets like PINs that only ever need
// comparing, never reading back.
//
// Each boat (or organization) gets its own AES-256-GCM key, derived via
// HKDF from a single master key (APP_DATA_ENCRYPTION_KEY, set in Render's
// env) using that boat's/org's own id as the HKDF "info" parameter. This
// means:
//   - No per-entity keys are stored anywhere -- they're derived on the fly
//     from the id already sitting right next to the data, so there's
//     nothing extra to manage, rotate, or lose.
//   - Data encrypted for one boat is mathematically tied to that boat's id;
//     you can't decrypt boat A's data using boat B's id as the derivation
//     input, even with the master key.
//   - Deleting a boat's rows (already done on org/boat delete elsewhere in
//     this file) is sufficient cleanup -- there's no separate per-boat key
//     record to also delete.
// This protects data that leaks out via the database alone (a stolen
// backup, a misconfigured read replica, etc). It does NOT protect against
// someone who has both DB access and this server's environment variables --
// nothing purely software-based can, since the running server always needs
// the master key to do its job. Access control (which boat's session can
// read which boat_id) is still enforced the same way it always was, in the
// route handlers below -- encryption adds confidentiality at rest, it
// doesn't replace authorization.
const ENC_MASTER_KEY = process.env.APP_DATA_ENCRYPTION_KEY || '';
if(!ENC_MASTER_KEY){
  console.warn('APP_DATA_ENCRYPTION_KEY is not set -- shipment photos and bank details will be stored unencrypted. Set a long random value for this in production.');
}
function deriveFieldKey(scopeId){
  if(!ENC_MASTER_KEY) return null;
  return crypto.hkdfSync('sha256', ENC_MASTER_KEY, scopeId || '', 'seafare-field-enc', 32);
}
// Returns a self-contained string "iv:authTag:ciphertext" (all hex) so
// nothing extra needs to be stored alongside it. Falls back to returning
// the plaintext unchanged if no master key is configured, so the app
// keeps working (unencrypted) rather than breaking outright.
function encryptField(plaintext, scopeId){
  if(plaintext === null || plaintext === undefined || plaintext === '') return plaintext;
  const key = deriveFieldKey(scopeId);
  if(!key) return plaintext;
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const ciphertext = Buffer.concat([cipher.update(String(plaintext), 'utf8'), cipher.final()]);
  const authTag = cipher.getAuthTag();
  return `enc:${iv.toString('hex')}:${authTag.toString('hex')}:${ciphertext.toString('hex')}`;
}
// Recognizes our own "enc:..." format and decrypts it; anything else
// (plaintext from before encryption was turned on, or values written while
// no master key was configured) is returned as-is rather than erroring, so
// old data doesn't become unreadable.
function decryptField(stored, scopeId){
  if(typeof stored !== 'string' || !stored.startsWith('enc:')) return stored;
  const key = deriveFieldKey(scopeId);
  if(!key) return stored;
  const [, ivHex, tagHex, dataHex] = stored.split(':');
  try{
    const decipher = crypto.createDecipheriv('aes-256-gcm', key, Buffer.from(ivHex, 'hex'));
    decipher.setAuthTag(Buffer.from(tagHex, 'hex'));
    const plaintext = Buffer.concat([decipher.update(Buffer.from(dataHex, 'hex')), decipher.final()]);
    return plaintext.toString('utf8');
  }catch(e){
    console.error('decryptField failed', e);
    return null;
  }
}

// PINs (staffUsers[].pin, managerUsers[].pin, legacy staffPin/ownerPin) are
// generated client-side and arrive here as plain 3-6 digit strings. This
// hashes any that aren't already hashed (hashSecret's output always
// contains a ':', which a plain numeric PIN never does) before the
// settings blob is persisted -- so a raw PIN is never written to the
// database, and by extension never sent back out to any client either.
// Idempotent: safe to run on every settings save even if some PINs in the
// object are already hashed from a previous save.
function hashRawPinsInSettings(settings){
  if(!settings || typeof settings !== 'object') return settings;
  const hashIfRaw = (v) => (typeof v === 'string' && v && !v.includes(':')) ? hashSecret(v) : v;
  if(Array.isArray(settings.staffUsers)){
    settings.staffUsers = settings.staffUsers.map(u => u && u.pin ? { ...u, pin: hashIfRaw(u.pin) } : u);
  }
  if(Array.isArray(settings.managerUsers)){
    settings.managerUsers = settings.managerUsers.map(u => u && u.pin ? { ...u, pin: hashIfRaw(u.pin) } : u);
  }
  if(settings.staffPin) settings.staffPin = hashIfRaw(settings.staffPin);
  if(settings.ownerPin) settings.ownerPin = hashIfRaw(settings.ownerPin);
  return settings;
}

// Strips PIN hashes out of a settings object entirely before it's sent to
// any client -- the client only ever needs to know a PIN exists (to e.g.
// show "PIN set" in the staff list), never its hash, since PIN checking
// now happens server-side in /api/staff-login and /api/manager-login below.
// Also decrypts bank account fields (encrypted at rest, but the Owner does
// need to see them to view/edit them in Settings).
function sanitizeSettingsForClient(settings, scopeId){
  if(!settings || typeof settings !== 'object') return settings;
  const out = { ...settings };
  if(Array.isArray(out.staffUsers)) out.staffUsers = out.staffUsers.map(({ pin, ...rest }) => ({ ...rest, hasPin: !!pin }));
  if(Array.isArray(out.managerUsers)) out.managerUsers = out.managerUsers.map(({ pin, ...rest }) => ({ ...rest, hasPin: !!pin }));
  if(out.staffPin) out.staffPin = undefined;
  if(out.ownerPin) out.ownerPin = undefined;
  if(out.bankAccountName) out.bankAccountName = decryptField(out.bankAccountName, scopeId);
  if(out.bankAccountNumber) out.bankAccountNumber = decryptField(out.bankAccountNumber, scopeId);
  return out;
}

async function getAdminSettingsRow(){
  const rows = await sql`SELECT * FROM admin_settings WHERE id = 'admin'`;
  return rows.length ? rows[0] : null;
}
// Ensures the single admin_settings row exists, seeded from the env vars
// the first time anything touches it -- so a fresh install still works with
// nothing but ADMIN_USERNAME/ADMIN_PASSWORD, but the moment the admin
// changes anything in Settings, that row takes over as the source of truth.
async function ensureAdminSettingsRow(){
  const existing = await getAdminSettingsRow();
  if(existing) return existing;
  await sql`
    INSERT INTO admin_settings (id, username, password_hash)
    VALUES ('admin', ${ADMIN_USERNAME || null}, ${ADMIN_PASSWORD ? hashSecret(ADMIN_PASSWORD) : null})
    ON CONFLICT (id) DO NOTHING
  `;
  return await getAdminSettingsRow();
}

async function checkAdmin(req){
  const u = (req.body && req.body.username) || (req.query && req.query.username) || '';
  const p = (req.body && req.body.passkey) || (req.query && req.query.passkey) || '';
  if(!u || !p) return false;
  const row = await getAdminSettingsRow();
  if(row && row.username && row.password_hash){
    return u === row.username && verifySecret(p, row.password_hash);
  }
  // No override saved yet -- fall back to the env vars.
  return !!(ADMIN_USERNAME && ADMIN_PASSWORD && u === ADMIN_USERNAME && p === ADMIN_PASSWORD);
}
async function requireAdmin(req, res, next){
  try{
    const row = await getAdminSettingsRow();
    const hasOverride = !!(row && row.username && row.password_hash);
    if(!hasOverride && !(ADMIN_USERNAME && ADMIN_PASSWORD)){
      return res.status(503).json({ ok:false, error:'Admin login is not configured yet. Set ADMIN_USERNAME and ADMIN_PASSWORD on the server.' });
    }
    if(!(await checkAdmin(req))) return res.status(401).json({ ok:false, error:'Invalid admin credentials.' });
    next();
  }catch(e){
    console.error(e);
    res.status(500).json({ ok:false, error:'Could not verify admin credentials.' });
  }
}

app.post('/api/admin/login', async (req, res) => {
  try{
    const row = await getAdminSettingsRow();
    const hasOverride = !!(row && row.username && row.password_hash);
    if(!hasOverride && !(ADMIN_USERNAME && ADMIN_PASSWORD)){
      return res.status(503).json({ ok:false, error:'Admin login is not configured yet.' });
    }
    if(await checkAdmin(req)) res.json({ ok:true });
    else res.status(401).json({ ok:false, error:'Incorrect username or passkey.' });
  }catch(e){
    console.error(e);
    res.status(500).json({ ok:false, error:'Something went wrong. Try again.' });
  }
});

// --- Super Admin Settings ---------------------------------------------------
// Everything the Super Admin can edit about their own account/setup: login
// credentials, the bank account shown to owners in the Pro upgrade popup,
// and which notification types raise an alert in the admin queue.
app.get('/api/admin/settings', requireAdmin, async (req, res) => {
  try{
    const row = await ensureAdminSettingsRow();
    res.json({ ok:true, settings: {
      username: row.username || ADMIN_USERNAME || '',
      bankAccountName: row.bank_account_name || '',
      bankAccountNumber: row.bank_account_number || '',
      mibAccountName: row.mib_account_name || '',
      mibAccountNumber: row.mib_account_number || '',
      notifyNewSignups: row.notify_new_signups,
      notifyBoatRequests: row.notify_boat_requests,
      notifyNewBoats: row.notify_new_boats,
      notifyProRequests: row.notify_pro_requests,
      notifyProPayments: row.notify_pro_payments,
    }});
  }catch(e){
    console.error(e);
    res.status(500).json({ ok:false, error:'Could not load admin settings.' });
  }
});
app.post('/api/admin/settings/credentials', requireAdmin, async (req, res) => {
  try{
    const { newUsername, newPassword } = req.body || {};
    if(!newUsername || !String(newUsername).trim()) return res.status(400).json({ ok:false, error:'Username is required.' });
    if(!newPassword || String(newPassword).length < 6) return res.status(400).json({ ok:false, error:'New password must be at least 6 characters.' });
    await ensureAdminSettingsRow();
    await sql`
      UPDATE admin_settings SET username = ${String(newUsername).trim()}, password_hash = ${hashSecret(newPassword)}, updated_at = now()
      WHERE id = 'admin'
    `;
    res.json({ ok:true });
  }catch(e){
    console.error(e);
    res.status(500).json({ ok:false, error:'Could not update credentials.' });
  }
});
app.post('/api/admin/settings/bank', requireAdmin, async (req, res) => {
  try{
    const { bankAccountName, bankAccountNumber, mibAccountName, mibAccountNumber } = req.body || {};
    await ensureAdminSettingsRow();
    await sql`
      UPDATE admin_settings SET
        bank_account_name = ${bankAccountName || ''}, bank_account_number = ${bankAccountNumber || ''},
        mib_account_name = ${mibAccountName || ''}, mib_account_number = ${mibAccountNumber || ''},
        updated_at = now()
      WHERE id = 'admin'
    `;
    res.json({ ok:true });
  }catch(e){
    console.error(e);
    res.status(500).json({ ok:false, error:'Could not update bank details.' });
  }
});
// Public (no admin auth) -- every owner's Upgrade to Pro popup needs these
// account details, and owners aren't authenticated as the Super Admin.
// Only ever returns the two account name/number pairs, nothing else off
// the admin_settings row (no credentials, no notification toggles).
app.get('/api/pro-bank-accounts', async (req, res) => {
  try{
    const row = await ensureAdminSettingsRow();
    res.json({ ok:true, accounts: {
      bml: { name: row.bank_account_name || '', number: row.bank_account_number || '' },
      mib: { name: row.mib_account_name || '', number: row.mib_account_number || '' },
    }});
  }catch(e){
    console.error(e);
    res.status(500).json({ ok:false, error:'Could not load payment account details.' });
  }
});
app.post('/api/admin/settings/notifications', requireAdmin, async (req, res) => {
  try{
    const { notifyNewSignups, notifyBoatRequests, notifyNewBoats, notifyProRequests, notifyProPayments } = req.body || {};
    await ensureAdminSettingsRow();
    await sql`
      UPDATE admin_settings SET
        notify_new_signups = ${!!notifyNewSignups},
        notify_boat_requests = ${!!notifyBoatRequests},
        notify_new_boats = ${!!notifyNewBoats},
        notify_pro_requests = ${!!notifyProRequests},
        notify_pro_payments = ${!!notifyProPayments},
        updated_at = now()
      WHERE id = 'admin'
    `;
    res.json({ ok:true });
  }catch(e){
    console.error(e);
    res.status(500).json({ ok:false, error:'Could not update notification preferences.' });
  }
});

// List every organization (owner) with their boats attached, for the
// Super Admin overview screen.
// Runs opportunistically whenever the Super Admin dashboard loads the
// organizations list (there's no background job runner here, so this is
// the closest equivalent to a scheduled check -- it just runs on demand
// instead of on a timer). Anything suspended for more than 15 days,
// whether at the organization level or an individual boat within an
// otherwise-active organization, is permanently deleted: a
// deleted_accounts record is kept first (mobile + names + reason only,
// nothing else), matching exactly what the manual admin delete does.
const SUSPENSION_AUTO_DELETE_MS = 15 * 24 * 60 * 60 * 1000;
async function cleanupExpiredSuspensions(){
  const cutoff = new Date(Date.now() - SUSPENSION_AUTO_DELETE_MS).toISOString();

  const expiredOrgs = await sql`SELECT id, mobile, boat_name, owner_name FROM organizations WHERE status = 'suspended' AND suspended_at IS NOT NULL AND suspended_at < ${cutoff}`;
  for(const org of expiredOrgs){
    const boats = await sql`SELECT id FROM boats WHERE organization_id = ${org.id}`;
    await blockOrgNumbers(org.id, 'auto_deleted_inactive_suspension');
    for(const b of boats){ await blockBoatNumbers(b.id, org.id, 'auto_deleted_inactive_suspension'); }
    for(const b of boats){ await sql`DELETE FROM app_data WHERE boat_id = ${b.id}`; }
    await sql`
      INSERT INTO deleted_accounts (id, mobile, boat_name, owner_name, reason)
      VALUES (${'del-' + Date.now() + '-' + Math.random().toString(36).slice(2,8)}, ${org.mobile}, ${org.boat_name}, ${org.owner_name}, 'auto_deleted_inactive_suspension')
    `;
    await sql`DELETE FROM organizations WHERE id = ${org.id}`;
  }

  // Individual boats suspended on their own (org itself still active) --
  // same 15-day rule, scoped to just that boat.
  const expiredBoats = await sql`
    SELECT b.id, b.name AS boat_name, b.organization_id, o.mobile, o.owner_name
    FROM boats b JOIN organizations o ON o.id = b.organization_id
    WHERE b.status = 'suspended' AND b.suspended_at IS NOT NULL AND b.suspended_at < ${cutoff} AND o.status != 'suspended'
  `;
  for(const boat of expiredBoats){
    await blockBoatNumbers(boat.id, boat.organization_id, 'auto_deleted_inactive_suspension');
    await sql`DELETE FROM app_data WHERE boat_id = ${boat.id}`;
    await sql`
      INSERT INTO deleted_accounts (id, mobile, boat_name, owner_name, reason)
      VALUES (${'del-' + Date.now() + '-' + Math.random().toString(36).slice(2,8)}, ${boat.mobile}, ${boat.boat_name}, ${boat.owner_name}, 'auto_deleted_inactive_suspension')
    `;
    await sql`DELETE FROM boats WHERE id = ${boat.id}`;
  }
}

// Super Admin notification queue -- new signups, new boats, pending
// requests, and re-signups of a previously-deleted mobile number.
app.get('/api/admin/notifications', requireAdmin, async (req, res) => {
  try{
    const rows = await sql`SELECT id, type, message, read, created_at, reference_type, reference_id FROM admin_notifications ORDER BY created_at DESC LIMIT 200`;
    res.json({ ok:true, notifications: rows });
  }catch(e){
    console.error(e);
    res.status(500).json({ ok:false, error:'Could not load notifications.' });
  }
});
app.post('/api/admin/notifications/:id/read', requireAdmin, async (req, res) => {
  try{
    await sql`UPDATE admin_notifications SET read = true WHERE id = ${req.params.id}`;
    res.json({ ok:true });
  }catch(e){ console.error(e); res.status(500).json({ ok:false, error:'Could not update notification.' }); }
});
app.post('/api/admin/notifications/read-all', requireAdmin, async (req, res) => {
  try{
    await sql`UPDATE admin_notifications SET read = true WHERE read = false`;
    res.json({ ok:true });
  }catch(e){ console.error(e); res.status(500).json({ ok:false, error:'Could not update notifications.' }); }
});

app.get('/api/admin/organizations', requireAdmin, async (req, res) => {
  try{
    await cleanupExpiredSuspensions();
    const orgs = await sql`SELECT id, boat_name, owner_name, contact_number, gmail, mobile, status, suspension_note, suspended_at, totp_secret, is_pro, pro_started_at, pro_expires_at, created_at FROM organizations ORDER BY created_at DESC`;
    const boats = await sql`SELECT id, organization_id, name, is_primary, status, suspension_note, suspended_at, created_at FROM boats ORDER BY created_at ASC`;
    // Each boat's own contact number(s) live in its settings
    // (tripDefaults.boatContacts), not the boats table itself -- pull
    // those in too so the admin popup can show every boat's own contact,
    // not just the organization's.
    const boatSettingsRows = boats.length
      ? await sql`SELECT boat_id, value FROM app_data WHERE key = 'settings' AND boat_id = ANY(${boats.map(b => b.id)})`
      : [];
    const contactsByBoatId = Object.fromEntries(
      boatSettingsRows.map(r => [r.boat_id, (r.value && r.value.tripDefaults && r.value.tripDefaults.boatContacts) || ''])
    );
    // Flag any org whose mobile number has a prior deletion on record, so
    // the admin can see at a glance (and open up why) even outside the
    // notification queue -- e.g. if they missed the original notification.
    const priorDeletions = await sql`SELECT DISTINCT ON (mobile) mobile, boat_name, reason, deleted_at FROM deleted_accounts ORDER BY mobile, deleted_at DESC`;
    const deletionsByMobile = Object.fromEntries(priorDeletions.map(d => [d.mobile, d]));
    const withBoats = orgs.map(o => ({
      ...o,
      boats: boats.filter(b => b.organization_id === o.id).map(b => ({ ...b, contact_number: contactsByBoatId[b.id] || '' })),
      priorDeletion: deletionsByMobile[o.mobile] || null,
    }));
    res.json({ ok:true, organizations: withBoats });
  }catch(e){
    console.error(e);
    res.status(500).json({ ok:false, error:'Could not load organizations.' });
  }
});

// Super Admin's "Blocked Users" tab -- every individually-blocked number,
// grouped by the organization's signup name (boat_name) so the admin sees
// one entry per owner with all their numbers (and all their boats' own
// numbers) broken out underneath. Includes lifted numbers too, so this
// doubles as the log the Super Admin asked for -- not just an active
// block list.
app.get('/api/admin/blocked-numbers', requireAdmin, async (req, res) => {
  try{
    const rows = await sql`
      SELECT id, mobile, organization_id, boat_id, boat_name, owner_name, source_label, reason, status, created_at, lifted_at
      FROM blocked_numbers
      WHERE status = 'blocked'
      ORDER BY boat_name ASC, created_at DESC
    `;
    const groups = {};
    const order = [];
    for(const r of rows){
      const key = `${r.boat_name}__${r.owner_name}`;
      if(!groups[key]){
        groups[key] = { boatName: r.boat_name, ownerName: r.owner_name, organizationId: r.organization_id || null, numbers: [] };
        order.push(key);
      }
      if(!groups[key].organizationId && r.organization_id) groups[key].organizationId = r.organization_id;
      groups[key].numbers.push(r);
    }
    const list = order.map(k => groups[k]);
    for(const g of list){
      if(g.organizationId){
        const orgRows = await sql`SELECT status, due_amount, due_currency FROM organizations WHERE id = ${g.organizationId}`;
        if(orgRows.length){
          g.orgStatus = orgRows[0].status;
          g.dueAmount = orgRows[0].due_amount;
          g.dueCurrency = orgRows[0].due_currency;
        } else {
          g.orgStatus = 'deleted';
        }
      } else {
        g.orgStatus = 'deleted';
      }
    }
    res.json({ ok:true, groups: list });
  }catch(e){
    console.error(e);
    res.status(500).json({ ok:false, error:'Could not load blocked users.' });
  }
});

// Manually unblock one specific number. Used for numbers permanently
// blocked by a deletion (deleted_by_admin / auto_deleted_inactive_suspension)
// where there's no org/boat left to unsuspend -- the Super Admin is the
// only way those ever come off the list. Works for a 'suspended'-reason
// row too, as a manual override without unsuspending the whole account.
app.post('/api/admin/blocked-numbers/:id/unblock', requireAdmin, async (req, res) => {
  try{
    await sql`DELETE FROM blocked_numbers WHERE id = ${req.params.id}`;
    res.json({ ok:true });
  }catch(e){
    console.error(e);
    res.status(500).json({ ok:false, error:'Could not unblock this number.' });
  }
});

// Admin grant/revoke Pro for an organization -- every boat, owner,
// manager, and staff under it shares this same status (see the
// GET /api/data/:boatId/settings merge above).
app.post('/api/admin/organizations/:id/pro/grant', requireAdmin, async (req, res) => {
  try{
    await grantProToOrganization(req.params.id);
    // Clear any pending manual bank-transfer request on this org's boats
    // now that Pro has actually been granted -- and drop their transfer
    // slip screenshots, since there's no reason to keep those once
    // approved.
    const boats = await sql`SELECT id FROM boats WHERE organization_id = ${req.params.id}`;
    for(const b of boats){
      const rows = await sql`SELECT value FROM app_data WHERE boat_id = ${b.id} AND key = 'settings'`;
      if(!rows.length) continue;
      const settings = rows[0].value || {};
      if(settings.proRequestPending || settings.proRequestScreenshot){
        settings.proRequestPending = false;
        settings.proRequestScreenshot = null;
        await sql`UPDATE app_data SET value = ${JSON.stringify(settings)}::jsonb, updated_at = now() WHERE boat_id = ${b.id} AND key = 'settings'`;
      }
    }
    const rows = await sql`SELECT is_pro, pro_started_at, pro_expires_at FROM organizations WHERE id = ${req.params.id}`;
    res.json({ ok:true, organization: rows[0] || null });
  }catch(e){
    console.error(e);
    res.status(500).json({ ok:false, error:'Could not grant Pro for this organization.' });
  }
});
app.post('/api/admin/organizations/:id/pro/revoke', requireAdmin, async (req, res) => {
  try{
    await sql`UPDATE organizations SET is_pro = false WHERE id = ${req.params.id}`;
    const rows = await sql`SELECT is_pro, pro_started_at, pro_expires_at FROM organizations WHERE id = ${req.params.id}`;
    res.json({ ok:true, organization: rows[0] || null });
  }catch(e){
    console.error(e);
    res.status(500).json({ ok:false, error:'Could not revoke Pro for this organization.' });
  }
});

// Suspend/unsuspend an organization -- every boat under it becomes
// unusable while suspended (checked at login/data-access time below), but
// nothing is deleted, so access can be restored at any time.
app.post('/api/admin/organizations/:id/suspend', requireAdmin, async (req, res) => {
  try{
    const note = (req.body && req.body.note || '').trim() || null;
    const dueAmountRaw = req.body && req.body.dueAmount;
    const dueAmount = (dueAmountRaw !== undefined && dueAmountRaw !== null && String(dueAmountRaw).trim() !== '') ? Number(dueAmountRaw) : null;
    await sql`UPDATE organizations SET status = 'suspended', suspension_note = ${note}, suspended_at = now(), due_amount = ${dueAmount} WHERE id = ${req.params.id}`;
    await sql`UPDATE boats SET status = 'suspended', suspension_note = ${note}, suspended_at = now() WHERE organization_id = ${req.params.id} AND status != 'suspended'`;
    // Block every number tied to this organization AND each of its boats
    // -- the owner's own mobile/contact number, plus each boat's own Trip
    // Defaults contact number(s) -- so none of them can be used to sign up
    // fresh while this account is suspended.
    await blockOrgNumbers(req.params.id, 'suspended');
    const boats = await sql`SELECT id FROM boats WHERE organization_id = ${req.params.id}`;
    for(const b of boats){ await blockBoatNumbers(b.id, req.params.id, 'suspended'); }
    res.json({ ok:true });
  }catch(e){ console.error(e); res.status(500).json({ ok:false, error:'Could not suspend this organization.' }); }
});
app.post('/api/admin/organizations/:id/unsuspend', requireAdmin, async (req, res) => {
  try{
    await sql`UPDATE organizations SET status = 'active', suspension_note = NULL, suspended_at = NULL, due_amount = NULL WHERE id = ${req.params.id}`;
    await sql`UPDATE boats SET status = 'active', suspension_note = NULL, suspended_at = NULL WHERE organization_id = ${req.params.id} AND status = 'suspended'`;
    await liftOrgNumbers(req.params.id);
    res.json({ ok:true });
  }catch(e){ console.error(e); res.status(500).json({ ok:false, error:'Could not unsuspend this organization.' }); }
});

// Permanently delete an organization and everything under it -- boats,
// boat requests (cascade via FK), and each boat's own app_data (shipments,
// rates, trips, settings), which isn't covered by a cascade so it's
// cleaned up by hand first.
app.delete('/api/admin/organizations/:id', requireAdmin, async (req, res) => {
  try{
    const orgRows = await sql`SELECT mobile, boat_name, owner_name FROM organizations WHERE id = ${req.params.id}`;
    const org = orgRows[0];
    const boats = await sql`SELECT id FROM boats WHERE organization_id = ${req.params.id}`;
    // Permanently block every number tied to this organization and its
    // boats BEFORE the rows are gone (blockOrgNumbers/blockBoatNumbers
    // need the organization/boat to still exist to read their numbers).
    await blockOrgNumbers(req.params.id, 'deleted_by_admin');
    for(const b of boats){ await blockBoatNumbers(b.id, req.params.id, 'deleted_by_admin'); }
    for(const b of boats){
      await sql`DELETE FROM app_data WHERE boat_id = ${b.id}`;
    }
    if(org){
      await sql`
        INSERT INTO deleted_accounts (id, mobile, boat_name, owner_name, reason)
        VALUES (${'del-' + Date.now() + '-' + Math.random().toString(36).slice(2,8)}, ${org.mobile}, ${org.boat_name}, ${org.owner_name}, 'deleted_by_admin')
      `;
    }
    await sql`DELETE FROM organizations WHERE id = ${req.params.id}`;
    res.json({ ok:true });
  }catch(e){ console.error(e); res.status(500).json({ ok:false, error:'Could not delete this organization.' }); }
});

// Suspend/unsuspend a single boat (doesn't affect sibling boats under the
// same organization).
app.post('/api/admin/boats/:id/suspend', requireAdmin, async (req, res) => {
  try{
    const note = (req.body && req.body.note || '').trim() || null;
    const boatRows = await sql`SELECT organization_id FROM boats WHERE id = ${req.params.id}`;
    await sql`UPDATE boats SET status = 'suspended', suspension_note = ${note}, suspended_at = now() WHERE id = ${req.params.id}`;
    if(boatRows.length) await blockBoatNumbers(req.params.id, boatRows[0].organization_id, 'suspended');
    res.json({ ok:true });
  }catch(e){ console.error(e); res.status(500).json({ ok:false, error:'Could not suspend this boat.' }); }
});
app.post('/api/admin/boats/:id/unsuspend', requireAdmin, async (req, res) => {
  try{
    await sql`UPDATE boats SET status = 'active', suspension_note = NULL, suspended_at = NULL WHERE id = ${req.params.id}`;
    await liftBoatNumbers(req.params.id);
    res.json({ ok:true });
  }catch(e){ console.error(e); res.status(500).json({ ok:false, error:'Could not unsuspend this boat.' }); }
});

// Permanently delete a single boat and its own app_data.
app.delete('/api/admin/boats/:id', requireAdmin, async (req, res) => {
  try{
    const boatRows = await sql`
      SELECT b.name AS boat_name, b.organization_id, o.mobile, o.owner_name
      FROM boats b JOIN organizations o ON o.id = b.organization_id
      WHERE b.id = ${req.params.id}
    `;
    const boat = boatRows[0];
    if(boat) await blockBoatNumbers(req.params.id, boat.organization_id, 'deleted_by_admin');
    await sql`DELETE FROM app_data WHERE boat_id = ${req.params.id}`;
    if(boat){
      await sql`
        INSERT INTO deleted_accounts (id, mobile, boat_name, owner_name, reason)
        VALUES (${'del-' + Date.now() + '-' + Math.random().toString(36).slice(2,8)}, ${boat.mobile}, ${boat.boat_name}, ${boat.owner_name}, 'deleted_by_admin')
      `;
    }
    await sql`DELETE FROM boats WHERE id = ${req.params.id}`;
    res.json({ ok:true });
  }catch(e){ console.error(e); res.status(500).json({ ok:false, error:'Could not delete this boat.' }); }
});

// List boat requests (pending additional-boat approvals), newest first.
app.get('/api/admin/boat-requests', requireAdmin, async (req, res) => {
  try{
    const rows = await sql`
      SELECT br.id, br.organization_id, br.requested_boat_name, br.payment_screenshot,
             br.status, br.admin_note, br.created_at, br.reviewed_at,
             o.boat_name AS org_boat_name, o.owner_name
      FROM boat_requests br
      JOIN organizations o ON o.id = br.organization_id
      ORDER BY br.created_at DESC
    `;
    res.json({ ok:true, requests: rows });
  }catch(e){
    console.error(e);
    res.status(500).json({ ok:false, error:'Could not load boat requests.' });
  }
});

// Every pending manual bank-transfer Pro request across all organizations,
// for the admin's Pro Requests tab -- the request itself is still
// submitted per boat (see submitProRequest in index.html), but shown here
// with its organization's context so the admin can grant Pro (which is
// org-wide) directly from this list.
app.get('/api/admin/pro-requests', requireAdmin, async (req, res) => {
  try{
    const rows = await sql`
      SELECT ad.boat_id, ad.value, b.name AS boat_name, b.organization_id,
             o.boat_name AS org_boat_name, o.owner_name
      FROM app_data ad
      JOIN boats b ON b.id = ad.boat_id
      JOIN organizations o ON o.id = b.organization_id
      WHERE ad.key = 'settings' AND ad.value->>'proRequestPending' = 'true'
      ORDER BY (ad.value->>'proRequestedAt') DESC NULLS LAST
    `;
    const requests = rows.map(r => ({
      boatId: r.boat_id,
      boatName: r.boat_name,
      organizationId: r.organization_id,
      orgBoatName: r.org_boat_name,
      ownerName: r.owner_name,
      requestedAt: r.value.proRequestedAt || null,
      screenshot: r.value.proRequestScreenshot || null,
    }));
    res.json({ ok:true, requests });
  }catch(e){
    console.error(e);
    res.status(500).json({ ok:false, error:'Could not load Pro requests.' });
  }
});

// Every completed payment (Swipe or RedotPay crypto) that auto-granted Pro
// (no admin approval involved) -- for the admin's "Paid via Swipe/RedotPay"
// tab, so there's still visibility into these even though nothing required
// action. `provider` lets the admin UI label each row by which gateway it
// actually came through.
app.get('/api/admin/pro-payments', requireAdmin, async (req, res) => {
  try{
    const rows = await sql`
      SELECT pp.id, pp.boat_id, pp.amount, pp.currency, pp.completed_at, pp.provider,
             b.name AS boat_name, b.organization_id, o.boat_name AS org_boat_name, o.owner_name
      FROM pro_payments pp
      JOIN boats b ON b.id = pp.boat_id
      JOIN organizations o ON o.id = b.organization_id
      WHERE pp.status = 'COMPLETED'
      ORDER BY pp.completed_at DESC
    `;
    res.json({ ok:true, payments: rows });
  }catch(e){
    console.error(e);
    res.status(500).json({ ok:false, error:'Could not load card/Swipe payments.' });
  }
});

// Pro plan cap: up to 15 boats per organization -- only applied to
// organizations created after the Free/Pro plan-limits feature shipped
// (plan_limits_enabled); every organization that existed before that is
// grandfathered in as unlimited, matching how nothing else about this
// feature retroactively restricts existing accounts. Free-tier orgs never
// need this check here -- they can't reach this function at all without a
// Super Admin manually approving their (paid, reviewed) request in the
// first place, which is its own natural gate.
async function boatCapReached(organizationId){
  const orgRows = await sql`SELECT plan_limits_enabled, is_pro FROM organizations WHERE id = ${organizationId}`;
  const org = orgRows[0];
  if(!org || !org.plan_limits_enabled || !org.is_pro) return false;
  const countRows = await sql`SELECT COUNT(*)::int AS n FROM boats WHERE organization_id = ${organizationId}`;
  return (countRows[0]?.n || 0) >= 15;
}

// Approve a pending boat request: creates the new boat row and marks the
// request approved. This is the step you take after confirming the
// transfer landed in your account.
// Shared by the manual admin-approval path below and the automatic Pro
// grant path in POST /api/boat-requests -- both end with an identical new
// boat row, pre-filled the same way from the org's own info.
async function createBoatForOrganization(organizationId, boatName){
  const boatId = crypto.randomBytes(8).toString('hex');
  await sql`
    INSERT INTO boats (id, organization_id, name, is_primary, status)
    VALUES (${boatId}, ${organizationId}, ${boatName}, false, 'active')
  `;

  // Pre-fill this new boat's Payment Details and Trip Defaults contact
  // number from the org's own info (set at signup) -- editable separately
  // per boat from here on.
  const orgRows = await sql`SELECT contact_number, bank_account_name, bank_account_number FROM organizations WHERE id = ${organizationId}`;
  const org = orgRows[0];
  if(org && (org.bank_account_name || org.bank_account_number || org.contact_number)){
    const initialSettings = {
      bankAccountName: encryptField(decryptField(org.bank_account_name, organizationId) || '', boatId),
      bankAccountNumber: encryptField(decryptField(org.bank_account_number, organizationId) || '', boatId),
      tripDefaults: { boatContacts: org.contact_number || '', trackingLink: '', viberLink: '' },
    };
    await sql`
      INSERT INTO app_data (boat_id, key, value, updated_at)
      VALUES (${boatId}, 'settings', ${JSON.stringify(initialSettings)}::jsonb, now())
      ON CONFLICT (boat_id, key) DO UPDATE SET value = ${JSON.stringify(initialSettings)}::jsonb, updated_at = now()
    `;
  }
  return boatId;
}

app.post('/api/admin/boat-requests/:id/approve', requireAdmin, async (req, res) => {
  try{
    const rows = await sql`SELECT * FROM boat_requests WHERE id = ${req.params.id}`;
    const request = rows[0];
    if(!request) return res.status(404).json({ ok:false, error:'Request not found.' });
    if(request.status !== 'pending') return res.status(400).json({ ok:false, error:'This request was already reviewed.' });
    if(await boatCapReached(request.organization_id)){
      return res.status(400).json({ ok:false, error:'This organization has reached its 15-boat Pro plan limit.' });
    }

    const boatId = await createBoatForOrganization(request.organization_id, request.requested_boat_name);

    // The screenshot is returned once in this response (so the admin can
    // download it), then permanently cleared from the database -- it's
    // sensitive banking info and shouldn't be retained after approval.
    await sql`UPDATE boat_requests SET status = 'approved', reviewed_at = now(), payment_screenshot = NULL WHERE id = ${req.params.id}`;
    res.json({ ok:true, boatId, paymentScreenshot: request.payment_screenshot || null, requestedBoatName: request.requested_boat_name });
  }catch(e){
    console.error(e);
    res.status(500).json({ ok:false, error:'Could not approve this request.' });
  }
});

app.post('/api/admin/boat-requests/:id/reject', requireAdmin, async (req, res) => {
  try{
    const note = (req.body && req.body.note) || '';
    await sql`UPDATE boat_requests SET status = 'rejected', admin_note = ${note}, reviewed_at = now() WHERE id = ${req.params.id}`;
    res.json({ ok:true });
  }catch(e){
    console.error(e);
    res.status(500).json({ ok:false, error:'Could not reject this request.' });
  }
});

// Test-only helper for this phase: lets you (or me, during testing) create
// a boat request without the owner-facing request UI existing yet -- that
// UI is later-phase work. Remove or restrict this once real owner signups
// exist.
app.post('/api/admin/boat-requests/seed', requireAdmin, async (req, res) => {
  try{
    const { organizationId, requestedBoatName, paymentScreenshot } = req.body || {};
    if(!organizationId || !requestedBoatName) return res.status(400).json({ ok:false, error:'organizationId and requestedBoatName are required.' });
    const id = crypto.randomBytes(8).toString('hex');
    await sql`
      INSERT INTO boat_requests (id, organization_id, requested_boat_name, payment_screenshot)
      VALUES (${id}, ${organizationId}, ${requestedBoatName}, ${paymentScreenshot || null})
    `;
    res.json({ ok:true, id });
  }catch(e){
    console.error(e);
    res.status(500).json({ ok:false, error:'Could not create request.' });
  }
});

// --- Owner signup / org login (Phase 2 of the multi-tenant rebuild) --------
// Passkeys are hashed with scrypt (Node's built-in crypto, no extra
// dependency) -- never stored or compared as plain text.
function hashPasskey(passkey){
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.scryptSync(String(passkey), salt, 64).toString('hex');
  return `${salt}:${hash}`;
}
function verifyPasskey(passkey, stored){
  if(!stored || !stored.includes(':')) return false;
  const [salt, hash] = stored.split(':');
  const check = crypto.scryptSync(String(passkey), salt, 64).toString('hex');
  try{ return crypto.timingSafeEqual(Buffer.from(hash,'hex'), Buffer.from(check,'hex')); }
  catch(e){ return false; }
}

// --- Blocked Users / mobile-number blocking ---------------------------------
// See neon-schema.sql for the full rationale. Short version: every
// individual number tied to an organization or one of its boats gets
// tracked separately (even when several are jammed into one free-text
// field like "7777777 / 9999999"), and blocked from future signups once
// that organization/boat is suspended or deleted.

// Splits on ANY run of non-digit characters -- "/", "-", ",", spaces,
// "and", newlines, anything -- so "7777777 / 9876543-7890567" and
// "7777777, 9876543 or 7890567" both come out as three separate numbers.
// Keeps only plausible phone-number-length digit runs (7-15 digits) so
// stray punctuation-only fragments don't turn into junk "numbers".
function parseNumbers(raw){
  if(!raw) return [];
  return Array.from(new Set(
    String(raw).split(/\D+/).filter(s => s.length >= 7 && s.length <= 15)
  ));
}

// Every individual number currently tied to an organization: its own
// "mobile" (owner's personal number) and "contact_number" (boat contact,
// possibly several jammed together), plus each of its boats' own contact
// number(s) as saved in that boat's Trip Defaults settings.
async function collectOrgNumberSources(organizationId){
  const orgRows = await sql`SELECT mobile, contact_number, boat_name FROM organizations WHERE id = ${organizationId}`;
  if(!orgRows.length) return [];
  const org = orgRows[0];
  const sources = [];
  parseNumbers(org.mobile).forEach(m => sources.push({ mobile: m, sourceLabel: 'Owner Mobile' }));
  parseNumbers(org.contact_number).forEach(m => sources.push({ mobile: m, sourceLabel: `Boat Contact (${org.boat_name})` }));
  const seen = new Set(); const out = [];
  for(const s of sources){ if(!seen.has(s.mobile)){ seen.add(s.mobile); out.push(s); } }
  return out;
}
// Same idea, scoped to one boat's own Trip Defaults contact number(s) only
// -- used when a single boat (not the whole organization) is suspended or
// deleted.
async function collectBoatNumberSources(boatId){
  const boatRows = await sql`
    SELECT b.name, b.organization_id, o.boat_name AS org_boat_name, o.owner_name
    FROM boats b JOIN organizations o ON o.id = b.organization_id
    WHERE b.id = ${boatId}
  `;
  if(!boatRows.length) return null;
  const boat = boatRows[0];
  const rows = await sql`SELECT value FROM app_data WHERE boat_id = ${boatId} AND key = 'settings'`;
  const contacts = rows.length ? (rows[0].value && rows[0].value.tripDefaults && rows[0].value.tripDefaults.boatContacts) : '';
  const numbers = parseNumbers(contacts).map(m => ({ mobile: m, sourceLabel: `Boat Contact (${boat.name})` }));
  return { organizationId: boat.organization_id, orgBoatName: boat.org_boat_name, ownerName: boat.owner_name, numbers };
}

async function blockOrgNumbers(organizationId, reason){
  const orgRows = await sql`SELECT boat_name, owner_name FROM organizations WHERE id = ${organizationId}`;
  if(!orgRows.length) return;
  const org = orgRows[0];
  const sources = await collectOrgNumberSources(organizationId);
  for(const s of sources){
    await sql`
      INSERT INTO blocked_numbers (id, mobile, organization_id, boat_id, boat_name, owner_name, source_label, reason, status)
      VALUES (${'blk-' + Date.now() + '-' + Math.random().toString(36).slice(2,8)}, ${s.mobile}, ${organizationId}, NULL, ${org.boat_name}, ${org.owner_name}, ${s.sourceLabel}, ${reason}, 'blocked')
      ON CONFLICT (mobile, organization_id, reason) WHERE status = 'blocked' DO NOTHING
    `;
  }
}
async function blockBoatNumbers(boatId, organizationId, reason){
  const info = await collectBoatNumberSources(boatId);
  if(!info) return;
  for(const s of info.numbers){
    await sql`
      INSERT INTO blocked_numbers (id, mobile, organization_id, boat_id, boat_name, owner_name, source_label, reason, status)
      VALUES (${'blk-' + Date.now() + '-' + Math.random().toString(36).slice(2,8)}, ${s.mobile}, ${organizationId || info.organizationId || null}, ${boatId}, ${info.orgBoatName}, ${info.ownerName}, ${s.sourceLabel}, ${reason}, 'blocked')
      ON CONFLICT (mobile, organization_id, reason) WHERE status = 'blocked' DO NOTHING
    `;
  }
}
// Unsuspending removes the block entirely -- the number goes straight
// back to being usable, and drops off the Blocked Users tab (rather than
// lingering there marked "lifted"). Scoped to reason='suspended' only, so
// a permanent block from an actual deletion is never touched by this.
async function liftOrgNumbers(organizationId){
  await sql`DELETE FROM blocked_numbers WHERE organization_id = ${organizationId} AND reason = 'suspended' AND status = 'blocked'`;
}
async function liftBoatNumbers(boatId){
  await sql`DELETE FROM blocked_numbers WHERE boat_id = ${boatId} AND reason = 'suspended' AND status = 'blocked'`;
}

// Scans every still-existing organization and boat (regardless of
// suspended/active status -- suspended accounts still "own" their numbers
// until deleted) for a number overlapping the ones just entered at
// signup. This is the plain "you can't reuse a number that's already
// registered somewhere" rule, separate from the blocked-numbers table
// (which covers suspended/deleted accounts specifically, with its own
// pay-to-resolve popup).
async function findActiveNumberConflict(numbers){
  if(!numbers.length) return null;
  const orgs = await sql`SELECT id, boat_name, owner_name, mobile, contact_number FROM organizations`;
  for(const org of orgs){
    const orgNums = parseNumbers(org.mobile).concat(parseNumbers(org.contact_number));
    if(orgNums.some(n => numbers.includes(n))) return { boatName: org.boat_name, ownerName: org.owner_name };
  }
  const boats = await sql`SELECT id, name, organization_id FROM boats`;
  const orgById = Object.fromEntries(orgs.map(o => [o.id, o]));
  for(const boat of boats){
    const rows = await sql`SELECT value FROM app_data WHERE boat_id = ${boat.id} AND key = 'settings'`;
    const contacts = rows.length ? (rows[0].value && rows[0].value.tripDefaults && rows[0].value.tripDefaults.boatContacts) : '';
    const boatNums = parseNumbers(contacts);
    if(boatNums.some(n => numbers.includes(n))){
      const org = orgById[boat.organization_id];
      return { boatName: org ? org.boat_name : boat.name, ownerName: org ? org.owner_name : '' };
    }
  }
  return null;
}

// After a due-clearance payment (see /api/blocked-numbers/*) completes,
// the owner chooses to either resume their old (now-paid-up) account, or
// walk away from it and sign up fresh. Either way every number tied to
// that organization is removed from the block list entirely -- it was
// just paid off, so there's nothing left to keep it blocked for.
async function resolveDuePayment(record, choice){
  const orgId = record.organization_id;
  if(!orgId) throw new Error('Payment has no organization to resolve.');
  await sql`DELETE FROM blocked_numbers WHERE organization_id = ${orgId} AND status = 'blocked'`;
  if(choice === 'existing'){
    await sql`UPDATE organizations SET status = 'active', suspension_note = NULL, suspended_at = NULL, due_amount = NULL WHERE id = ${orgId}`;
    await sql`UPDATE boats SET status = 'active', suspension_note = NULL, suspended_at = NULL WHERE organization_id = ${orgId} AND status = 'suspended'`;
  } else {
    const boats = await sql`SELECT id FROM boats WHERE organization_id = ${orgId}`;
    for(const b of boats){ await sql`DELETE FROM app_data WHERE boat_id = ${b.id}`; }
    await sql`DELETE FROM organizations WHERE id = ${orgId}`; // boats cascade via FK
  }
}

// Shared by the signup-verification endpoints below AND by POST /api/signup
// itself (defense in depth, in case someone calls /api/signup directly
// without going through send-code/verify-code first): is this one mobile
// number blocked, or already actively used by another organization/boat?
// Returns null when it's free to use.
async function checkMobileAvailability(mobile){
  const numbers = parseNumbers(mobile);
  if(!numbers.length) return { ok:false, error:'Enter a valid mobile number.' };
  const blockedRows = await sql`
    SELECT * FROM blocked_numbers
    WHERE status = 'blocked' AND mobile = ANY(${numbers}::text[])
    ORDER BY created_at DESC LIMIT 1
  `;
  if(blockedRows.length){
    const rec = blockedRows[0];
    let organizationId = null, dueAmount = 0, dueCurrency = 'MVR';
    if(rec.organization_id){
      const orgRows = await sql`SELECT id, due_amount, due_currency FROM organizations WHERE id = ${rec.organization_id}`;
      if(orgRows.length){
        organizationId = rec.organization_id;
        dueAmount = Number(orgRows[0].due_amount) || 0;
        dueCurrency = orgRows[0].due_currency || 'MVR';
      }
    }
    return {
      ok:false, blocked:true, mobile: rec.mobile,
      boatName: rec.boat_name, ownerName: rec.owner_name, reason: rec.reason,
      organizationId, dueAmount, dueCurrency,
    };
  }
  const conflict = await findActiveNumberConflict(numbers);
  if(conflict){
    return { ok:false, error: 'This mobile number is already in use. Please use another mobile number.' };
  }
  return null;
}

// --- Signup mobile verification (SMS OTP via Twilio) ------------------------
// Verifies the owner actually controls the mobile number they're signing up
// with, before an organization is created. Reuses the same
// TWILIO_ACCOUNT_SID/TWILIO_AUTH_TOKEN/TWILIO_PHONE_NUMBER already
// configured for PIN-reset texts (see near the top of this file) -- no
// extra setup needed. WhatsApp delivery isn't available here since it
// needs a separately-approved WhatsApp Business sender and message
// template; SMS works immediately with what's already configured.
const SIGNUP_OTP_TTL_MS = 10 * 60 * 1000;      // code valid for 10 minutes
const SIGNUP_OTP_RESEND_COOLDOWN_MS = 45 * 1000; // 45s between sends to the same number
const SIGNUP_OTP_MAX_ATTEMPTS = 5;

app.post('/api/signup/send-code', async (req, res) => {
  try{
    const mobile = (req.body && req.body.mobile || '').trim();
    if(!mobile) return res.status(400).json({ ok:false, error:'Enter a mobile number.' });
    if(!smsClient || !TWILIO_PHONE_NUMBER){
      return res.status(503).json({ ok:false, error:'SMS verification is not configured on this server yet.' });
    }

    const availability = await checkMobileAvailability(mobile);
    if(availability) return res.status(409).json(availability);

    const digitsOnly = parseNumbers(mobile)[0]; // the single number this OTP is scoped to
    const existing = await sql`SELECT last_sent_at FROM signup_otps WHERE mobile = ${digitsOnly}`;
    if(existing.length){
      const elapsedMs = Date.now() - new Date(existing[0].last_sent_at).getTime();
      if(elapsedMs < SIGNUP_OTP_RESEND_COOLDOWN_MS){
        const waitSeconds = Math.ceil((SIGNUP_OTP_RESEND_COOLDOWN_MS - elapsedMs) / 1000);
        return res.status(429).json({ ok:false, error:`Please wait ${waitSeconds}s before requesting another code.` });
      }
    }

    const code = String(crypto.randomInt(0, 1000000)).padStart(6, '0');
    const codeHash = hashPasskey(code); // reuses the same scrypt hashing as PINs/passkeys
    const expiresAt = new Date(Date.now() + SIGNUP_OTP_TTL_MS).toISOString();

    await sql`
      INSERT INTO signup_otps (mobile, code_hash, attempts, verified, last_sent_at, expires_at)
      VALUES (${digitsOnly}, ${codeHash}, 0, false, now(), ${expiresAt})
      ON CONFLICT (mobile) DO UPDATE SET code_hash = ${codeHash}, attempts = 0, verified = false, last_sent_at = now(), expires_at = ${expiresAt}
    `;

    await smsClient.messages.create({
      to: `+960${digitsOnly}`, // Maldivian numbers -- matches isValidMaldivesMobile on the front-end
      from: TWILIO_PHONE_NUMBER,
      body: `Your SeaFare verification code is ${code}. It expires in 10 minutes.`,
    });

    res.json({ ok:true, expiresInSeconds: SIGNUP_OTP_TTL_MS / 1000 });
  }catch(e){
    console.error('send-code failed', e);
    res.status(502).json({ ok:false, error:'Could not send a verification code right now. Try again in a moment.' });
  }
});

app.post('/api/signup/verify-code', async (req, res) => {
  try{
    const mobile = (req.body && req.body.mobile || '').trim();
    const code = (req.body && req.body.code || '').trim();
    if(!mobile || !code) return res.status(400).json({ ok:false, error:'Enter the code sent to your mobile number.' });
    const digitsOnly = parseNumbers(mobile)[0];
    const rows = await sql`SELECT * FROM signup_otps WHERE mobile = ${digitsOnly}`;
    if(!rows.length) return res.status(400).json({ ok:false, error:'Request a verification code first.' });
    const record = rows[0];
    if(new Date(record.expires_at).getTime() < Date.now()){
      return res.status(400).json({ ok:false, error:'This code has expired. Request a new one.' });
    }
    if(record.attempts >= SIGNUP_OTP_MAX_ATTEMPTS){
      return res.status(400).json({ ok:false, error:'Too many incorrect attempts. Request a new code.' });
    }
    if(!verifyPasskey(code, record.code_hash)){
      await sql`UPDATE signup_otps SET attempts = attempts + 1 WHERE mobile = ${digitsOnly}`;
      const remaining = SIGNUP_OTP_MAX_ATTEMPTS - (record.attempts + 1);
      return res.status(400).json({ ok:false, error: remaining > 0 ? `Incorrect code. ${remaining} attempt(s) left.` : 'Incorrect code. Request a new one.' });
    }
    await sql`UPDATE signup_otps SET verified = true WHERE mobile = ${digitsOnly}`;
    res.json({ ok:true, verified:true });
  }catch(e){
    console.error('verify-code failed', e);
    res.status(500).json({ ok:false, error:'Could not verify that code. Try again.' });
  }
});

// --- Signup email verification (email OTP via Gmail SMTP) -------------------
// Same idea as the SMS flow above, but sent via the existing Gmail SMTP
// transport (`mailer`, configured near the top of this file for PIN-reset
// emails) rather than Twilio -- chosen because it's free (Gmail's own
// sending limits are generous for this volume) and needs no separate
// approval process, unlike SMS or WhatsApp. This is now what POST
// /api/signup actually requires; the mobile SMS OTP endpoints above are
// left in place but unused by the front-end for now.
app.post('/api/signup/send-email-code', async (req, res) => {
  try{
    const email = (req.body && req.body.email || '').trim().toLowerCase();
    if(!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)){
      return res.status(400).json({ ok:false, error:'Enter a valid email address.' });
    }
    if(!mailer){
      return res.status(503).json({ ok:false, error:'Email verification is not configured on this server yet.' });
    }

    const existing = await sql`SELECT last_sent_at FROM signup_email_otps WHERE email = ${email}`;
    if(existing.length){
      const elapsedMs = Date.now() - new Date(existing[0].last_sent_at).getTime();
      if(elapsedMs < SIGNUP_OTP_RESEND_COOLDOWN_MS){
        const waitSeconds = Math.ceil((SIGNUP_OTP_RESEND_COOLDOWN_MS - elapsedMs) / 1000);
        return res.status(429).json({ ok:false, error:`Please wait ${waitSeconds}s before requesting another code.` });
      }
    }

    const code = String(crypto.randomInt(0, 1000000)).padStart(6, '0');
    const codeHash = hashPasskey(code);
    const expiresAt = new Date(Date.now() + SIGNUP_OTP_TTL_MS).toISOString();

    await sql`
      INSERT INTO signup_email_otps (email, code_hash, attempts, verified, last_sent_at, expires_at)
      VALUES (${email}, ${codeHash}, 0, false, now(), ${expiresAt})
      ON CONFLICT (email) DO UPDATE SET code_hash = ${codeHash}, attempts = 0, verified = false, last_sent_at = now(), expires_at = ${expiresAt}
    `;

    await mailer.sendMail({
      from: GMAIL_USER,
      to: email,
      subject: 'Your SeaFare verification code',
      text: `Your SeaFare verification code is ${code}. It expires in 10 minutes.`,
      html: `<p>Your SeaFare verification code is <strong>${code}</strong>.</p><p>It expires in 10 minutes.</p>`,
    });

    res.json({ ok:true, expiresInSeconds: SIGNUP_OTP_TTL_MS / 1000 });
  }catch(e){
    console.error('send-email-code failed', e);
    res.status(502).json({ ok:false, error:'Could not send a verification code right now. Try again in a moment.' });
  }
});

app.post('/api/signup/verify-email-code', async (req, res) => {
  try{
    const email = (req.body && req.body.email || '').trim().toLowerCase();
    const code = (req.body && req.body.code || '').trim();
    if(!email || !code) return res.status(400).json({ ok:false, error:'Enter the code sent to your email.' });
    const rows = await sql`SELECT * FROM signup_email_otps WHERE email = ${email}`;
    if(!rows.length) return res.status(400).json({ ok:false, error:'Request a verification code first.' });
    const record = rows[0];
    if(new Date(record.expires_at).getTime() < Date.now()){
      return res.status(400).json({ ok:false, error:'This code has expired. Request a new one.' });
    }
    if(record.attempts >= SIGNUP_OTP_MAX_ATTEMPTS){
      return res.status(400).json({ ok:false, error:'Too many incorrect attempts. Request a new code.' });
    }
    if(!verifyPasskey(code, record.code_hash)){
      await sql`UPDATE signup_email_otps SET attempts = attempts + 1 WHERE email = ${email}`;
      const remaining = SIGNUP_OTP_MAX_ATTEMPTS - (record.attempts + 1);
      return res.status(400).json({ ok:false, error: remaining > 0 ? `Incorrect code. ${remaining} attempt(s) left.` : 'Incorrect code. Request a new one.' });
    }
    await sql`UPDATE signup_email_otps SET verified = true WHERE email = ${email}`;
    res.json({ ok:true, verified:true });
  }catch(e){
    console.error('verify-email-code failed', e);
    res.status(500).json({ ok:false, error:'Could not verify that code. Try again.' });
  }
});

// Create a new owner + their one free boat. Returns the TOTP secret once,
// in the response, so the front-end can show it to the owner for adding to
// an authenticator app -- it is never returned again after this call.
// Small helper for the Super Admin notification queue -- used from
// signup, boat requests, and boat-request approval below.
//
// --- Web Push (real notifications reaching the Super Admin even with the
// tab closed) --------------------------------------------------------------
// VAPID_PUBLIC_KEY / VAPID_PRIVATE_KEY are the keypair generated for this
// project -- the public half is already embedded in index.html
// (ADMIN_PUSH_VAPID_PUBLIC_KEY); the private half must only ever live here,
// as a server env var, never shipped to the browser. VAPID_SUBJECT is a
// contact URL or mailto: some push services require in the request.
const VAPID_PUBLIC_KEY = process.env.VAPID_PUBLIC_KEY;
const VAPID_PRIVATE_KEY = process.env.VAPID_PRIVATE_KEY;
const VAPID_SUBJECT = process.env.VAPID_SUBJECT || 'mailto:admin@example.com';
const webPushConfigured = !!(VAPID_PUBLIC_KEY && VAPID_PRIVATE_KEY);
if(webPushConfigured){
  webpush.setVapidDetails(VAPID_SUBJECT, VAPID_PUBLIC_KEY, VAPID_PRIVATE_KEY);
}

app.post('/api/admin/push-subscribe', async (req, res) => {
  try{
    if(!(await checkAdmin(req))) return res.status(401).json({ ok:false, error:'Invalid admin credentials.' });
    const { subscription } = req.body || {};
    if(!subscription || !subscription.endpoint) return res.status(400).json({ ok:false, error:'subscription is required.' });
    await sql`
      INSERT INTO admin_push_subscriptions (endpoint, subscription)
      VALUES (${subscription.endpoint}, ${JSON.stringify(subscription)}::jsonb)
      ON CONFLICT (endpoint) DO UPDATE SET subscription = ${JSON.stringify(subscription)}::jsonb
    `;
    res.json({ ok:true });
  }catch(e){
    console.error('push-subscribe failed', e);
    res.status(500).json({ ok:false, error:'Could not save that subscription.' });
  }
});

// Sends a real push to every device the Super Admin has enabled
// notifications on. A subscription that comes back expired/gone (410 or
// 404 -- the browser unsubscribed, cleared storage, etc.) is removed so it
// stops being retried forever; any other failure for one device just gets
// logged, not thrown, so it never blocks the others or the caller.
async function sendAdminPush(type, message){
  if(!webPushConfigured) return;
  try{
    const subs = await sql`SELECT endpoint, subscription FROM admin_push_subscriptions`;
    const typeLabels = { new_signup: 'New Signup', new_boat: 'New Boat', pending_request: 'Pending Request', resignup_after_deletion: 'Re-signup After Deletion', pro_request: 'Pro Upgrade Requested', pro_paid_via_swipe: 'Paid via Swipe', pro_paid_via_redotpay: 'Paid via Crypto (RedotPay)' };
    const payload = JSON.stringify({ title: `SeaFare Super Admin \u2014 ${typeLabels[type] || type}`, body: message });
    await Promise.all(subs.map(async (s) => {
      try{
        await webpush.sendNotification(s.subscription, payload);
      }catch(e){
        if(e.statusCode === 410 || e.statusCode === 404){
          await sql`DELETE FROM admin_push_subscriptions WHERE endpoint = ${s.endpoint}`;
        } else {
          console.error('sendAdminPush failed for one subscription', e.statusCode || e);
        }
      }
    }));
  }catch(e){ console.error('sendAdminPush failed', e); }
}

const NOTIFY_TYPE_TO_SETTING = {
  new_signup: 'notify_new_signups',
  resignup_after_deletion: 'notify_new_signups',
  pending_request: 'notify_boat_requests',
  new_boat: 'notify_new_boats',
  pro_request: 'notify_pro_requests',
  pro_paid_via_swipe: 'notify_pro_payments',
  pro_paid_via_redotpay: 'notify_pro_payments',
};
async function notifyAdmin(type, message, ref){
  try{
    const settingCol = NOTIFY_TYPE_TO_SETTING[type];
    if(settingCol){
      const row = await ensureAdminSettingsRow();
      if(row[settingCol] === false) return; // this notification type is turned off
    }
    await sql`
      INSERT INTO admin_notifications (id, type, message, reference_type, reference_id)
      VALUES (${'note-' + Date.now() + '-' + Math.random().toString(36).slice(2,8)}, ${type}, ${message}, ${(ref && ref.type) || null}, ${(ref && ref.id) || null})
    `;
  }catch(e){ console.error('notifyAdmin failed', e); return; }
  await sendAdminPush(type, message);
}

app.post('/api/signup', async (req, res) => {
  try{
    const b = req.body || {};
    const required = ['boatName','ownerName','mobile','passkey'];
    for(const f of required){
      if(!b[f] || !String(b[f]).trim()) return res.status(400).json({ ok:false, error:`Missing ${f}.` });
    }
    if(String(b.passkey).length < 6) return res.status(400).json({ ok:false, error:'PIN must be at least 6 characters.' });

    // No verification step required for mobile or email right now --
    // both are collected as plain fields (email is optional, under
    // Additional Setup Information). The send-code/verify-code endpoints
    // for each (SMS and email OTP) are still in place above if this is
    // turned back on later.
    const emailLower = String(b.gmail || '').trim().toLowerCase();
    const mobileDigits = parseNumbers(b.mobile)[0];

    // The first boat's name doubles as the owner's login username, so it
    // has to be unique across every organization -- otherwise two owners
    // could collide and neither could log in reliably.
    const existing = await sql`SELECT id FROM organizations WHERE lower(boat_name) = lower(${b.boatName})`;
    if(existing.length > 0) return res.status(409).json({ ok:false, error:'That boat name is already taken as a username. Choose a different one.' });

    // Every individual number entered (both fields can carry more than
    // one number, e.g. "7777777 / 9999999") gets checked two ways:
    //   1) is any of them blocked (tied to a suspended or deleted
    //      account)? -- returns a structured response the front-end turns
    //      into the "blocked number" popup, with a pay-to-resolve path
    //      for still-suspended (not yet deleted) accounts.
    //   2) is any of them already in active use by a different account?
    //      -- plain rejection, no special popup.
    const numbersEntered = Array.from(new Set(parseNumbers(b.mobile).concat(parseNumbers(b.contactNumber))));
    if(numbersEntered.length){
      const blockedRows = await sql`
        SELECT * FROM blocked_numbers
        WHERE status = 'blocked' AND mobile = ANY(${numbersEntered}::text[])
        ORDER BY created_at DESC LIMIT 1
      `;
      if(blockedRows.length){
        const rec = blockedRows[0];
        let organizationId = null, dueAmount = 0, dueCurrency = 'MVR';
        if(rec.organization_id){
          const orgRows = await sql`SELECT id, due_amount, due_currency FROM organizations WHERE id = ${rec.organization_id}`;
          if(orgRows.length){
            organizationId = rec.organization_id;
            dueAmount = Number(orgRows[0].due_amount) || 0;
            dueCurrency = orgRows[0].due_currency || 'MVR';
          }
        }
        return res.status(409).json({
          ok:false, blocked:true, mobile: rec.mobile,
          boatName: rec.boat_name, ownerName: rec.owner_name, reason: rec.reason,
          organizationId, dueAmount, dueCurrency,
        });
      }
      const conflict = await findActiveNumberConflict(numbersEntered);
      if(conflict){
        return res.status(409).json({ ok:false, error: 'This mobile number is already in use. Please use another mobile number.' });
      }
    }

    // Was this mobile number previously deleted (by an admin, or
    // automatically after 15 days suspended)? Flag it distinctly for the
    // Super Admin rather than silently letting it back in unnoticed. (By
    // this point it's already confirmed NOT currently blocked, e.g. its
    // due balance was just paid off -- see resolveDuePayment -- so this
    // is purely informational for the admin.)
    const priorDeletion = await sql`SELECT boat_name, reason, deleted_at FROM deleted_accounts WHERE mobile = ${b.mobile} ORDER BY deleted_at DESC LIMIT 1`;

    const orgId = crypto.randomBytes(8).toString('hex');
    const totpSecret = authenticator.generateSecret();
    const passkeyHash = hashPasskey(b.passkey);
    // Boat contact number is optional at signup now (moved to Additional
    // Setup Information) -- when left blank, the owner's own mobile
    // number doubles as the organization's and first boat's contact
    // number until they change it later in Settings.
    const effectiveContactNumber = (b.contactNumber && String(b.contactNumber).trim()) || b.mobile;

    await sql`
      INSERT INTO organizations (
        id, boat_name, owner_name, contact_number, gmail, mobile, passkey_hash,
        bank_account_name, bank_account_number, tracking_link, viber_link,
        social_links, routes, totp_secret, plan_limits_enabled
      ) VALUES (
        ${orgId}, ${b.boatName}, ${b.ownerName}, ${effectiveContactNumber}, ${b.gmail || null}, ${b.mobile}, ${passkeyHash},
        ${b.bankAccountName ? encryptField(b.bankAccountName, orgId) : null}, ${b.bankAccountNumber ? encryptField(b.bankAccountNumber, orgId) : null}, ${b.trackingLink || null}, ${b.viberLink || null},
        ${JSON.stringify(b.socialLinks || [])}::jsonb, ${JSON.stringify(b.routes || [])}::jsonb, ${totpSecret}, true
      )
    `;

    const boatId = crypto.randomBytes(8).toString('hex');
    await sql`
      INSERT INTO boats (id, organization_id, name, is_primary, status)
      VALUES (${boatId}, ${orgId}, ${b.boatName}, true, 'active')
    `;
    await sql`DELETE FROM signup_otps WHERE mobile = ${mobileDigits}`;
    await sql`DELETE FROM signup_email_otps WHERE email = ${emailLower}`;

    if(priorDeletion.length > 0){
      await notifyAdmin('resignup_after_deletion', `${b.ownerName} (${b.mobile}) signed up again as "${b.boatName}" -- was previously deleted ("${priorDeletion[0].boat_name}", removed ${priorDeletion[0].deleted_at.toISOString().slice(0,10)}).`, { type:'organization', id: orgId });
    } else {
      await notifyAdmin('new_signup', `New signup: ${b.ownerName} created boat "${b.boatName}".`, { type:'organization', id: orgId });
    }

    // Pre-fill this boat's own Payment Details and Trip Defaults contact
    // number -- boatContacts always gets a value now (the owner's mobile,
    // if they didn't fill in a separate boat contact number), so this
    // always runs rather than only when contactNumber/bank fields were
    // filled in.
    {
      const initialSettings = {
        bankAccountName: b.bankAccountName ? encryptField(b.bankAccountName, boatId) : '',
        bankAccountNumber: b.bankAccountNumber ? encryptField(b.bankAccountNumber, boatId) : '',
        tripDefaults: { boatContacts: effectiveContactNumber, trackingLink: b.trackingLink || '', viberLink: b.viberLink || '' },
      };
      await sql`
        INSERT INTO app_data (boat_id, key, value, updated_at)
        VALUES (${boatId}, 'settings', ${JSON.stringify(initialSettings)}::jsonb, now())
        ON CONFLICT (boat_id, key) DO UPDATE SET value = ${JSON.stringify(initialSettings)}::jsonb, updated_at = now()
      `;
    }

    res.json({ ok:true, organizationId: orgId, boatId, totpSecret });
  }catch(e){
    console.error(e);
    res.status(500).json({ ok:false, error:'Could not create your account. Try again.' });
  }
});

// Owner login: identify by boat name (case-insensitive) + passkey.
// "Forgot Password" for the #org Owner Login screen. Verifies the code
// against that organization's own authenticator secret (set at signup),
// then issues a token scoped to resetting THAT organization's login
// passkey -- distinct from the older per-boat ownerPin reset flow.
app.post('/api/org-reset/totp-verify', async (req, res) => {
  const boatName = (req.body && req.body.boatName || '').trim();
  const code = (req.body && req.body.code || '').trim();
  const generic = { ok: false, error: 'Incorrect boat name or code.' };
  if (!boatName || !code || !/^\d{6}$/.test(code)) return res.status(400).json(generic);
  try {
    const rows = await sql`SELECT id, totp_secret FROM organizations WHERE lower(boat_name) = lower(${boatName})`;
    const org = rows[0];
    if (!org || !org.totp_secret) return res.status(400).json(generic);
    const valid = authenticator.verify({ token: code, secret: org.totp_secret });
    if (!valid) return res.status(400).json(generic);

    await sql`DELETE FROM pin_resets WHERE expires_at < now() - interval '1 day'`;

    const token = crypto.randomBytes(24).toString('hex');
    const expiresAt = new Date(Date.now() + RESET_TOKEN_TTL_MS).toISOString();
    await sql`
      INSERT INTO pin_resets (token, role, expires_at, organization_id)
      VALUES (${token}, 'org-owner', ${expiresAt}, ${org.id})
    `;
    res.json({ ok: true, token });
  } catch (e) {
    console.error(e);
    res.status(500).json({ ok: false, error: 'Something went wrong. Try again.' });
  }
});

app.post('/api/org-reset/confirm', async (req, res) => {
  const { token, newPasskey } = req.body || {};
  if (!token || !newPasskey || String(newPasskey).length < 6) {
    return res.status(400).json({ ok: false, error: 'Password must be at least 6 characters.' });
  }
  try {
    const rows = await sql`SELECT * FROM pin_resets WHERE token = ${token}`;
    const record = rows[0];
    if (!record || record.used || new Date(record.expires_at) < new Date() || !record.organization_id) {
      return res.status(400).json({ ok: false, error: 'That link is invalid or expired. Request a new one.' });
    }
    const passkeyHash = hashPasskey(newPasskey);
    await sql`UPDATE organizations SET passkey_hash = ${passkeyHash} WHERE id = ${record.organization_id}`;
    await sql`UPDATE pin_resets SET used = true WHERE token = ${token}`;
    res.json({ ok: true });
  } catch (e) {
    console.error(e);
    res.status(500).json({ ok: false, error: 'Something went wrong. Try again.' });
  }
});

app.post('/api/org-login', async (req, res) => {
  try{
    const { mobile, passkey } = req.body || {};
    if(!mobile || !passkey) return res.status(400).json({ ok:false, error:'Username and PIN are required.' });
    const rows = await sql`SELECT * FROM organizations WHERE trim(mobile) = trim(${mobile})`;
    const org = rows[0];
    if(!org || !verifyPasskey(passkey, org.passkey_hash)){
      return res.status(401).json({ ok:false, error:'Incorrect username or PIN.' });
    }
    if(org.status === 'suspended'){
      return res.status(403).json({ ok:false, error:'This account has been suspended. Contact support for help.', note: org.suspension_note || null, suspendedAt: org.suspended_at || null });
    }
    const boats = await sql`SELECT id, name, is_primary, status, suspension_note, suspended_at FROM boats WHERE organization_id = ${org.id} ORDER BY created_at ASC`;
    res.json({
      ok:true,
      organization: {
        id: org.id, boatName: org.boat_name, ownerName: org.owner_name,
        contactNumber: org.contact_number, gmail: org.gmail, mobile: org.mobile,
        bankAccountName: decryptField(org.bank_account_name, org.id), bankAccountNumber: decryptField(org.bank_account_number, org.id),
        trackingLink: org.tracking_link, viberLink: org.viber_link,
        socialLinks: org.social_links, routes: org.routes,
        isPro: org.is_pro, proExpiresAt: org.pro_expires_at,
      },
      boats,
    });
  }catch(e){
    console.error(e);
    res.status(500).json({ ok:false, error:'Something went wrong. Try again.' });
  }
});

// Owner requests an additional boat. Re-verifies the org's own passkey so
// this can't be called by anyone who merely knows the organizationId.
//
// Payment + admin approval is a non-Pro-only gate. A Pro org already pays
// for its subscription, so any boat it asks for is created immediately --
// no payment_screenshot, no boat_requests row, nothing sitting in the
// admin's Boat Requests queue. Non-Pro orgs are unchanged: their request
// still lands in boat_requests as 'pending' and waits on
// /api/admin/boat-requests/:id/approve.
app.post('/api/boat-requests', async (req, res) => {
  try{
    const { organizationId, passkey, requestedBoatName, paymentScreenshot } = req.body || {};
    if(!organizationId || !passkey || !requestedBoatName){
      return res.status(400).json({ ok:false, error:'Missing required fields.' });
    }
    const rows = await sql`SELECT passkey_hash, boat_name, is_pro FROM organizations WHERE id = ${organizationId}`;
    const org = rows[0];
    if(!org || !verifyPasskey(passkey, org.passkey_hash)){
      return res.status(401).json({ ok:false, error:'Could not verify your account.' });
    }

    if(org.is_pro){
      if(await boatCapReached(organizationId)){
        return res.status(400).json({ ok:false, error:'You\u2019ve reached the 15-boat limit for your plan. Contact support if you need more.' });
      }
      const boatId = await createBoatForOrganization(organizationId, requestedBoatName);
      // Informational only -- nothing for the admin to act on, so this
      // goes through the same notify type as any other new boat, not
      // 'pending_request' (which implies action is needed).
      await notifyAdmin('new_boat', `${org.boat_name} (Pro) added a new boat: "${requestedBoatName}" -- granted automatically, no approval needed.`, { type:'organization', id: organizationId });
      return res.json({ ok:true, autoApproved:true, boatId });
    }

    const id = crypto.randomBytes(8).toString('hex');
    await sql`
      INSERT INTO boat_requests (id, organization_id, requested_boat_name, payment_screenshot)
      VALUES (${id}, ${organizationId}, ${requestedBoatName}, ${paymentScreenshot || null})
    `;
    await notifyAdmin('pending_request', `${org.boat_name} requested a new boat: "${requestedBoatName}".`, { type:'boat_request', id });
    res.json({ ok:true, autoApproved:false, id });
  }catch(e){
    console.error(e);
    res.status(500).json({ ok:false, error:'Could not submit your request. Try again.' });
  }
});

// Raises the admin notification for a manual bank-transfer Pro request
// (see submitProRequest in index.html) -- the request itself is already
// recorded on the boat's own settings (proRequestPending/proRequestScreenshot,
// visible in the admin's Pro Requests tab); this just puts it in the
// notification queue too, same as every other notifyAdmin call.
app.post('/api/pro-requests', async (req, res) => {
  try{
    const { boatId, boatName } = req.body || {};
    if(!boatId) return res.status(400).json({ ok:false, error:'boatId is required.' });
    const rows = await sql`
      SELECT o.id AS organization_id, o.boat_name AS org_boat_name, o.owner_name FROM boats b
      JOIN organizations o ON o.id = b.organization_id
      WHERE b.id = ${boatId}
    `;
    const label = rows.length ? `${rows[0].owner_name} (${rows[0].org_boat_name})` : (boatName || boatId);
    await notifyAdmin('pro_request', `${label} submitted a Pro upgrade payment for review.`, rows.length ? { type:'organization', id: rows[0].organization_id } : undefined);
    res.json({ ok:true });
  }catch(e){
    console.error(e);
    res.status(500).json({ ok:false, error:'Could not notify admin.' });
  }
});

// Every owner is entitled to one free boat. Normally that's the primary
// boat created at signup -- but if it (and every other boat) has since been
// deleted, an org can be left with zero boats. In that specific case, adding
// a boat is free and immediate, same as signup, with no request/approval/
// payment step -- it only becomes a paid request once they already have one.
app.post('/api/boats/first-free', async (req, res) => {
  try{
    const { organizationId, passkey, boatName } = req.body || {};
    if(!organizationId || !passkey || !boatName){
      return res.status(400).json({ ok:false, error:'Missing required fields.' });
    }
    const rows = await sql`SELECT passkey_hash, contact_number, bank_account_name, bank_account_number FROM organizations WHERE id = ${organizationId}`;
    const org = rows[0];
    if(!org || !verifyPasskey(passkey, org.passkey_hash)){
      return res.status(401).json({ ok:false, error:'Could not verify your account.' });
    }
    const existing = await sql`SELECT id FROM boats WHERE organization_id = ${organizationId} LIMIT 1`;
    if(existing.length > 0){
      return res.status(400).json({ ok:false, error:'This organization already has a boat. Additional boats require a request and approval.' });
    }
    const boatId = crypto.randomBytes(8).toString('hex');
    await sql`
      INSERT INTO boats (id, organization_id, name, is_primary, status)
      VALUES (${boatId}, ${organizationId}, ${boatName}, true, 'active')
    `;
    if(org.bank_account_name || org.bank_account_number || org.contact_number){
      const initialSettings = {
        bankAccountName: encryptField(decryptField(org.bank_account_name, organizationId) || '', boatId),
        bankAccountNumber: encryptField(decryptField(org.bank_account_number, organizationId) || '', boatId),
        tripDefaults: { boatContacts: org.contact_number || '', trackingLink: '', viberLink: '' },
      };
      await sql`
        INSERT INTO app_data (boat_id, key, value, updated_at)
        VALUES (${boatId}, 'settings', ${JSON.stringify(initialSettings)}::jsonb, now())
        ON CONFLICT (boat_id, key) DO UPDATE SET value = ${JSON.stringify(initialSettings)}::jsonb, updated_at = now()
      `;
    }
    await notifyAdmin('new_boat', `New boat created: "${boatName}".`, { type:'organization', id: organizationId });
    res.json({ ok:true, boatId });
  }catch(e){
    console.error(e);
    res.status(500).json({ ok:false, error:'Could not add your boat. Try again.' });
  }
});

// Owner-initiated deletion of one of their own boats (Settings -> Owner
// Settings -> Permanent Deletion, in the dispatch app). Two auth paths,
// matching the app's two sign-in systems:
//   - Multi-boat organizations: verified against the organization's own
//     passkey (body.organizationId + body.passkey), the same check
//     /api/org-login and /api/boats/first-free already use.
//   - Legacy single-boat direct logins (#owner/<boatId> links, no
//     organization involved from the client's point of view): verified
//     against that boat's own owner PIN in its settings (body.pin), the
//     same check /api/owner-pin-login uses.
// Deliberately lighter-touch than the Super Admin delete route above --
// this is an owner voluntarily removing one of their own boats, not a
// moderation action, so their numbers are NOT added to the blocked list
// and nothing is written to deleted_accounts (that table drives the
// "previously deleted" warning/blocklist shown on new signups, which
// only makes sense for an account-level closure, not one boat being
// removed from an organization that may still have others).
app.delete('/api/boats/:id', async (req, res) => {
  try{
    const { id } = req.params;
    const { passkey, organizationId, pin } = req.body || {};
    const boatRows = await sql`SELECT id, organization_id FROM boats WHERE id = ${id}`;
    const boat = boatRows[0];
    if(!boat) return res.status(404).json({ ok:false, error:'Unknown boat.' });

    if(organizationId){
      if(String(boat.organization_id) !== String(organizationId)){
        return res.status(403).json({ ok:false, error:'This boat does not belong to that account.' });
      }
      const orgRows = await sql`SELECT passkey_hash FROM organizations WHERE id = ${organizationId}`;
      const org = orgRows[0];
      if(!org || !passkey || !verifyPasskey(passkey, org.passkey_hash)){
        return res.status(401).json({ ok:false, error:'Incorrect password.' });
      }
    } else {
      const settingsRows = await sql`SELECT value FROM app_data WHERE boat_id = ${id} AND key = 'settings'`;
      const settings = settingsRows.length ? settingsRows[0].value : {};
      if(!settings.ownerPin || !pin || !verifySecret(pin, settings.ownerPin)){
        return res.status(401).json({ ok:false, error:'Incorrect PIN.' });
      }
    }

    await sql`DELETE FROM app_data WHERE boat_id = ${id}`;
    // Clears any lingering suspended-reason block record tied to this
    // boat_id (harmless/no-op in the common case where none exists) so
    // nothing referencing this boat is left behind anywhere once it's
    // gone -- matches the "remove every trace of this boat" intent of a
    // full deletion, same table blockBoatNumbers/liftBoatNumbers already
    // manage elsewhere.
    await liftBoatNumbers(id);
    await sql`DELETE FROM boats WHERE id = ${id}`;
    if(boat.organization_id){
      await notifyAdmin('boat_deleted', `A boat was deleted by its owner.`, { type:'organization', id: boat.organization_id });
    }
    res.json({ ok:true });
  }catch(e){
    console.error(e);
    res.status(500).json({ ok:false, error:'Could not delete this boat. Try again.' });
  }
});

// --- Google Sheets trip logging ---------------------------------------------
// Each ORGANIZATION (not boat) connects one Google account, once, via OAuth.
// Sheets created for that organization's boats live directly in that
// person's own Google Drive -- nothing is stored on our side except the
// refresh token needed to act on their behalf. Requires a Google Cloud
// project with the Sheets + Drive APIs enabled, an OAuth 2.0 Client ID, and
// these three env vars: GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET,
// GOOGLE_REDIRECT_URI (must exactly match the redirect URI registered in
// Google Cloud Console), plus APP_URL (your GitHub Pages URL) to bounce
// back to after connecting.
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID;
const GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET;
const GOOGLE_REDIRECT_URI = process.env.GOOGLE_REDIRECT_URI;
const GOOGLE_APP_URL = (process.env.APP_URL || '').replace(/\/+$/, '');
const GOOGLE_SCOPES = ['https://www.googleapis.com/auth/spreadsheets', 'https://www.googleapis.com/auth/drive.file', 'https://www.googleapis.com/auth/userinfo.email'];
const SHEET_TAB = 'Cargo Log';
const SHEET_HEADER = ['Tracking Code','Sender Name','Sender Mobile','Receiver Name','Receiver Mobile','Destination Island','Items','Total','Payment Status','Delivery Status','Loaded At','Delivered At'];

function googleConfigured(){ return !!(GOOGLE_CLIENT_ID && GOOGLE_CLIENT_SECRET && GOOGLE_REDIRECT_URI); }
function makeGoogleOAuthClient(){
  return new google.auth.OAuth2(GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET, GOOGLE_REDIRECT_URI);
}
// Every organization's Google connection is looked up via whichever boat is
// asking -- boats don't each get their own Google account, they share their
// organization's one connection.
async function getGoogleClientForBoat(boatId){
  const rows = await sql`
    SELECT o.google_refresh_token FROM boats b
    JOIN organizations o ON o.id = b.organization_id
    WHERE b.id = ${boatId}
  `;
  const token = rows[0] && rows[0].google_refresh_token;
  if(!token) return null;
  const client = makeGoogleOAuthClient();
  client.setCredentials({ refresh_token: token });
  return client;
}
function shipmentToSheetRow(s){
  const items = (s.items||[]).map(i => `${i.qty}x ${i.name}`).join(', ');
  return [
    s.id || '', s.name || '', s.mobile || '', s.receiverName || '', s.receiverMobile || '',
    s.island || '', items, (s.total != null ? s.total : ''), (s.paid ? 'Paid' : 'Unpaid'),
    s.status || '', s.loadedAt || '', s.deliveredAt || '',
  ];
}

// Start the connect flow -- boatId travels through as the OAuth "state" so
// the callback knows which boat's organization to attach the token to.
app.get('/api/google/auth-url', (req, res) => {
  if(!googleConfigured()) return res.status(503).json({ error: 'Google integration is not configured yet.' });
  const boatId = req.query.boatId;
  if(!boatId) return res.status(400).json({ error: 'boatId is required.' });
  const client = makeGoogleOAuthClient();
  const url = client.generateAuthUrl({
    access_type: 'offline',
    prompt: 'consent', // forces a refresh_token every time, not just the first connect
    scope: GOOGLE_SCOPES,
    state: boatId,
  });
  res.json({ url });
});

app.get('/api/google/oauth-callback', async (req, res) => {
  const { code, state: boatId } = req.query;
  if(!googleConfigured() || !code || !boatId){
    return res.status(400).send('Missing information. Close this tab and try connecting again.');
  }
  try{
    const client = makeGoogleOAuthClient();
    const { tokens } = await client.getToken(code);
    if(!tokens.refresh_token){
      // Happens if the account already granted consent before without
      // prompt=consent forcing a fresh one -- shouldn't occur here since we
      // always pass prompt=consent, but guard anyway.
      return res.status(400).send('Google did not return a long-lived connection. Revoke access for this app in your Google Account and try again.');
    }
    client.setCredentials(tokens);
    const oauth2 = google.oauth2({ version: 'v2', auth: client });
    const me = await oauth2.userinfo.get();
    const email = me.data.email;

    const boatRows = await sql`SELECT organization_id FROM boats WHERE id = ${boatId}`;
    const orgId = boatRows[0] && boatRows[0].organization_id;
    if(orgId){
      await sql`UPDATE organizations SET google_refresh_token = ${tokens.refresh_token}, google_connected_email = ${email} WHERE id = ${orgId}`;
    }
    res.redirect(`${GOOGLE_APP_URL}/#owner/${boatId}`);
  }catch(e){
    console.error(e);
    res.status(500).send('Could not connect your Google account. Close this tab and try again.');
  }
});

app.get('/api/google/status', async (req, res) => {
  const boatId = req.query.boatId;
  if(!boatId) return res.status(400).json({ connected:false });
  try{
    const rows = await sql`
      SELECT o.google_connected_email FROM boats b
      JOIN organizations o ON o.id = b.organization_id
      WHERE b.id = ${boatId}
    `;
    const email = rows[0] && rows[0].google_connected_email;
    res.json({ connected: !!email, email: email || null, configured: googleConfigured() });
  }catch(e){ console.error(e); res.status(500).json({ connected:false }); }
});

app.post('/api/google/disconnect', async (req, res) => {
  const { boatId } = req.body || {};
  if(!boatId) return res.status(400).json({ ok:false });
  try{
    const boatRows = await sql`SELECT organization_id FROM boats WHERE id = ${boatId}`;
    const orgId = boatRows[0] && boatRows[0].organization_id;
    if(orgId) await sql`UPDATE organizations SET google_refresh_token = NULL, google_connected_email = NULL WHERE id = ${orgId}`;
    res.json({ ok:true });
  }catch(e){ console.error(e); res.status(500).json({ ok:false }); }
});

// Create a new sheet for a trip, with a header row already in place.
// Silently no-ops with { ok:false, error:'not_connected' } if this boat's
// organization hasn't connected Google -- trips still work fine without it.
app.post('/api/google/sheets/create', async (req, res) => {
  const { boatId, title } = req.body || {};
  try{
    const client = await getGoogleClientForBoat(boatId);
    if(!client) return res.json({ ok:false, error:'not_connected' });
    const sheets = google.sheets({ version:'v4', auth: client });
    const created = await sheets.spreadsheets.create({
      requestBody: {
        properties: { title: title || 'Ferry Cargo Trip' },
        sheets: [{ properties: { title: SHEET_TAB } }],
      },
    });
    const spreadsheetId = created.data.spreadsheetId;
    await sheets.spreadsheets.values.update({
      spreadsheetId,
      range: `${SHEET_TAB}!A1`,
      valueInputOption: 'RAW',
      requestBody: { values: [SHEET_HEADER] },
    });
    await sheets.spreadsheets.batchUpdate({
      spreadsheetId,
      requestBody: { requests: [{
        repeatCell: {
          range: { sheetId: 0, startRowIndex: 0, endRowIndex: 1 },
          cell: { userEnteredFormat: { textFormat: { bold: true } } },
          fields: 'userEnteredFormat.textFormat.bold',
        },
      }]},
    });
    res.json({ ok:true, sheetId: spreadsheetId, sheetUrl: `https://docs.google.com/spreadsheets/d/${spreadsheetId}/edit` });
  }catch(e){
    console.error(e);
    res.status(500).json({ ok:false, error:'Could not create the sheet.' });
  }
});

// Live row sync -- called on every shipment change (check-in, loaded,
// delivered, paid). Upserts by tracking code: updates the existing row if
// found, appends a new one if not.
app.post('/api/google/sheets/sync-row', async (req, res) => {
  const { boatId, sheetId, shipment } = req.body || {};
  if(!sheetId || !shipment || !shipment.id) return res.json({ ok:false });
  try{
    const client = await getGoogleClientForBoat(boatId);
    if(!client) return res.json({ ok:false, error:'not_connected' });
    const sheets = google.sheets({ version:'v4', auth: client });
    const colA = await sheets.spreadsheets.values.get({ spreadsheetId: sheetId, range: `${SHEET_TAB}!A:A` });
    const rows = colA.data.values || [];
    const rowIndex = rows.findIndex(r => r[0] === shipment.id);
    const row = shipmentToSheetRow(shipment);
    if(rowIndex === -1){
      await sheets.spreadsheets.values.append({
        spreadsheetId: sheetId,
        range: `${SHEET_TAB}!A:L`,
        valueInputOption: 'RAW',
        insertDataOption: 'INSERT_ROWS',
        requestBody: { values: [row] },
      });
    } else {
      const rowNum = rowIndex + 1;
      await sheets.spreadsheets.values.update({
        spreadsheetId: sheetId,
        range: `${SHEET_TAB}!A${rowNum}:L${rowNum}`,
        valueInputOption: 'RAW',
        requestBody: { values: [row] },
      });
    }
    res.json({ ok:true });
  }catch(e){
    console.error(e);
    res.status(500).json({ ok:false });
  }
});

// Trip end: rename the sheet to mark it closed out, and save a PDF export
// alongside it in the same Drive.
app.post('/api/google/sheets/finalize', async (req, res) => {
  const { boatId, sheetId, tripTitle } = req.body || {};
  if(!sheetId) return res.json({ ok:false });
  try{
    const client = await getGoogleClientForBoat(boatId);
    if(!client) return res.json({ ok:false, error:'not_connected' });
    const drive = google.drive({ version:'v3', auth: client });
    const dateStr = new Date().toISOString().slice(0,10);
    const finalName = `${tripTitle || 'Trip'} \u2014 FINAL \u2014 ${dateStr}`;
    await drive.files.update({ fileId: sheetId, requestBody: { name: finalName } });

    const exported = await drive.files.export(
      { fileId: sheetId, mimeType: 'application/pdf' },
      { responseType: 'arraybuffer' }
    );
    const pdfBuffer = Buffer.from(exported.data);
    const { Readable } = require('stream');
    const pdfFile = await drive.files.create({
      requestBody: { name: `${finalName}.pdf`, mimeType: 'application/pdf' },
      media: { mimeType: 'application/pdf', body: Readable.from(pdfBuffer) },
    });
    res.json({ ok:true, pdfFileId: pdfFile.data.id });
  }catch(e){
    console.error(e);
    res.status(500).json({ ok:false, error:'Could not finalize the sheet.' });
  }
});

const port = process.env.PORT || 3000;
app.listen(port, () => console.log(`Cargo API listening on :${port}`));
