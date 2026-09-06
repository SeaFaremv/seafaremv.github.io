-- SeaFare -- full database schema, matching the current multi-
-- tenant server.js exactly (organizations -> boats -> app_data, plus PIN
-- reset tokens and boat-add requests). Run this once against a brand new
-- Neon database.
--
-- This replaces the old single-tenant neon-schema.sql (a single app_data
-- table keyed only by `key`, no organizations/boats at all) which no
-- longer matches how the app has grown. If you're setting up a fresh
-- Neon project, this is the file to run -- the old one is obsolete.

-- ---------------------------------------------------------------------------
-- organizations: one row per owner/company. Created at signup (POST
-- /api/signup). The first boat's name doubles as the login username
-- (case-insensitive unique), so boat_name lives here.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS organizations (
  id                      TEXT PRIMARY KEY,
  boat_name               TEXT NOT NULL,
  owner_name              TEXT NOT NULL,
  contact_number          TEXT NOT NULL,
  gmail                   TEXT,
  mobile                  TEXT NOT NULL,
  passkey_hash            TEXT NOT NULL,
  bank_account_name       TEXT,
  bank_account_number     TEXT,
  tracking_link           TEXT,
  viber_link              TEXT,
  social_links            JSONB NOT NULL DEFAULT '[]'::jsonb,
  routes                  JSONB NOT NULL DEFAULT '[]'::jsonb,
  totp_secret             TEXT NOT NULL,
  status                  TEXT NOT NULL DEFAULT 'active',   -- 'active' | 'suspended'
  suspension_note         TEXT,
  google_refresh_token    TEXT,
  google_connected_email  TEXT,
  is_pro                  BOOLEAN NOT NULL DEFAULT false,
  pro_started_at          TIMESTAMPTZ,
  pro_expires_at          TIMESTAMPTZ,
  created_at              TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Boat names are looked up case-insensitively (lower(boat_name)) both for
-- uniqueness at signup and for every org login -- this index makes both fast
-- and enforces the uniqueness at the database level too, not just in app code.
CREATE UNIQUE INDEX IF NOT EXISTS organizations_boat_name_lower_idx
  ON organizations (lower(boat_name));

-- Safe to run against an existing database that already has the
-- organizations table from before Pro moved to the organization level --
-- adds the three columns only if they're not already there.
ALTER TABLE organizations ADD COLUMN IF NOT EXISTS is_pro BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE organizations ADD COLUMN IF NOT EXISTS pro_started_at TIMESTAMPTZ;
ALTER TABLE organizations ADD COLUMN IF NOT EXISTS pro_expires_at TIMESTAMPTZ;

-- ---------------------------------------------------------------------------
-- boats: one row per boat. Every organization gets one free boat at
-- signup (is_primary = true); additional boats go through a request/
-- approval flow (boat_requests below).
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS boats (
  id               TEXT PRIMARY KEY,
  organization_id  TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  name             TEXT NOT NULL,
  is_primary       BOOLEAN NOT NULL DEFAULT false,
  status           TEXT NOT NULL DEFAULT 'active',   -- 'active' | 'suspended'
  suspension_note  TEXT,
  created_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS boats_organization_id_idx ON boats (organization_id);

-- ---------------------------------------------------------------------------
-- app_data: every boat's own shipments/rates/trips/settings, stored as JSON
-- documents scoped by boat_id. This is intentionally NOT cascade-deleted
-- from boats/organizations -- the API cleans it up by hand first (see the
-- DELETE /api/admin/organizations/:id and /api/admin/boats/:id handlers)
-- since it's a different table with its own lifecycle, not a strict
-- ownership relationship worth a hard FK cascade.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS app_data (
  boat_id     TEXT NOT NULL,
  key         TEXT NOT NULL,
  value       JSONB NOT NULL,
  updated_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (boat_id, key)
);

-- ---------------------------------------------------------------------------
-- pin_resets: one-time tokens for the three PIN/passkey reset flows --
-- Owner PIN reset (role='owner', scoped by boat_id), org login passkey
-- reset (role='org-owner', scoped by organization_id), and the older
-- unscoped legacy path (both null, kept only for backward safety and no
-- longer created by current code). Tokens are single-use and expire after
-- 30 minutes; expired ones older than a day get swept on each new request.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS pin_resets (
  token            TEXT PRIMARY KEY,
  role             TEXT NOT NULL DEFAULT 'owner',
  expires_at       TIMESTAMPTZ NOT NULL,
  used             BOOLEAN NOT NULL DEFAULT false,
  boat_id          TEXT REFERENCES boats(id) ON DELETE CASCADE,
  organization_id  TEXT REFERENCES organizations(id) ON DELETE CASCADE,
  created_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS pin_resets_expires_at_idx ON pin_resets (expires_at);

-- ---------------------------------------------------------------------------
-- boat_requests: an owner's request for an additional boat beyond their
-- free first one, reviewed from the Super Admin dashboard. The payment
-- screenshot is cleared (set to NULL) once approved -- it's sensitive
-- banking info and shouldn't be retained after review.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS boat_requests (
  id                    TEXT PRIMARY KEY,
  organization_id       TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  requested_boat_name   TEXT NOT NULL,
  payment_screenshot    TEXT,
  status                TEXT NOT NULL DEFAULT 'pending',   -- 'pending' | 'approved' | 'rejected'
  admin_note            TEXT,
  created_at            TIMESTAMPTZ NOT NULL DEFAULT now(),
  reviewed_at           TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS boat_requests_organization_id_idx ON boat_requests (organization_id);

-- ---------------------------------------------------------------------------
-- admin_settings: a single row (id = 'admin') holding the Super Admin's
-- in-app-editable settings -- an optional username/password override (falls
-- back to the ADMIN_USERNAME/ADMIN_PASSWORD env vars when not set here), the
-- bank account details shown to owners in the Pro upgrade payment popup, and
-- which notification types should be raised to the admin queue. There's only
-- ever one admin account, so a single fixed-id row is enough -- no need for
-- a full table keyed by user.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS admin_settings (
  id                    TEXT PRIMARY KEY DEFAULT 'admin',
  username              TEXT,
  password_hash         TEXT,
  bank_account_name     TEXT,
  bank_account_number   TEXT,
  notify_new_signups    BOOLEAN NOT NULL DEFAULT true,
  notify_boat_requests  BOOLEAN NOT NULL DEFAULT true,
  notify_new_boats      BOOLEAN NOT NULL DEFAULT true,
  updated_at            TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ---------------------------------------------------------------------------
-- pro_payments: one row per Swipe payment link created from the Pro upgrade
-- popup. `reference` is Swipe's transaction code for the payment (returned
-- as `reference` from POST /api/v1/payments, and again as `transaction_code`
-- on the webhook payload) -- it's what correlates an incoming webhook back
-- to the boat that requested the link, since the webhook itself has no idea
-- which SeaFare boat initiated the payment.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS pro_payments (
  id            TEXT PRIMARY KEY,
  boat_id       TEXT NOT NULL REFERENCES boats(id) ON DELETE CASCADE,
  swipe_payment_id TEXT NOT NULL,
  reference     TEXT,
  amount        NUMERIC NOT NULL,
  currency      TEXT NOT NULL DEFAULT 'MVR',
  status        TEXT NOT NULL DEFAULT 'PENDING',   -- 'PENDING' | 'COMPLETED' | 'EXPIRED' | 'CANCELLED'
  payment_url   TEXT,
  created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
  completed_at  TIMESTAMPTZ
);

-- swipe_payment_id, not reference, is the reliable correlation key --
-- Swipe doesn't always return `reference` at creation time (it may only
-- get assigned once the payment actually progresses), so it can't be
-- required or relied on for matching a webhook back to this row.
CREATE UNIQUE INDEX IF NOT EXISTS pro_payments_swipe_payment_id_idx ON pro_payments (swipe_payment_id);
CREATE INDEX IF NOT EXISTS pro_payments_reference_idx ON pro_payments (reference);
CREATE INDEX IF NOT EXISTS pro_payments_boat_id_idx ON pro_payments (boat_id);

-- Safe to run against an existing database that already has this table
-- from before this fix -- drops the old NOT NULL + unique constraint on
-- reference and adds the new unique index on swipe_payment_id instead.
ALTER TABLE pro_payments ALTER COLUMN reference DROP NOT NULL;
DROP INDEX IF EXISTS pro_payments_reference_idx;
CREATE INDEX IF NOT EXISTS pro_payments_reference_idx ON pro_payments (reference);
CREATE UNIQUE INDEX IF NOT EXISTS pro_payments_swipe_payment_id_idx ON pro_payments (swipe_payment_id);

-- ---------------------------------------------------------------------------
-- external_swipe_references: references registered by another app sharing
-- this Swipe client/wallet (currently just Maldexpress, source='maldexpress'),
-- so POST /api/webhooks/swipe below knows to forward that event instead of
-- processing it as one of SeaFare's own payments. Registered via POST
-- /api/internal/register-swipe-reference before the other app's payment
-- link is ever shown to its user, so a webhook can never arrive before the
-- row does. `reference` holds whatever identifier that app registered --
-- for Maldexpress this is Swipe's transaction_id, for the same reason
-- pro_payments keys on swipe_payment_id rather than the sometimes-absent
-- transaction_code/reference field.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS external_swipe_references (
  reference      TEXT PRIMARY KEY,
  source         TEXT NOT NULL,
  registered_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ---------------------------------------------------------------------------
-- admin_notifications: the Super Admin's notification queue (new signups,
-- new boats, pending boat requests, Pro requests, Swipe payments, and
-- re-signups of a previously-deleted mobile number). reference_type /
-- reference_id let the admin UI jump straight to the relevant record when a
-- notification is tapped -- 'organization' + an organizations.id for
-- account-level events, 'boat_request' + a boat_requests.id for a pending
-- request awaiting approval. Both are nullable since older notification
-- types (or rows written before this was added) may not have one.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS admin_notifications (
  id              TEXT PRIMARY KEY,
  type            TEXT NOT NULL,
  message         TEXT NOT NULL,
  reference_type  TEXT,
  reference_id    TEXT,
  read            BOOLEAN NOT NULL DEFAULT false,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS admin_notifications_created_at_idx ON admin_notifications (created_at);

-- Safe to run against an existing database that already has this table from
-- before notifications carried a reference -- adds the two columns only if
-- they're not already there.
ALTER TABLE admin_notifications ADD COLUMN IF NOT EXISTS reference_type TEXT;
ALTER TABLE admin_notifications ADD COLUMN IF NOT EXISTS reference_id TEXT;

-- ---------------------------------------------------------------------------
-- admin_push_subscriptions: one row per browser/device the Super Admin has
-- enabled real push notifications on (Notifications tab -> "Enable Push
-- Notifications on This Device"). `subscription` is the full PushSubscription
-- object the browser returns; `endpoint` (part of that object, also unique
-- per device) is the natural key so re-enabling on the same device updates
-- rather than duplicates.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS admin_push_subscriptions (
  endpoint     TEXT PRIMARY KEY,
  subscription JSONB NOT NULL,
  created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ---------------------------------------------------------------------------
-- deleted_accounts: a small audit trail kept after an organization or boat
-- is deleted (by the Super Admin, or automatically after 15 days
-- suspended) -- mobile + names + reason only, no other account data. Used
-- at signup to flag when a mobile number that was previously removed is
-- signing up again, so the Super Admin sees it distinctly rather than it
-- silently blending in with ordinary new signups.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS deleted_accounts (
  id          TEXT PRIMARY KEY,
  mobile      TEXT NOT NULL,
  boat_name   TEXT NOT NULL,
  owner_name  TEXT NOT NULL,
  reason      TEXT NOT NULL,
  deleted_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS deleted_accounts_mobile_idx ON deleted_accounts (mobile);

-- ---------------------------------------------------------------------------
-- admin_settings notification toggles for Pro requests / Pro payments --
-- these two columns are used by server.js (GET /api/admin/settings,
-- POST /api/admin/settings/notifications) but were missing from the
-- original admin_settings table above. Safe to run against an existing
-- database; adds them only if not already there.
-- ---------------------------------------------------------------------------
ALTER TABLE admin_settings ADD COLUMN IF NOT EXISTS notify_pro_requests BOOLEAN NOT NULL DEFAULT true;
ALTER TABLE admin_settings ADD COLUMN IF NOT EXISTS notify_pro_payments BOOLEAN NOT NULL DEFAULT true;

-- ---------------------------------------------------------------------------
-- That's the whole schema. No default/seed rows are inserted here (unlike
-- the old single-tenant version) -- every organization, boat, and its
-- initial rates/settings are created dynamically through the app's own
-- signup flow (POST /api/signup) as real owners sign up. There's nothing
-- to pre-seed at the database level anymore.
-- ---------------------------------------------------------------------------
