-- Additive basic-account support. Run this manually, once, on the live Railway
-- MySQL BEFORE deploying the server code that reads/writes these columns. It is
-- not run by setup-db.js. Existing rows keep their current verification_level;
-- no row data is backfilled or otherwise modified.

-- Allow the new 'basic' tier while keeping the current default for any row that
-- does not set the level explicitly. Existing 'verified' / 'fully_verified'
-- values are unchanged.
ALTER TABLE users
  MODIFY COLUMN verification_level ENUM('basic','verified','fully_verified') NOT NULL DEFAULT 'verified';

-- The old sign-up flow wrote its ID number on every account. New basic accounts
-- insert NULL and collect the number only when they request an upgrade, so the
-- column must accept NULL. The existing UNIQUE key is left in place.
ALTER TABLE users
  MODIFY COLUMN government_id_number VARCHAR(64) NULL;

-- The upgrade row now carries the ID number being reviewed (copied to users
-- only on approval) and the reason shown to the user when an admin rejects it.
ALTER TABLE verification_upgrades
  ADD COLUMN government_id_number VARCHAR(64) NULL AFTER upgrade_method,
  ADD COLUMN rejection_reason VARCHAR(255) NULL AFTER reviewed_by,
  ADD KEY idx_verification_upgrades_gov_id (government_id_number, status);
