-- Additive guardian-assisted verification columns.
-- Run this manually, once, on the live Railway MySQL BEFORE deploying the
-- server code that reads/writes these columns. It is not run by setup-db.js.
-- Existing rows get the default upgrade_method = 'self'; no row data is
-- backfilled or otherwise modified.

ALTER TABLE verification_upgrades
  ADD COLUMN upgrade_method ENUM('self','guardian') NOT NULL DEFAULT 'self',
  ADD COLUMN guardian_name VARCHAR(100) NULL,
  ADD COLUMN guardian_relationship ENUM('parent','legal_guardian') NULL,
  ADD COLUMN guardian_photo LONGTEXT NULL,
  ADD COLUMN guardian_id_photo LONGTEXT NULL,
  ADD COLUMN guardian_id_photo_back LONGTEXT NULL,
  ADD COLUMN birth_certificate_photo LONGTEXT NULL,
  ADD COLUMN guardian_face_match_confidence DOUBLE NULL,
  ADD COLUMN consent_at TIMESTAMP NULL;
