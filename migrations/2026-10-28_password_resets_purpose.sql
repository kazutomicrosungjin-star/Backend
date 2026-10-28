-- Additive password/PIN reset-purpose migration.
-- Run this manually, once, on the live Railway MySQL BEFORE deploying the
-- server code that reads/writes this column. It is not run by setup-db.js.
-- Existing password_resets rows remain valid password-purpose codes because
-- the new column defaults to 'password'.

ALTER TABLE password_resets
  ADD COLUMN purpose ENUM('password','pin') NOT NULL DEFAULT 'password' AFTER user_id,
  ADD KEY idx_password_resets_user_purpose (user_id, purpose, created_at);
