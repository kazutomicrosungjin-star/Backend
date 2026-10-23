-- PayCST backend: COMPLETE, CURRENT database schema (for a brand-new database).
-- Built from what server.js actually reads and writes. The old schema.sql in
-- the repo was missing the phone / ID / photo / verification columns and the
-- savings, group-request and login-attempt tables.
--
-- Money is stored as whole centavos (BIGINT), never decimals.
--
-- On Railway / most hosts the database already exists, so skip the first two
-- lines (CREATE DATABASE / USE) and select your database in your SQL tool.

CREATE DATABASE IF NOT EXISTS paycst CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE paycst;

-- ---------- admins ----------
CREATE TABLE IF NOT EXISTS admins (
  id INT AUTO_INCREMENT PRIMARY KEY,
  username VARCHAR(50) NOT NULL,
  password_hash CHAR(60) NOT NULL,
  pin_hash CHAR(60) NULL,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE KEY uniq_admin_username (username)
) ENGINE=InnoDB;

-- ---------- users ----------
-- UNIQUE keys on username, wallet_id (= phone number), phone_number and
-- government_id_number make the DATABASE refuse duplicate accounts even if two
-- sign-ups arrive at the same instant.
CREATE TABLE IF NOT EXISTS users (
  id INT AUTO_INCREMENT PRIMARY KEY,
  username VARCHAR(50) NOT NULL,
  password_hash CHAR(60) NOT NULL,
  pin_hash CHAR(60) NOT NULL,
  wallet_id VARCHAR(20) NOT NULL,
  balance BIGINT NOT NULL DEFAULT 0,
  -- NULL means no budget set. The user sets it themselves; it is a spending
  -- target, not a cap the server enforces.
  monthly_budget_centavos BIGINT NULL,
  phone_number VARCHAR(20) NULL,
  government_id_number VARCHAR(64) NULL,
  government_id_photo LONGTEXT NULL,
  government_id_photo_back LONGTEXT NULL,
  selfie_photo LONGTEXT NULL,
  terms_accepted_at TIMESTAMP NULL,
  verification_status ENUM('pending','approved','rejected') NOT NULL DEFAULT 'pending',
  verification_level ENUM('verified','fully_verified') NOT NULL DEFAULT 'verified',
  liveness_status ENUM('not_done','passed','skipped') NOT NULL DEFAULT 'not_done',
  face_match_confidence DOUBLE NULL,
  status ENUM('active','suspended') NOT NULL DEFAULT 'active',
  session_version INT NOT NULL DEFAULT 0,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE KEY uniq_users_username (username),
  UNIQUE KEY uniq_users_wallet (wallet_id),
  UNIQUE KEY uniq_users_phone (phone_number),
  UNIQUE KEY uniq_users_gov_id (government_id_number),
  KEY idx_users_verification (verification_status)
) ENGINE=InnoDB;

-- ---------- groups ----------
CREATE TABLE IF NOT EXISTS `groups` (
  id INT AUTO_INCREMENT PRIMARY KEY,
  name VARCHAR(100) NOT NULL,
  balance BIGINT NOT NULL DEFAULT 0,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS group_members (
  id INT AUTO_INCREMENT PRIMARY KEY,
  group_id INT NOT NULL,
  user_id INT NOT NULL,
  joined_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE KEY uniq_member (group_id, user_id),
  KEY idx_member_user (user_id),
  FOREIGN KEY (group_id) REFERENCES `groups`(id) ON DELETE CASCADE,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS group_join_requests (
  id INT AUTO_INCREMENT PRIMARY KEY,
  group_id INT NOT NULL,
  user_id INT NOT NULL,
  status ENUM('pending','approved','declined') NOT NULL DEFAULT 'pending',
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  KEY idx_join_group (group_id, status),
  FOREIGN KEY (group_id) REFERENCES `groups`(id) ON DELETE CASCADE,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS group_withdraw_requests (
  id INT AUTO_INCREMENT PRIMARY KEY,
  group_id INT NOT NULL,
  requester_id INT NOT NULL,
  amount BIGINT NOT NULL,
  reason VARCHAR(255) NOT NULL,
  approvals_needed INT NOT NULL DEFAULT 1,
  status ENUM('pending','approved','declined') NOT NULL DEFAULT 'pending',
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  KEY idx_gwr_group (group_id, status),
  FOREIGN KEY (group_id) REFERENCES `groups`(id) ON DELETE CASCADE,
  FOREIGN KEY (requester_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS group_withdraw_approvals (
  id INT AUTO_INCREMENT PRIMARY KEY,
  request_id INT NOT NULL,
  member_id INT NOT NULL,
  decision ENUM('approve','decline') NOT NULL,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE KEY uniq_member_request (request_id, member_id),
  FOREIGN KEY (request_id) REFERENCES group_withdraw_requests(id) ON DELETE CASCADE,
  FOREIGN KEY (member_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB;

-- Older admin-approved group withdrawal flow (still referenced by the code).
CREATE TABLE IF NOT EXISTS withdrawal_requests (
  id INT AUTO_INCREMENT PRIMARY KEY,
  group_id INT NOT NULL,
  requester_name VARCHAR(100) NOT NULL,
  reason VARCHAR(255) NOT NULL,
  amount BIGINT NOT NULL,
  status ENUM('pending','approved','declined') NOT NULL DEFAULT 'pending',
  decided_by_admin_id INT NULL,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  decided_at TIMESTAMP NULL,
  KEY group_id (group_id),
  KEY decided_by_admin_id (decided_by_admin_id),
  FOREIGN KEY (group_id) REFERENCES `groups`(id) ON DELETE CASCADE,
  FOREIGN KEY (decided_by_admin_id) REFERENCES admins(id) ON DELETE SET NULL
) ENGINE=InnoDB;

-- ---------- money ----------
CREATE TABLE IF NOT EXISTS transactions (
  id INT AUTO_INCREMENT PRIMARY KEY,
  account_type ENUM('user','group') NOT NULL,
  account_id INT NOT NULL,
  label VARCHAR(200) NOT NULL,
  type VARCHAR(50) NOT NULL,
  amount BIGINT NOT NULL,
  is_credit TINYINT(1) NOT NULL,
  transfer_ref VARCHAR(64) NULL,
  details JSON NULL,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  reversed_transfer_ref VARCHAR(64) NULL,
  KEY idx_tx_account (account_type, account_id, created_at),
  KEY idx_tx_ref (transfer_ref),
  KEY idx_tx_reversed (reversed_transfer_ref)
) ENGINE=InnoDB;

-- ---------- payment requests (request money) ----------
-- Also created at boot by server.js, and the two definitions must stay
-- identical: schema.sql is the source of truth for a brand-new database, while
-- server.js creates the table on an existing one. No foreign keys here, so
-- where this table sits in this file does not matter.
CREATE TABLE IF NOT EXISTS payment_requests (
  id INT AUTO_INCREMENT PRIMARY KEY,
  requester_id INT NOT NULL,
  payer_id INT NOT NULL,
  amount BIGINT NOT NULL,
  note VARCHAR(100) NULL,
  status ENUM('pending','paid','declined','cancelled') NOT NULL DEFAULT 'pending',
  reference VARCHAR(20) NULL,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  responded_at TIMESTAMP NULL,
  KEY idx_pr_payer (payer_id, status),
  KEY idx_pr_requester (requester_id, created_at)
) ENGINE=InnoDB;

-- ---------- events and tickets ----------
-- Added after `transactions` so the two commerce tables sit together. Both are
-- new tables, so CREATE TABLE IF NOT EXISTS creates them on the next boot of a
-- server started with AUTO_SETUP_DB=true; no ALTER of an existing table is
-- needed and setup-db.js is not involved.
--
-- capacity is deliberately unused in v1 (NULL means unlimited). It exists so
-- enabling a limit later is an additive change. There is no tickets_sold
-- counter on purpose: the tickets table is the single source of truth and a
-- counter could drift out of step with it.
CREATE TABLE IF NOT EXISTS events (
  id INT AUTO_INCREMENT PRIMARY KEY,
  title VARCHAR(150) NOT NULL,
  venue VARCHAR(150) NOT NULL,
  starts_at TIMESTAMP NOT NULL,
  price_centavos BIGINT NOT NULL,
  capacity INT NULL,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  KEY idx_events_starts (starts_at)
) ENGINE=InnoDB;

-- ticket_code is a bearer credential, so it is 128 bits of
-- crypto.randomBytes(16) hex, not the short human-facing reference number that
-- appears on receipts. status is unused in v1 (there is no cancel, refund or
-- scanner yet) but a ticket with no lifecycle state cannot be extended without
-- a second migration.
CREATE TABLE IF NOT EXISTS tickets (
  id INT AUTO_INCREMENT PRIMARY KEY,
  user_id INT NOT NULL,
  event_id INT NOT NULL,
  ticket_code CHAR(32) NOT NULL,
  quantity INT NOT NULL DEFAULT 1,
  amount_paid_centavos BIGINT NOT NULL,
  status ENUM('valid','cancelled','used') NOT NULL DEFAULT 'valid',
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE KEY uniq_ticket_code (ticket_code),
  KEY idx_tickets_user (user_id, created_at),
  KEY idx_tickets_event (event_id),
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
  FOREIGN KEY (event_id) REFERENCES events(id) ON DELETE CASCADE
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS savings_goals (
  id INT AUTO_INCREMENT PRIMARY KEY,
  user_id INT NOT NULL,
  name VARCHAR(100) NOT NULL,
  target_amount BIGINT NOT NULL,
  saved_amount BIGINT NOT NULL DEFAULT 0,
  status ENUM('active','completed') NOT NULL DEFAULT 'active',
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  KEY idx_savings_user (user_id),
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB;

-- ---------- loans ----------
CREATE TABLE IF NOT EXISTS loans (
  id INT AUTO_INCREMENT PRIMARY KEY,
  user_id INT NOT NULL,
  loan_type VARCHAR(50) NOT NULL DEFAULT 'Personal Loan',
  amount BIGINT NOT NULL,
  purpose VARCHAR(255) NOT NULL,
  term_months INT NOT NULL,
  applicant_age INT NOT NULL DEFAULT 18,
  government_id VARCHAR(50) NOT NULL DEFAULT '',
  legal_ack TINYINT(1) NOT NULL DEFAULT 0,
  status ENUM('pending','approved','declined','repaid') NOT NULL DEFAULT 'pending',
  amount_repaid BIGINT NOT NULL DEFAULT 0,
  approvals_needed INT NOT NULL DEFAULT 2,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  decided_at TIMESTAMP NULL DEFAULT NULL,
  KEY idx_loans_user (user_id),
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS loan_approvals (
  id INT AUTO_INCREMENT PRIMARY KEY,
  loan_id INT NOT NULL,
  admin_id INT NOT NULL,
  decision ENUM('approve','decline') NOT NULL,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE KEY uniq_admin_loan (loan_id, admin_id),
  FOREIGN KEY (loan_id) REFERENCES loans(id) ON DELETE CASCADE,
  FOREIGN KEY (admin_id) REFERENCES admins(id) ON DELETE CASCADE
) ENGINE=InnoDB;

-- ---------- admin audit log (who did what) ----------
CREATE TABLE IF NOT EXISTS admin_audit_log (
  id INT AUTO_INCREMENT PRIMARY KEY,
  admin_id INT NULL,
  action VARCHAR(50) NOT NULL,
  target_type VARCHAR(30) NOT NULL,
  target_id VARCHAR(64) NOT NULL,
  details JSON NULL,
  ip VARCHAR(64) NULL,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  KEY idx_audit_admin (admin_id, created_at),
  KEY idx_audit_target (target_type, target_id)
) ENGINE=InnoDB;

-- ---------- verification upgrades (verified -> fully_verified) ----------
-- The account-level verification_status above is still the login gate. This
-- table only holds post-login upgrade requests; an admin decision is what
-- grants verification_level = 'fully_verified'.
CREATE TABLE IF NOT EXISTS verification_upgrades (
  id INT AUTO_INCREMENT PRIMARY KEY,
  user_id INT NOT NULL,
  status ENUM('pending','approved','rejected') NOT NULL DEFAULT 'pending',
  liveness_status ENUM('passed','skipped') NOT NULL DEFAULT 'skipped',
  face_match_confidence DOUBLE NULL,
  government_id_photo LONGTEXT NULL,
  government_id_photo_back LONGTEXT NULL,
  selfie_photo LONGTEXT NULL,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  reviewed_at TIMESTAMP NULL,
  reviewed_by INT NULL,
  KEY idx_verification_upgrades_user_status (user_id, status),
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
  FOREIGN KEY (reviewed_by) REFERENCES admins(id) ON DELETE SET NULL
) ENGINE=InnoDB;

-- ---------- fingerprint / device login tokens ----------
CREATE TABLE IF NOT EXISTS device_tokens (
  id INT AUTO_INCREMENT PRIMARY KEY,
  user_id INT NOT NULL,
  token_hash CHAR(64) NOT NULL,
  device_name VARCHAR(100) NULL,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  last_used_at TIMESTAMP NULL,
  expires_at TIMESTAMP NOT NULL,
  UNIQUE KEY uniq_device_token (token_hash),
  KEY idx_device_user (user_id),
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB;

-- ---------- login lockouts (survive server restarts) ----------
CREATE TABLE IF NOT EXISTS login_attempts (
  id INT AUTO_INCREMENT PRIMARY KEY,
  identifier VARCHAR(100) NOT NULL,
  attempted_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  KEY idx_attempts (identifier, attempted_at)
) ENGINE=InnoDB;

-- ---------- phone verification codes (sign-up SMS) ----------
CREATE TABLE IF NOT EXISTS phone_otps (
  id INT AUTO_INCREMENT PRIMARY KEY,
  phone_number VARCHAR(20) NOT NULL,
  code_hash CHAR(64) NOT NULL,
  attempts INT NOT NULL DEFAULT 0,
  expires_at DATETIME NOT NULL,
  consumed TINYINT(1) NOT NULL DEFAULT 0,
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  KEY idx_phone_otps (phone_number, created_at)
) ENGINE=InnoDB;

-- ---------- cash-in requests (simulated) ----------
-- Also created at boot by server.js. 'rejected' is set by
-- POST /api/admin/cashins/:id/respond when an admin declines a request.
CREATE TABLE IF NOT EXISTS cash_ins (
  id INT AUTO_INCREMENT PRIMARY KEY,
  user_id INT NOT NULL,
  channel VARCHAR(20) NOT NULL,
  amount BIGINT NOT NULL,
  reference VARCHAR(20) NOT NULL,
  status ENUM('pending','completed','expired','rejected') NOT NULL DEFAULT 'pending',
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  expires_at DATETIME NOT NULL,
  completed_at DATETIME NULL,
  KEY idx_cash_ins_user (user_id, created_at),
  UNIQUE KEY uniq_cash_in_ref (reference)
) ENGINE=InnoDB;

-- No admin is created here on purpose. After loading this schema run:
--   node create-admin.js <username> <password> <4-digit-pin>