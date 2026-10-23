-- Additive verification-level migration.
-- Run this manually, once, on the live Railway MySQL BEFORE deploying the
-- server code that reads/writes these columns. It is not run by setup-db.js.
-- Existing users become 'verified' (never 'fully_verified') and 'not_done'.

ALTER TABLE users
  ADD COLUMN verification_level ENUM('verified','fully_verified') NOT NULL DEFAULT 'verified',
  ADD COLUMN liveness_status ENUM('not_done','passed','skipped') NOT NULL DEFAULT 'not_done';

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
