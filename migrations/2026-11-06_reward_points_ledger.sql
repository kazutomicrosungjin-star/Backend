CREATE TABLE IF NOT EXISTS reward_points_ledger (
  id BIGINT AUTO_INCREMENT PRIMARY KEY,
  user_id INT NOT NULL,
  points INT NOT NULL,
  source_type VARCHAR(20) NOT NULL,
  source_id VARCHAR(64) NOT NULL,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE KEY uq_source (source_type, source_id),
  KEY idx_user (user_id, created_at)
) ENGINE=InnoDB;
