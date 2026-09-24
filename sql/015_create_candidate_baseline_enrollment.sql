-- Step 14C: candidate baseline enrollment / review gate.
-- MariaDB 10.1 compatible. This migration adds review-state tables only.
-- It does NOT modify candidate application tables and does NOT call Solr.

CREATE TABLE IF NOT EXISTS `wazuh_audit_poc`.`candidate_baseline_enrollment` (
    `enrollment_id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    `source_instance` VARCHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    `agent_id` VARCHAR(32) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    `candidate_id` VARCHAR(32) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    `status` ENUM('pending','approved') NOT NULL,
    `baseline_sha256` CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    `disk_file_count` INT UNSIGNED NOT NULL,
    `eligible_file_count` INT UNSIGNED NOT NULL,
    `skipped_file_count` INT UNSIGNED NOT NULL,
    `solr_document_count` INT UNSIGNED NOT NULL,
    `match_count` INT UNSIGNED NOT NULL,
    `missing_count` INT UNSIGNED NOT NULL,
    `stale_count` INT UNSIGNED NOT NULL,
    `other_conflict_count` INT UNSIGNED NOT NULL,
    `baseline_json` LONGTEXT NOT NULL,
    `captured_at_utc` DATETIME(6) NOT NULL,
    `updated_at_utc` DATETIME(6) NOT NULL,
    `approved_at_utc` DATETIME(6) NULL,
    `approved_by` VARCHAR(191) NULL,
    `approval_note` VARCHAR(1000) NULL,
    PRIMARY KEY (`enrollment_id`),
    UNIQUE KEY `uq_candidate_baseline_identity`
        (`source_instance`, `agent_id`, `candidate_id`),
    KEY `ix_candidate_baseline_status` (`status`, `updated_at_utc`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS `wazuh_audit_poc`.`candidate_baseline_enrollment_history` (
    `history_id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    `enrollment_id` BIGINT UNSIGNED NOT NULL,
    `source_instance` VARCHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    `agent_id` VARCHAR(32) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    `candidate_id` VARCHAR(32) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    `event_type` ENUM('captured','approved') NOT NULL,
    `baseline_sha256` CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    `detail_json` LONGTEXT NOT NULL,
    `actor` VARCHAR(191) NULL,
    `event_at_utc` DATETIME(6) NOT NULL,
    PRIMARY KEY (`history_id`),
    KEY `ix_candidate_baseline_history_candidate`
        (`source_instance`, `agent_id`, `candidate_id`, `event_at_utc`),
    KEY `ix_candidate_baseline_history_enrollment`
        (`enrollment_id`, `event_at_utc`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

SHOW TABLES FROM `wazuh_audit_poc` LIKE 'candidate_baseline_enrollment%';
