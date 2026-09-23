-- Step 10A: concrete Solr action planning table.
-- MariaDB 10.1 compatible. DRY-RUN PLAN STORAGE ONLY.
-- This script does not change Solr and does not modify existing application tables.

CREATE TABLE IF NOT EXISTS `wazuh_audit_poc`.`solr_mutation_action` (
    `action_id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    `mutation_id` BIGINT UNSIGNED NOT NULL,
    `source_instance` VARCHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    `agent_id` VARCHAR(32) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    `candidate_id` VARCHAR(32) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    `worker_version` BIGINT UNSIGNED NOT NULL,
    `action_order` INT UNSIGNED NOT NULL,
    `action_type` ENUM('delete_document','index_document') NOT NULL,
    `status` ENUM('planned','processing','applied','failed','skipped') NOT NULL DEFAULT 'planned',
    `reason` VARCHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    `solr_document_id` VARCHAR(255) NOT NULL,
    `canonical_path` TEXT NOT NULL,
    `source_file_path` TEXT NULL,
    `source_file_length` BIGINT UNSIGNED NULL,
    `source_file_last_write_utc` DATETIME(6) NULL,
    `solr_last_update_utc` DATETIME(6) NULL,
    `idempotency_key` CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    `attempt_count` INT UNSIGNED NOT NULL DEFAULT 0,
    `planned_at_utc` DATETIME(6) NOT NULL,
    `updated_at_utc` DATETIME(6) NOT NULL,
    `applied_at_utc` DATETIME(6) NULL,
    `last_error` TEXT NULL,
    PRIMARY KEY (`action_id`),
    UNIQUE KEY `uq_solr_action_order` (`mutation_id`, `action_order`),
    UNIQUE KEY `uq_solr_action_idempotency` (`idempotency_key`),
    KEY `ix_solr_action_mutation_status` (`mutation_id`, `status`),
    KEY `ix_solr_action_candidate_status`
        (`source_instance`, `agent_id`, `candidate_id`, `status`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

SHOW TABLES FROM `wazuh_audit_poc` LIKE 'solr_mutation_action';

SELECT TABLE_NAME, ENGINE, TABLE_COLLATION
FROM information_schema.TABLES
WHERE TABLE_SCHEMA='wazuh_audit_poc'
  AND TABLE_NAME='solr_mutation_action';
