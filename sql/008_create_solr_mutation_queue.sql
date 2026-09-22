-- Step 8: dry-run Solr mutation planning table.
-- MariaDB 10.1 compatible. No existing audit rows or candidate queue rows are changed.
-- This table records proposed Solr work only; there is no Solr executor in Step 8.

CREATE TABLE IF NOT EXISTS `wazuh_audit_poc`.`solr_mutation_queue` (
    `mutation_id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    `source_instance` VARCHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    `agent_id` VARCHAR(32) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    `candidate_id` VARCHAR(32) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    `worker_version` BIGINT UNSIGNED NOT NULL,
    `operation` ENUM('reindex_candidate','none') NOT NULL,
    `status` ENUM('planned','not_required','processing','applied','failed','skipped') NOT NULL,
    `added_count` INT UNSIGNED NOT NULL DEFAULT 0,
    `removed_count` INT UNSIGNED NOT NULL DEFAULT 0,
    `changed_count` INT UNSIGNED NOT NULL DEFAULT 0,
    `plan_json` LONGTEXT NOT NULL,
    `idempotency_key` CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    `attempt_count` INT UNSIGNED NOT NULL DEFAULT 0,
    `planned_at_utc` DATETIME(6) NOT NULL,
    `updated_at_utc` DATETIME(6) NOT NULL,
    `applied_at_utc` DATETIME(6) NULL,
    `last_error` TEXT NULL,
    PRIMARY KEY (`mutation_id`),
    UNIQUE KEY `uq_solr_plan_version`
        (`source_instance`, `agent_id`, `candidate_id`, `worker_version`),
    UNIQUE KEY `uq_solr_plan_idempotency` (`idempotency_key`),
    KEY `ix_solr_plan_status` (`status`, `planned_at_utc`),
    KEY `ix_solr_plan_candidate`
        (`source_instance`, `agent_id`, `candidate_id`, `worker_version`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

SHOW TABLES FROM `wazuh_audit_poc` LIKE 'solr_mutation_queue';

SELECT TABLE_NAME, ENGINE, TABLE_COLLATION
FROM information_schema.TABLES
WHERE TABLE_SCHEMA='wazuh_audit_poc'
  AND TABLE_NAME='solr_mutation_queue';
