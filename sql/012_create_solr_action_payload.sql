-- Step 10B: reviewed dry-run Solr payload storage.
-- MariaDB 10.1 compatible. This table stores payloads only; it does not execute Solr.

CREATE TABLE IF NOT EXISTS `wazuh_audit_poc`.`solr_action_payload` (
    `payload_id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    `action_id` BIGINT UNSIGNED NOT NULL,
    `mutation_id` BIGINT UNSIGNED NOT NULL,
    `action_type` ENUM('delete_document','index_document') NOT NULL,
    `status` ENUM('ready','blocked') NOT NULL,
    `extractor` VARCHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    `payload_json` LONGTEXT NULL,
    `payload_sha256` CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NULL,
    `source_file_sha256` CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NULL,
    `content_sha256` CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NULL,
    `content_char_count` BIGINT UNSIGNED NULL,
    `source_file_length` BIGINT UNSIGNED NULL,
    `source_file_last_write_utc` DATETIME(6) NULL,
    `block_reason` VARCHAR(191) NULL,
    `generated_at_utc` DATETIME(6) NOT NULL,
    PRIMARY KEY (`payload_id`),
    UNIQUE KEY `uq_solr_payload_action` (`action_id`),
    KEY `ix_solr_payload_mutation_status` (`mutation_id`, `status`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

SHOW TABLES FROM `wazuh_audit_poc` LIKE 'solr_action_payload';

SELECT TABLE_NAME, ENGINE, TABLE_COLLATION
FROM information_schema.TABLES
WHERE TABLE_SCHEMA='wazuh_audit_poc'
  AND TABLE_NAME='solr_action_payload';
