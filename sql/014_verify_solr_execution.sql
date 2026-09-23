-- Step 11 verification. Read-only SQL; no rows are changed.
-- Change @mutation_id if a later reviewed mutation is executed.
SET @mutation_id := 5;

SELECT mutation_id, source_instance, agent_id, candidate_id, worker_version,
       operation, status, attempt_count, planned_at_utc, updated_at_utc,
       applied_at_utc, last_error
FROM wazuh_audit_poc.solr_mutation_queue
WHERE mutation_id=@mutation_id;

SELECT a.action_id, a.action_order, a.action_type, a.status AS action_status,
       a.reason, a.solr_document_id, a.canonical_path, a.attempt_count,
       a.applied_at_utc, a.last_error,
       p.status AS payload_status, p.extractor, p.payload_sha256,
       p.source_file_sha256, p.content_sha256, p.content_char_count
FROM wazuh_audit_poc.solr_mutation_action a
LEFT JOIN wazuh_audit_poc.solr_action_payload p ON p.action_id=a.action_id
WHERE a.mutation_id=@mutation_id
ORDER BY a.action_order;
