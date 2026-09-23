-- Step 10B verification. Read-only.
SELECT p.payload_id, p.action_id, p.mutation_id, p.action_type, p.status,
       p.extractor, p.payload_sha256, p.source_file_sha256,
       p.content_sha256, p.content_char_count, p.source_file_length,
       p.source_file_last_write_utc, p.block_reason, p.generated_at_utc,
       a.action_order, a.solr_document_id, a.canonical_path, a.source_file_path
FROM wazuh_audit_poc.solr_action_payload p
JOIN wazuh_audit_poc.solr_mutation_action a ON a.action_id=p.action_id
WHERE p.mutation_id=(SELECT MAX(mutation_id) FROM wazuh_audit_poc.solr_mutation_queue
                     WHERE source_instance='wazuh-lab-pilot-01'
                       AND agent_id='001' AND candidate_id='1180097')
ORDER BY a.action_order;

SELECT status, COUNT(*) AS rows_count
FROM wazuh_audit_poc.solr_action_payload
GROUP BY status
ORDER BY status;
