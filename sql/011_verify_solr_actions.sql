-- Read-only verification for Step 10A.
SELECT
    a.action_id,
    a.mutation_id,
    a.candidate_id,
    a.worker_version,
    a.action_order,
    a.action_type,
    a.status,
    a.reason,
    a.solr_document_id,
    a.canonical_path,
    a.source_file_path,
    a.source_file_length,
    a.source_file_last_write_utc,
    a.solr_last_update_utc,
    a.attempt_count,
    a.planned_at_utc,
    a.applied_at_utc,
    a.last_error
FROM wazuh_audit_poc.solr_mutation_action a
WHERE a.source_instance='wazuh-lab-pilot-01'
  AND a.agent_id='001'
  AND a.candidate_id='1180097'
ORDER BY a.mutation_id, a.action_order;

SELECT
    mutation_id,
    COUNT(*) AS action_count,
    SUM(action_type='delete_document') AS delete_count,
    SUM(action_type='index_document') AS index_count,
    SUM(status='planned') AS planned_count,
    SUM(status='applied') AS applied_count
FROM wazuh_audit_poc.solr_mutation_action
WHERE source_instance='wazuh-lab-pilot-01'
  AND agent_id='001'
  AND candidate_id='1180097'
GROUP BY mutation_id
ORDER BY mutation_id;
