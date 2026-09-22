-- Read-only Step 8 verification.

SELECT
    mutation_id,
    source_instance,
    agent_id,
    candidate_id,
    worker_version,
    operation,
    status,
    added_count,
    removed_count,
    changed_count,
    attempt_count,
    planned_at_utc,
    applied_at_utc,
    last_error
FROM wazuh_audit_poc.solr_mutation_queue
WHERE source_instance='wazuh-lab-pilot-01'
  AND agent_id='001'
  AND candidate_id='1180097'
ORDER BY worker_version, mutation_id;

SELECT
    candidate_id,
    status,
    event_version,
    claimed_version,
    completed_version,
    last_audit_event_id
FROM wazuh_audit_poc.candidate_work_queue
WHERE source_instance='wazuh-lab-pilot-01'
  AND agent_id='001'
  AND candidate_id='1180097';
