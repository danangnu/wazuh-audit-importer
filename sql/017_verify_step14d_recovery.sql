-- Step 14D recovery verification. READ ONLY.
-- Shows nonterminal/uncertain Solr mutation states and per-candidate queue state.
SELECT mutation_id, candidate_id, worker_version, operation, status, attempt_count,
       planned_at_utc, updated_at_utc, applied_at_utc, last_error
FROM wazuh_audit_poc.solr_mutation_queue
WHERE status IN ('planned','processing','failed')
ORDER BY candidate_id, worker_version DESC, mutation_id DESC;

SELECT a.mutation_id, a.candidate_id, a.action_order, a.action_type, a.status,
       a.attempt_count, a.applied_at_utc, a.last_error,
       p.status AS payload_status, p.block_reason
FROM wazuh_audit_poc.solr_mutation_action a
LEFT JOIN wazuh_audit_poc.solr_action_payload p ON p.action_id=a.action_id
WHERE a.status IN ('planned','processing','failed')
ORDER BY a.mutation_id, a.action_order;

SELECT candidate_id, status, event_version, completed_version, available_at_utc,
       attempt_count, last_error
FROM wazuh_audit_poc.candidate_work_queue
ORDER BY candidate_id;
