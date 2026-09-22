-- Step 6 worker verification. Read-only.
SELECT work_item_id, source_instance, agent_id, candidate_id, candidate_folder,
       status, event_version, claimed_version, completed_version, attempt_count,
       last_audit_event_id, available_at_utc, lease_token, lease_expires_at_utc,
       last_error, created_at_utc, updated_at_utc
FROM wazuh_audit_poc.candidate_work_queue
WHERE source_instance='wazuh-lab-pilot-01'
  AND agent_id='001'
  AND candidate_id='1180097';

SELECT COUNT(*) AS audit_event_count,
       MIN(event_time_utc) AS first_event_utc,
       MAX(event_time_utc) AS last_event_utc
FROM wazuh_audit_poc.audit_event
WHERE source_instance='wazuh-lab-pilot-01'
  AND agent_id='001'
  AND candidate_id='1180097';
