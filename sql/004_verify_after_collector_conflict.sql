-- Read-only verification after the Step 4 collector stopped on the pre-existing manual event.
SELECT COUNT(*) AS audit_event_rows
FROM wazuh_audit_poc.audit_event
WHERE source_instance='wazuh-lab-pilot-01'
  AND agent_id='001'
  AND candidate_id='1180097';

SELECT work_item_id, source_instance, agent_id, candidate_id, status,
       event_version, completed_version, last_audit_event_id,
       lease_token, lease_expires_at_utc
FROM wazuh_audit_poc.candidate_work_queue
WHERE source_instance='wazuh-lab-pilot-01'
  AND agent_id='001'
  AND candidate_id='1180097';

SELECT COUNT(*) AS checkpoint_rows
FROM wazuh_audit_poc.collector_checkpoint
WHERE source_instance='wazuh-lab-pilot-01'
  AND stream_key='flosvr01-fim-pilot';

SELECT audit_event_id, wazuh_event_id, event_type, event_time_utc, source_path
FROM wazuh_audit_poc.audit_event
WHERE source_instance='wazuh-lab-pilot-01'
  AND agent_id='001'
  AND candidate_id='1180097'
ORDER BY event_time_utc, audit_event_id;
