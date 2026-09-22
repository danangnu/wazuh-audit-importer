-- Step 5 read-only verification. No writes.
SELECT COUNT(*) AS scoped_audit_events
FROM wazuh_audit_poc.audit_event
WHERE source_instance='wazuh-lab-pilot-01'
  AND agent_id='001'
  AND candidate_id='1180097';

SELECT work_item_id, candidate_id, status, event_version, completed_version,
       last_audit_event_id, updated_at_utc
FROM wazuh_audit_poc.candidate_work_queue
WHERE source_instance='wazuh-lab-pilot-01'
  AND agent_id='001'
  AND candidate_id='1180097';

SELECT source_instance, stream_key, input_kind, input_location,
       last_wazuh_event_id, updated_at_utc, cursor_text
FROM wazuh_audit_poc.collector_checkpoint
WHERE source_instance='wazuh-lab-pilot-01'
  AND stream_key='flosvr01-fim-pilot';
