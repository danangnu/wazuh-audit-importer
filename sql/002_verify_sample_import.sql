-- READ-ONLY verification (apart from session variables); no table/data mutations.
-- Works in an authorized SQL client connected to MGMTNB08 / 127.0.0.1:3306.
SET @source_instance = 'wazuh-lab-pilot-01';
SET @sample_event_id = '1790045703.1555358';

SELECT COUNT(*) AS matching_audit_rows
FROM wazuh_audit_poc.audit_event
WHERE source_instance = @source_instance AND wazuh_event_id = @sample_event_id;

SELECT audit_event_id, source_instance, wazuh_event_id, agent_id, agent_name,
       manager_name, candidate_id, event_type, detection_mode,
       event_time_utc, file_owner_name, actor_name, actor_process,
       reported_size_bytes, source_path
FROM wazuh_audit_poc.audit_event
WHERE source_instance = @source_instance AND wazuh_event_id = @sample_event_id;

SELECT work_item_id, source_instance, agent_id, candidate_id, candidate_folder,
       status, event_version, completed_version, last_audit_event_id,
       lease_token, lease_expires_at_utc
FROM wazuh_audit_poc.candidate_work_queue
WHERE source_instance = @source_instance AND agent_id = '001' AND candidate_id = '1180097';

SELECT COUNT(*) AS checkpoint_rows_for_this_source
FROM wazuh_audit_poc.collector_checkpoint
WHERE source_instance = @source_instance;

-- For a new empty pilot schema after one import:
-- matching_audit_rows = 1; one queue row, pending, event_version = 1;
-- actor_name/process = NULL; checkpoint_rows_for_this_source = 0.
-- After replay of THE SAME event: these values must not change.
-- Auto-increment gaps are permissible: do not use sequence continuity as the test.
