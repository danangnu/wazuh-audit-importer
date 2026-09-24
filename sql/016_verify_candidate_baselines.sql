SELECT
    candidate_id,
    status,
    baseline_sha256,
    disk_file_count,
    eligible_file_count,
    skipped_file_count,
    solr_document_count,
    match_count,
    missing_count,
    stale_count,
    other_conflict_count,
    captured_at_utc,
    approved_at_utc,
    approved_by,
    approval_note
FROM wazuh_audit_poc.candidate_baseline_enrollment
ORDER BY candidate_id;

SELECT
    history_id,
    candidate_id,
    event_type,
    baseline_sha256,
    actor,
    event_at_utc
FROM wazuh_audit_poc.candidate_baseline_enrollment_history
ORDER BY history_id;
