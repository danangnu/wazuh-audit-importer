using System.Data;
using MySqlConnector;

namespace WazuhAuditImporter;

public static class BaselineEnrollmentRepository
{
    public static BaselineEnrollmentSnapshot? Read(
        MySqlConnection connection,
        ImportSettings settings,
        string candidateId)
    {
        using var cmd = new MySqlCommand("""
            SELECT enrollment_id, candidate_id, status, baseline_sha256,
                   disk_file_count, eligible_file_count, skipped_file_count,
                   solr_document_count, match_count, missing_count, stale_count,
                   other_conflict_count, captured_at_utc, approved_at_utc,
                   approved_by, approval_note
            FROM wazuh_audit_poc.candidate_baseline_enrollment
            WHERE source_instance=@source AND agent_id=@agent AND candidate_id=@candidate
            LIMIT 1;
            """, connection);
        cmd.Parameters.AddWithValue("@source", settings.SourceInstance);
        cmd.Parameters.AddWithValue("@agent", settings.AgentId);
        cmd.Parameters.AddWithValue("@candidate", candidateId);
        using var reader = cmd.ExecuteReader();
        if (!reader.Read()) return null;
        return ReadSnapshot(reader);
    }

    public static BaselineEnrollmentSnapshot UpsertPending(
        MySqlConnection connection,
        ImportSettings settings,
        BaselineEnrollmentCapture capture)
    {
        using var tx = connection.BeginTransaction(IsolationLevel.ReadCommitted);
        try
        {
            var candidateId = capture.Evidence.CandidateId;
            ulong? enrollmentId = null;
            string? status = null;
            using (var select = new MySqlCommand("""
                SELECT enrollment_id, status
                FROM wazuh_audit_poc.candidate_baseline_enrollment
                WHERE source_instance=@source AND agent_id=@agent AND candidate_id=@candidate
                FOR UPDATE;
                """, connection, tx))
            {
                select.Parameters.AddWithValue("@source", settings.SourceInstance);
                select.Parameters.AddWithValue("@agent", settings.AgentId);
                select.Parameters.AddWithValue("@candidate", candidateId);
                using var reader = select.ExecuteReader();
                if (reader.Read())
                {
                    enrollmentId = reader.GetUInt64(0);
                    status = reader.GetString(1);
                }
            }

            if (status == BaselineEnrollmentPolicy.Approved)
                throw new EventConflictException($"Candidate {candidateId} baseline is already approved; approved evidence cannot be silently replaced.");

            var now = DbUtcNow(connection, tx);
            if (enrollmentId is null)
            {
                using var insert = new MySqlCommand("""
                    INSERT INTO wazuh_audit_poc.candidate_baseline_enrollment
                    (source_instance, agent_id, candidate_id, status, baseline_sha256,
                     disk_file_count, eligible_file_count, skipped_file_count,
                     solr_document_count, match_count, missing_count, stale_count,
                     other_conflict_count, baseline_json, captured_at_utc, updated_at_utc,
                     approved_at_utc, approved_by, approval_note)
                    VALUES
                    (@source,@agent,@candidate,'pending',@sha,
                     @disk,@eligible,@skipped,@solr,@match,@missing,@stale,@other,@json,@captured,@now,
                     NULL,NULL,NULL);
                    """, connection, tx);
                AddCaptureParameters(insert, settings, capture, now);
                insert.ExecuteNonQuery();
                enrollmentId = insert.LastInsertedId > 0 ? (ulong)insert.LastInsertedId : null;
                if (enrollmentId is null) throw new InvalidOperationException("Baseline enrollment insert did not return an identity.");
            }
            else
            {
                using var update = new MySqlCommand("""
                    UPDATE wazuh_audit_poc.candidate_baseline_enrollment
                    SET status='pending', baseline_sha256=@sha,
                        disk_file_count=@disk, eligible_file_count=@eligible, skipped_file_count=@skipped,
                        solr_document_count=@solr, match_count=@match, missing_count=@missing,
                        stale_count=@stale, other_conflict_count=@other,
                        baseline_json=@json, captured_at_utc=@captured, updated_at_utc=@now,
                        approved_at_utc=NULL, approved_by=NULL, approval_note=NULL
                    WHERE enrollment_id=@id AND status='pending';
                    """, connection, tx);
                AddCaptureParameters(update, settings, capture, now);
                update.Parameters.AddWithValue("@id", enrollmentId.Value);
                if (update.ExecuteNonQuery() != 1)
                    throw new EventConflictException("Baseline enrollment state changed before refresh.");
            }

            InsertHistory(connection, tx, enrollmentId!.Value, settings, candidateId,
                "captured", capture.BaselineSha256, capture.BaselineJson, null, now);
            tx.Commit();
            return Read(connection, settings, candidateId)
                   ?? throw new InvalidOperationException("Baseline enrollment disappeared after capture.");
        }
        catch
        {
            try { tx.Rollback(); } catch { }
            throw;
        }
    }

    public static BaselineEnrollmentSnapshot Approve(
        MySqlConnection connection,
        ImportSettings settings,
        string candidateId,
        string baselineSha256,
        string reviewer,
        string? note)
    {
        reviewer = CleanText(reviewer, 191, "reviewer");
        note = string.IsNullOrWhiteSpace(note) ? null : CleanText(note, 1000, "approval note");
        using var tx = connection.BeginTransaction(IsolationLevel.ReadCommitted);
        try
        {
            ulong enrollmentId;
            string status;
            string currentSha;
            string baselineJson;
            using (var select = new MySqlCommand("""
                SELECT enrollment_id, status, baseline_sha256, baseline_json
                FROM wazuh_audit_poc.candidate_baseline_enrollment
                WHERE source_instance=@source AND agent_id=@agent AND candidate_id=@candidate
                FOR UPDATE;
                """, connection, tx))
            {
                select.Parameters.AddWithValue("@source", settings.SourceInstance);
                select.Parameters.AddWithValue("@agent", settings.AgentId);
                select.Parameters.AddWithValue("@candidate", candidateId);
                using var reader = select.ExecuteReader();
                if (!reader.Read()) throw new InvalidOperationException($"Candidate {candidateId} has no captured baseline.");
                enrollmentId = reader.GetUInt64(0);
                status = reader.GetString(1);
                currentSha = reader.GetString(2);
                baselineJson = reader.GetString(3);
            }

            BaselineEnrollmentPolicy.ValidateApprovalToken(currentSha, baselineSha256);
            if (status == BaselineEnrollmentPolicy.Approved)
            {
                tx.Commit();
                return Read(connection, settings, candidateId)
                       ?? throw new InvalidOperationException("Baseline enrollment disappeared after approval read.");
            }
            if (status != BaselineEnrollmentPolicy.Pending)
                throw new EventConflictException($"Unsupported baseline enrollment status '{status}'.");

            var now = DbUtcNow(connection, tx);
            using var update = new MySqlCommand("""
                UPDATE wazuh_audit_poc.candidate_baseline_enrollment
                SET status='approved', approved_at_utc=@now, approved_by=@reviewer,
                    approval_note=@note, updated_at_utc=@now
                WHERE enrollment_id=@id AND status='pending' AND baseline_sha256=@sha;
                """, connection, tx);
            update.Parameters.AddWithValue("@now", now);
            update.Parameters.AddWithValue("@reviewer", reviewer);
            update.Parameters.AddWithValue("@note", (object?)note ?? DBNull.Value);
            update.Parameters.AddWithValue("@id", enrollmentId);
            update.Parameters.AddWithValue("@sha", currentSha);
            if (update.ExecuteNonQuery() != 1)
                throw new EventConflictException("Baseline enrollment changed before approval could be recorded.");

            InsertHistory(connection, tx, enrollmentId, settings, candidateId,
                "approved", currentSha, baselineJson, reviewer, now);
            tx.Commit();
            return Read(connection, settings, candidateId)
                   ?? throw new InvalidOperationException("Baseline enrollment disappeared after approval.");
        }
        catch
        {
            try { tx.Rollback(); } catch { }
            throw;
        }
    }

    private static BaselineEnrollmentSnapshot ReadSnapshot(MySqlDataReader reader) => new(
        reader.GetUInt64(0),
        reader.GetString(1),
        reader.GetString(2),
        reader.GetString(3),
        Convert.ToInt32(reader.GetValue(4), System.Globalization.CultureInfo.InvariantCulture),
        Convert.ToInt32(reader.GetValue(5), System.Globalization.CultureInfo.InvariantCulture),
        Convert.ToInt32(reader.GetValue(6), System.Globalization.CultureInfo.InvariantCulture),
        Convert.ToInt32(reader.GetValue(7), System.Globalization.CultureInfo.InvariantCulture),
        Convert.ToInt32(reader.GetValue(8), System.Globalization.CultureInfo.InvariantCulture),
        Convert.ToInt32(reader.GetValue(9), System.Globalization.CultureInfo.InvariantCulture),
        Convert.ToInt32(reader.GetValue(10), System.Globalization.CultureInfo.InvariantCulture),
        Convert.ToInt32(reader.GetValue(11), System.Globalization.CultureInfo.InvariantCulture),
        DateTime.SpecifyKind(reader.GetDateTime(12), DateTimeKind.Utc),
        reader.IsDBNull(13) ? null : DateTime.SpecifyKind(reader.GetDateTime(13), DateTimeKind.Utc),
        reader.IsDBNull(14) ? null : reader.GetString(14),
        reader.IsDBNull(15) ? null : reader.GetString(15));

    private static void AddCaptureParameters(MySqlCommand cmd, ImportSettings settings,
        BaselineEnrollmentCapture capture, DateTime now)
    {
        var e = capture.Evidence;
        cmd.Parameters.AddWithValue("@source", settings.SourceInstance);
        cmd.Parameters.AddWithValue("@agent", settings.AgentId);
        cmd.Parameters.AddWithValue("@candidate", e.CandidateId);
        cmd.Parameters.AddWithValue("@sha", capture.BaselineSha256);
        cmd.Parameters.AddWithValue("@disk", e.DiskFileCount);
        cmd.Parameters.AddWithValue("@eligible", e.EligibleFileCount);
        cmd.Parameters.AddWithValue("@skipped", e.SkippedFileCount);
        cmd.Parameters.AddWithValue("@solr", e.SolrDocumentCount);
        cmd.Parameters.AddWithValue("@match", e.MatchCount);
        cmd.Parameters.AddWithValue("@missing", e.MissingCount);
        cmd.Parameters.AddWithValue("@stale", e.StaleCount);
        cmd.Parameters.AddWithValue("@other", e.OtherConflictCount);
        cmd.Parameters.AddWithValue("@json", capture.BaselineJson);
        cmd.Parameters.AddWithValue("@captured", capture.CapturedAtUtc);
        cmd.Parameters.AddWithValue("@now", now);
    }

    private static void InsertHistory(MySqlConnection connection, MySqlTransaction tx,
        ulong enrollmentId, ImportSettings settings, string candidateId, string eventType,
        string baselineSha256, string detailJson, string? actor, DateTime now)
    {
        using var cmd = new MySqlCommand("""
            INSERT INTO wazuh_audit_poc.candidate_baseline_enrollment_history
            (enrollment_id, source_instance, agent_id, candidate_id, event_type,
             baseline_sha256, detail_json, actor, event_at_utc)
            VALUES (@enrollment,@source,@agent,@candidate,@event,@sha,@detail,@actor,@now);
            """, connection, tx);
        cmd.Parameters.AddWithValue("@enrollment", enrollmentId);
        cmd.Parameters.AddWithValue("@source", settings.SourceInstance);
        cmd.Parameters.AddWithValue("@agent", settings.AgentId);
        cmd.Parameters.AddWithValue("@candidate", candidateId);
        cmd.Parameters.AddWithValue("@event", eventType);
        cmd.Parameters.AddWithValue("@sha", baselineSha256);
        cmd.Parameters.AddWithValue("@detail", detailJson);
        cmd.Parameters.AddWithValue("@actor", (object?)actor ?? DBNull.Value);
        cmd.Parameters.AddWithValue("@now", now);
        cmd.ExecuteNonQuery();
    }

    private static string CleanText(string value, int max, string label)
    {
        value = (value ?? string.Empty).Replace("\0", string.Empty).Trim();
        if (value.Length == 0) throw new FormatException($"{label} is required.");
        if (value.Length > max) throw new FormatException($"{label} exceeds {max} characters.");
        return value;
    }

    private static DateTime DbUtcNow(MySqlConnection connection, MySqlTransaction tx)
    {
        using var cmd = new MySqlCommand("SELECT UTC_TIMESTAMP(6);", connection, tx);
        var value = cmd.ExecuteScalar() ?? throw new InvalidOperationException("Database UTC clock was unavailable.");
        return DateTime.SpecifyKind(Convert.ToDateTime(value, System.Globalization.CultureInfo.InvariantCulture), DateTimeKind.Utc);
    }
}
