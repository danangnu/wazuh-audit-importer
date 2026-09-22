using System.Data;
using MySqlConnector;

namespace WazuhAuditImporter;

public static class WorkerRepository
{
    public static WorkerClaim? ClaimNext(MySqlConnection connection, ImportSettings settings)
    {
        using var tx = connection.BeginTransaction(IsolationLevel.ReadCommitted);
        try
        {
            var now = DbUtcNow(connection, tx);
            var placeholders = settings.CandidateIds
                .Select((_, i) => "@candidate" + i)
                .ToArray();
            var sql = $"""
                SELECT work_item_id, source_instance, agent_id, candidate_id, candidate_folder,
                       event_version, completed_version, attempt_count
                FROM wazuh_audit_poc.candidate_work_queue
                WHERE source_instance=@source
                  AND agent_id=@agent
                  AND candidate_id IN ({string.Join(",", placeholders)})
                  AND (
                       (status IN ('pending','retry') AND available_at_utc <= @now)
                       OR
                       (status='processing' AND lease_expires_at_utc IS NOT NULL
                                            AND lease_expires_at_utc <= @now)
                  )
                ORDER BY available_at_utc, work_item_id
                LIMIT 1
                FOR UPDATE;
                """;

            ulong workItemId;
            string source, agentId, candidateId, candidateFolder;
            ulong eventVersion, completedVersion;
            uint attemptCount;
            using (var select = new MySqlCommand(sql, connection, tx))
            {
                select.Parameters.AddWithValue("@source", settings.SourceInstance);
                select.Parameters.AddWithValue("@agent", settings.AgentId);
                select.Parameters.AddWithValue("@now", now);
                for (var i = 0; i < settings.CandidateIds.Length; i++)
                    select.Parameters.AddWithValue("@candidate" + i, settings.CandidateIds[i]);

                using var reader = select.ExecuteReader();
                if (!reader.Read())
                {
                    tx.Commit();
                    return null;
                }
                workItemId = reader.GetUInt64(0);
                source = reader.GetString(1);
                agentId = reader.GetString(2);
                candidateId = reader.GetString(3);
                candidateFolder = reader.GetString(4);
                eventVersion = reader.GetUInt64(5);
                completedVersion = reader.GetUInt64(6);
                attemptCount = reader.GetUInt32(7);
            }

            var expectedFolder = settings.CandidateRoot + "\\" + candidateId;
            if (!candidateFolder.Equals(expectedFolder, StringComparison.OrdinalIgnoreCase))
                throw new EventConflictException(
                    $"Queue source folder '{candidateFolder}' does not match configured source folder '{expectedFolder}'.");
            if (eventVersion <= completedVersion)
                throw new EventConflictException(
                    $"Due queue row has event_version={eventVersion} but completed_version={completedVersion}.");

            var token = Guid.NewGuid().ToString("D");
            var leaseExpires = now.AddSeconds(settings.WorkerLeaseSeconds);
            using (var update = new MySqlCommand("""
                UPDATE wazuh_audit_poc.candidate_work_queue
                SET status='processing',
                    claimed_version=event_version,
                    attempt_count=attempt_count+1,
                    lease_token=@token,
                    lease_expires_at_utc=@lease_expires,
                    updated_at_utc=@now,
                    last_error=NULL
                WHERE work_item_id=@id;
                """, connection, tx))
            {
                update.Parameters.AddWithValue("@token", token);
                update.Parameters.AddWithValue("@lease_expires", leaseExpires);
                update.Parameters.AddWithValue("@now", now);
                update.Parameters.AddWithValue("@id", workItemId);
                if (update.ExecuteNonQuery() != 1)
                    throw new EventConflictException("Failed to claim the selected queue row.");
            }

            tx.Commit();
            return new WorkerClaim(
                workItemId, source, agentId, candidateId, candidateFolder,
                eventVersion, eventVersion, completedVersion, checked(attemptCount + 1),
                token, leaseExpires);
        }
        catch
        {
            try { tx.Rollback(); } catch { }
            throw;
        }
    }

    public static WorkerCompletion Complete(MySqlConnection connection, WorkerClaim claim)
    {
        using var tx = connection.BeginTransaction(IsolationLevel.ReadCommitted);
        try
        {
            var now = DbUtcNow(connection, tx);
            string status, token;
            ulong eventVersion, completedVersion;
            ulong? claimedVersion;
            using (var select = new MySqlCommand("""
                SELECT status, event_version, claimed_version, completed_version, lease_token
                FROM wazuh_audit_poc.candidate_work_queue
                WHERE work_item_id=@id
                FOR UPDATE;
                """, connection, tx))
            {
                select.Parameters.AddWithValue("@id", claim.WorkItemId);
                using var reader = select.ExecuteReader();
                if (!reader.Read())
                    throw new EventConflictException("Claimed queue row no longer exists.");
                status = reader.GetString(0);
                eventVersion = reader.GetUInt64(1);
                claimedVersion = reader.IsDBNull(2) ? null : reader.GetUInt64(2);
                completedVersion = reader.GetUInt64(3);
                token = ReadLeaseToken(reader, 4);
            }

            if (status != "processing" || token != claim.LeaseToken || claimedVersion != claim.ClaimedVersion)
                throw new EventConflictException("Worker lease was lost or replaced; completion was refused.");

            var newCompleted = Math.Max(completedVersion, claim.ClaimedVersion);
            var newStatus = eventVersion > claim.ClaimedVersion ? "pending" : "completed";
            using (var update = new MySqlCommand("""
                UPDATE wazuh_audit_poc.candidate_work_queue
                SET status=@status,
                    completed_version=@completed,
                    available_at_utc=@now,
                    claimed_version=NULL,
                    lease_token=NULL,
                    lease_expires_at_utc=NULL,
                    updated_at_utc=@now,
                    last_error=NULL
                WHERE work_item_id=@id
                  AND status='processing'
                  AND lease_token=@token;
                """, connection, tx))
            {
                update.Parameters.AddWithValue("@status", newStatus);
                update.Parameters.AddWithValue("@completed", newCompleted);
                update.Parameters.AddWithValue("@now", now);
                update.Parameters.AddWithValue("@id", claim.WorkItemId);
                update.Parameters.AddWithValue("@token", claim.LeaseToken);
                if (update.ExecuteNonQuery() != 1)
                    throw new EventConflictException("Worker lease changed during completion.");
            }

            tx.Commit();
            return new WorkerCompletion(
                claim.WorkItemId, claim.CandidateId, newStatus, eventVersion, newCompleted);
        }
        catch
        {
            try { tx.Rollback(); } catch { }
            throw;
        }
    }

    public static bool Fail(MySqlConnection connection, WorkerClaim claim, ImportSettings settings, string error)
    {
        var cleanError = (error ?? "Worker failed.").Replace("\0", string.Empty);
        if (cleanError.Length > 16000) cleanError = cleanError[..16000];

        using var tx = connection.BeginTransaction(IsolationLevel.ReadCommitted);
        try
        {
            var now = DbUtcNow(connection, tx);
            var available = now.AddSeconds(settings.WorkerRetrySeconds);
            using var update = new MySqlCommand("""
                UPDATE wazuh_audit_poc.candidate_work_queue
                SET status='retry',
                    available_at_utc=@available,
                    claimed_version=NULL,
                    lease_token=NULL,
                    lease_expires_at_utc=NULL,
                    updated_at_utc=@now,
                    last_error=@error
                WHERE work_item_id=@id
                  AND status='processing'
                  AND lease_token=@token;
                """, connection, tx);
            update.Parameters.AddWithValue("@available", available);
            update.Parameters.AddWithValue("@now", now);
            update.Parameters.AddWithValue("@error", cleanError);
            update.Parameters.AddWithValue("@id", claim.WorkItemId);
            update.Parameters.AddWithValue("@token", claim.LeaseToken);
            var changed = update.ExecuteNonQuery() == 1;
            tx.Commit();
            return changed;
        }
        catch
        {
            try { tx.Rollback(); } catch { }
            throw;
        }
    }

    private static string ReadLeaseToken(MySqlDataReader reader, int ordinal)
    {
        if (reader.IsDBNull(ordinal)) return string.Empty;

        // MySqlConnector can materialize CHAR(36) values that look like UUIDs
        // as System.Guid depending on its GuidFormat/connection behavior. The
        // schema deliberately stores lease_token as CHAR(36), so accept both
        // representations and normalize to the canonical D string before the
        // compare-and-set completion check.
        return reader.GetValue(ordinal) switch
        {
            string value => value,
            Guid value => value.ToString("D"),
            var value => throw new InvalidDataException(
                $"Unexpected lease_token database type: {value.GetType().FullName}.")
        };
    }

    private static DateTime DbUtcNow(MySqlConnection connection, MySqlTransaction tx)
    {
        using var clock = new MySqlCommand("SELECT UTC_TIMESTAMP(6);", connection, tx);
        return DateTime.SpecifyKind(Convert.ToDateTime(clock.ExecuteScalar()), DateTimeKind.Utc);
    }
}
