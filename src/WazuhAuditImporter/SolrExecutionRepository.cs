using System.Data;
using MySqlConnector;

namespace WazuhAuditImporter;

public static class SolrExecutionRepository
{
    public static SolrMutationTarget ReadTarget(MySqlConnection connection, ImportSettings settings, ulong mutationId)
    {
        using var cmd = new MySqlCommand("""
            SELECT m.mutation_id, m.source_instance, m.agent_id, m.candidate_id,
                   m.worker_version, m.operation, m.status,
                   q.status, q.event_version, q.completed_version
            FROM wazuh_audit_poc.solr_mutation_queue m
            INNER JOIN wazuh_audit_poc.candidate_work_queue q
               ON q.source_instance=m.source_instance
              AND q.agent_id=m.agent_id
              AND q.candidate_id=m.candidate_id
            WHERE m.mutation_id=@mutation
            LIMIT 1;
            """, connection);
        cmd.Parameters.AddWithValue("@mutation", mutationId);
        using var reader = cmd.ExecuteReader();
        if (!reader.Read())
            throw new SolrExecutionException($"Mutation {mutationId} was not found.");
        var target = new SolrMutationTarget(
            reader.GetUInt64(0), reader.GetString(1), reader.GetString(2), reader.GetString(3),
            reader.GetUInt64(4), reader.GetString(5), reader.GetString(6), reader.GetString(7),
            reader.GetUInt64(8), reader.GetUInt64(9));
        ValidateTarget(target, settings);
        return target;
    }

    public static IReadOnlyList<SolrExecutionItem> ReadItems(MySqlConnection connection, SolrMutationTarget target)
    {
        using var cmd = new MySqlCommand("""
            SELECT a.action_id, a.mutation_id, a.source_instance, a.agent_id, a.candidate_id, a.worker_version,
                   a.action_order, a.action_type, a.status, a.reason, a.solr_document_id, a.canonical_path,
                   a.source_file_path, a.source_file_length, a.source_file_last_write_utc, a.idempotency_key,
                   p.action_id, p.mutation_id, p.action_type, p.status, p.extractor, p.payload_json,
                   p.payload_sha256, p.source_file_sha256, p.content_sha256, p.content_char_count,
                   p.source_file_length, p.source_file_last_write_utc, p.block_reason, p.generated_at_utc
            FROM wazuh_audit_poc.solr_mutation_action a
            LEFT JOIN wazuh_audit_poc.solr_action_payload p ON p.action_id=a.action_id
            WHERE a.mutation_id=@mutation
            ORDER BY a.action_order;
            """, connection);
        cmd.Parameters.AddWithValue("@mutation", target.MutationId);
        var result = new List<SolrExecutionItem>();
        using var reader = cmd.ExecuteReader();
        while (reader.Read())
        {
            if (reader.IsDBNull(16))
                throw new SolrExecutionException($"Action {reader.GetUInt64(0)} has no Step 10B payload.");
            var action = new SolrStoredAction(
                reader.GetUInt64(0), reader.GetUInt64(1), reader.GetString(2), reader.GetString(3), reader.GetString(4),
                reader.GetUInt64(5), Convert.ToInt32(reader.GetValue(6)), reader.GetString(7), reader.GetString(8),
                reader.GetString(9), reader.GetString(10), reader.GetString(11), reader.IsDBNull(12) ? null : reader.GetString(12),
                reader.IsDBNull(13) ? null : Convert.ToUInt64(reader.GetValue(13)),
                reader.IsDBNull(14) ? null : DateTime.SpecifyKind(reader.GetDateTime(14), DateTimeKind.Utc),
                reader.GetString(15));
            var payload = new SolrPayloadSpec(
                reader.GetUInt64(16), reader.GetUInt64(17), reader.GetString(18), reader.GetString(19), reader.GetString(20),
                reader.IsDBNull(21) ? null : reader.GetString(21), reader.IsDBNull(22) ? null : reader.GetString(22),
                reader.IsDBNull(23) ? null : reader.GetString(23), reader.IsDBNull(24) ? null : reader.GetString(24),
                reader.IsDBNull(25) ? null : Convert.ToUInt64(reader.GetValue(25)),
                reader.IsDBNull(26) ? null : Convert.ToUInt64(reader.GetValue(26)),
                reader.IsDBNull(27) ? null : DateTime.SpecifyKind(reader.GetDateTime(27), DateTimeKind.Utc),
                reader.IsDBNull(28) ? null : reader.GetString(28),
                DateTime.SpecifyKind(reader.GetDateTime(29), DateTimeKind.Utc));
            var item = new SolrExecutionItem(action, payload);
            SolrExecutionSafety.ValidateReadyItem(item);
            result.Add(item);
        }
        if (result.Count == 0)
            throw new SolrExecutionException("Mutation has no concrete actions to execute.");
        if (!result.Select(x => x.Action.ActionOrder).SequenceEqual(Enumerable.Range(1, result.Count)))
            throw new SolrExecutionException("Concrete action order is not contiguous starting at 1.");
        if (result.Any(x => x.Action.MutationId != target.MutationId || x.Action.CandidateId != target.CandidateId ||
                            x.Action.WorkerVersion != target.WorkerVersion))
            throw new SolrExecutionException("Concrete action identity does not match the selected mutation.");
        return result;
    }

    public static void BeginExecution(MySqlConnection connection, ImportSettings settings,
        SolrMutationTarget target, int expectedActionCount)
    {
        using var tx = connection.BeginTransaction(IsolationLevel.ReadCommitted);
        try
        {
            var now = DbUtcNow(connection, tx);
            using (var lockTarget = new MySqlCommand("""
                SELECT m.source_instance, m.agent_id, m.candidate_id, m.worker_version, m.operation, m.status,
                       q.status, q.event_version, q.completed_version
                FROM wazuh_audit_poc.solr_mutation_queue m
                INNER JOIN wazuh_audit_poc.candidate_work_queue q
                  ON q.source_instance=m.source_instance AND q.agent_id=m.agent_id AND q.candidate_id=m.candidate_id
                WHERE m.mutation_id=@mutation
                FOR UPDATE;
                """, connection, tx))
            {
                lockTarget.Parameters.AddWithValue("@mutation", target.MutationId);
                using var reader = lockTarget.ExecuteReader();
                if (!reader.Read()) throw new EventConflictException("Mutation disappeared before execution claim.");
                var current = new SolrMutationTarget(target.MutationId, reader.GetString(0), reader.GetString(1), reader.GetString(2),
                    reader.GetUInt64(3), reader.GetString(4), reader.GetString(5), reader.GetString(6), reader.GetUInt64(7), reader.GetUInt64(8));
                ValidateTarget(current, settings);
                if (current.WorkerVersion != target.WorkerVersion)
                    throw new EventConflictException("Mutation worker version changed before execution claim.");
            }

            var actionIds = new List<ulong>();
            using (var lockActions = new MySqlCommand("""
                SELECT a.action_id, a.status, p.status, p.payload_json, p.payload_sha256, p.block_reason
                FROM wazuh_audit_poc.solr_mutation_action a
                INNER JOIN wazuh_audit_poc.solr_action_payload p ON p.action_id=a.action_id
                WHERE a.mutation_id=@mutation
                ORDER BY a.action_order
                FOR UPDATE;
                """, connection, tx))
            {
                lockActions.Parameters.AddWithValue("@mutation", target.MutationId);
                using var reader = lockActions.ExecuteReader();
                while (reader.Read())
                {
                    if (reader.GetString(1) != "planned")
                        throw new EventConflictException($"Action {reader.GetUInt64(0)} is no longer planned.");
                    if (reader.IsDBNull(2) || reader.GetString(2) != "ready" || reader.IsDBNull(3) || reader.IsDBNull(4) || !reader.IsDBNull(5))
                        throw new EventConflictException($"Action {reader.GetUInt64(0)} no longer has a ready unblocked payload.");
                    actionIds.Add(reader.GetUInt64(0));
                }
            }
            if (actionIds.Count != expectedActionCount)
                throw new EventConflictException("Action count changed before execution claim.");

            using (var updateMutation = new MySqlCommand("""
                UPDATE wazuh_audit_poc.solr_mutation_queue
                SET status='processing', attempt_count=attempt_count+1, updated_at_utc=@now, last_error=NULL
                WHERE mutation_id=@mutation AND status='planned';
                """, connection, tx))
            {
                updateMutation.Parameters.AddWithValue("@now", now);
                updateMutation.Parameters.AddWithValue("@mutation", target.MutationId);
                if (updateMutation.ExecuteNonQuery() != 1)
                    throw new EventConflictException("Failed to claim mutation for Step 11 execution.");
            }
            using (var updateActions = new MySqlCommand("""
                UPDATE wazuh_audit_poc.solr_mutation_action
                SET status='processing', attempt_count=attempt_count+1, updated_at_utc=@now, last_error=NULL
                WHERE mutation_id=@mutation AND status='planned';
                """, connection, tx))
            {
                updateActions.Parameters.AddWithValue("@now", now);
                updateActions.Parameters.AddWithValue("@mutation", target.MutationId);
                if (updateActions.ExecuteNonQuery() != expectedActionCount)
                    throw new EventConflictException("Failed to claim every Step 11 action atomically in MariaDB.");
            }
            tx.Commit();
        }
        catch
        {
            try { tx.Rollback(); } catch { }
            throw;
        }
    }

    public static void MarkApplied(MySqlConnection connection, ulong mutationId, int expectedActionCount)
    {
        using var tx = connection.BeginTransaction(IsolationLevel.ReadCommitted);
        try
        {
            var now = DbUtcNow(connection, tx);
            using (var actions = new MySqlCommand("""
                UPDATE wazuh_audit_poc.solr_mutation_action
                SET status='applied', applied_at_utc=@now, updated_at_utc=@now, last_error=NULL
                WHERE mutation_id=@mutation AND status='processing';
                """, connection, tx))
            {
                actions.Parameters.AddWithValue("@now", now);
                actions.Parameters.AddWithValue("@mutation", mutationId);
                if (actions.ExecuteNonQuery() != expectedActionCount)
                    throw new EventConflictException("Could not mark every processing Solr action applied after verification.");
            }
            using (var mutation = new MySqlCommand("""
                UPDATE wazuh_audit_poc.solr_mutation_queue
                SET status='applied', applied_at_utc=@now, updated_at_utc=@now, last_error=NULL
                WHERE mutation_id=@mutation AND status='processing';
                """, connection, tx))
            {
                mutation.Parameters.AddWithValue("@now", now);
                mutation.Parameters.AddWithValue("@mutation", mutationId);
                if (mutation.ExecuteNonQuery() != 1)
                    throw new EventConflictException("Could not mark the processing Solr mutation applied after verification.");
            }
            tx.Commit();
        }
        catch
        {
            try { tx.Rollback(); } catch { }
            throw;
        }
    }

    public static void MarkFailedBestEffort(MySqlConnection connection, ulong mutationId, string error)
    {
        try
        {
            var safe = error.Length > 4000 ? error[..4000] : error;
            using var tx = connection.BeginTransaction(IsolationLevel.ReadCommitted);
            var now = DbUtcNow(connection, tx);
            using (var actions = new MySqlCommand("""
                UPDATE wazuh_audit_poc.solr_mutation_action
                SET status='failed', updated_at_utc=@now, last_error=@error
                WHERE mutation_id=@mutation AND status='processing';
                """, connection, tx))
            {
                actions.Parameters.AddWithValue("@now", now);
                actions.Parameters.AddWithValue("@error", safe);
                actions.Parameters.AddWithValue("@mutation", mutationId);
                actions.ExecuteNonQuery();
            }
            using (var mutation = new MySqlCommand("""
                UPDATE wazuh_audit_poc.solr_mutation_queue
                SET status='failed', updated_at_utc=@now, last_error=@error
                WHERE mutation_id=@mutation AND status='processing';
                """, connection, tx))
            {
                mutation.Parameters.AddWithValue("@now", now);
                mutation.Parameters.AddWithValue("@error", safe);
                mutation.Parameters.AddWithValue("@mutation", mutationId);
                mutation.ExecuteNonQuery();
            }
            tx.Commit();
        }
        catch
        {
            // Best-effort only. The original execution failure is more important and
            // an uncertain DB finalization must not cause another Solr write attempt.
        }
    }

    private static void ValidateTarget(SolrMutationTarget target, ImportSettings settings)
    {
        if (target.SourceInstance != settings.SourceInstance || target.AgentId != settings.AgentId ||
            !settings.CandidateIds.Contains(target.CandidateId, StringComparer.Ordinal))
            throw new SolrExecutionException("Selected mutation is outside the explicit Step 11 pilot identity/scope.");
        if (target.Operation != "reindex_candidate" || target.MutationStatus != "planned")
            throw new SolrExecutionException($"Mutation {target.MutationId} is operation={target.Operation}, status={target.MutationStatus}; Step 11 requires planned reindex_candidate.");
        if (target.QueueStatus != "completed" || target.EventVersion != target.WorkerVersion || target.CompletedVersion != target.WorkerVersion)
            throw new SolrExecutionException("Candidate queue is not quiescent at the selected mutation worker version. Process the newer event before Solr execution.");
    }

    private static DateTime DbUtcNow(MySqlConnection connection, MySqlTransaction tx)
    {
        using var cmd = new MySqlCommand("SELECT UTC_TIMESTAMP(6);", connection, tx);
        return DateTime.SpecifyKind(Convert.ToDateTime(cmd.ExecuteScalar(), System.Globalization.CultureInfo.InvariantCulture), DateTimeKind.Utc);
    }
}
