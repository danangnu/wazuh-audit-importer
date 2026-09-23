using System.Data;
using MySqlConnector;

namespace WazuhAuditImporter;

public static class SolrConcreteActionRepository
{
    public static SolrMutationTarget ReadLatestTarget(MySqlConnection connection, ImportSettings settings, string candidateId)
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
            WHERE m.source_instance=@source
              AND m.agent_id=@agent
              AND m.candidate_id=@candidate
            ORDER BY m.worker_version DESC, m.mutation_id DESC
            LIMIT 1;
            """, connection);
        cmd.Parameters.AddWithValue("@source", settings.SourceInstance);
        cmd.Parameters.AddWithValue("@agent", settings.AgentId);
        cmd.Parameters.AddWithValue("@candidate", candidateId);
        using var reader = cmd.ExecuteReader();
        if (!reader.Read())
            throw new SolrConcreteActionException($"No Solr candidate mutation exists for candidate {candidateId}. Run the reconciliation worker first.");
        var target = new SolrMutationTarget(
            reader.GetUInt64(0), reader.GetString(1), reader.GetString(2), reader.GetString(3),
            reader.GetUInt64(4), reader.GetString(5), reader.GetString(6), reader.GetString(7),
            reader.GetUInt64(8), reader.GetUInt64(9));
        ValidateTarget(target);
        return target;
    }

    public static SolrConcreteActionWriteResult EnsureActions(
        MySqlConnection connection,
        SolrMutationTarget target,
        IReadOnlyList<SolrConcreteActionSpec> actions)
    {
        using var tx = connection.BeginTransaction(IsolationLevel.ReadCommitted);
        try
        {
            LockAndRevalidate(connection, tx, target);
            var now = DbUtcNow(connection, tx);
            var inserted = 0;
            var existing = 0;

            using (var count = new MySqlCommand("""
                SELECT COUNT(*)
                FROM wazuh_audit_poc.solr_mutation_action
                WHERE mutation_id=@mutation;
                """, connection, tx))
            {
                count.Parameters.AddWithValue("@mutation", target.MutationId);
                var existingCount = Convert.ToInt32(count.ExecuteScalar(), System.Globalization.CultureInfo.InvariantCulture);
                if (existingCount > actions.Count)
                    throw new EventConflictException("Concrete action rows exceed the newly generated deterministic plan. Inspect before retrying.");
            }

            foreach (var action in actions.OrderBy(x => x.ActionOrder))
            {
                SolrConcreteActionSpec? stored = null;
                using (var select = new MySqlCommand("""
                    SELECT action_order, action_type, status, reason, solr_document_id,
                           canonical_path, source_file_path, source_file_length,
                           source_file_last_write_utc, solr_last_update_utc, idempotency_key
                    FROM wazuh_audit_poc.solr_mutation_action
                    WHERE mutation_id=@mutation AND action_order=@order
                    FOR UPDATE;
                    """, connection, tx))
                {
                    select.Parameters.AddWithValue("@mutation", target.MutationId);
                    select.Parameters.AddWithValue("@order", action.ActionOrder);
                    using var reader = select.ExecuteReader();
                    if (reader.Read())
                    {
                        stored = new SolrConcreteActionSpec(
                            Convert.ToInt32(reader.GetValue(0)),
                            reader.GetString(1),
                            reader.GetString(2),
                            reader.GetString(3),
                            reader.GetString(4),
                            reader.GetString(5),
                            reader.IsDBNull(6) ? null : reader.GetString(6),
                            reader.IsDBNull(7) ? null : Convert.ToUInt64(reader.GetValue(7)),
                            reader.IsDBNull(8) ? null : DateTime.SpecifyKind(reader.GetDateTime(8), DateTimeKind.Utc),
                            reader.IsDBNull(9) ? null : DateTime.SpecifyKind(reader.GetDateTime(9), DateTimeKind.Utc),
                            reader.GetString(10));
                    }
                }

                if (stored is not null)
                {
                    if (!SameImmutable(stored, action))
                        throw new EventConflictException(
                            $"Concrete Solr action conflict for mutation {target.MutationId} order {action.ActionOrder}.");
                    existing++;
                    continue;
                }

                using var insert = new MySqlCommand("""
                    INSERT INTO wazuh_audit_poc.solr_mutation_action
                    (mutation_id, source_instance, agent_id, candidate_id, worker_version,
                     action_order, action_type, status, reason, solr_document_id,
                     canonical_path, source_file_path, source_file_length,
                     source_file_last_write_utc, solr_last_update_utc,
                     idempotency_key, attempt_count, planned_at_utc, updated_at_utc,
                     applied_at_utc, last_error)
                    VALUES
                    (@mutation, @source, @agent, @candidate, @version,
                     @order, @type, 'planned', @reason, @solr_id,
                     @path, @source_file, @source_length,
                     @source_mtime, @solr_update,
                     @key, 0, @now, @now, NULL, NULL);
                    """, connection, tx);
                insert.Parameters.AddWithValue("@mutation", target.MutationId);
                insert.Parameters.AddWithValue("@source", target.SourceInstance);
                insert.Parameters.AddWithValue("@agent", target.AgentId);
                insert.Parameters.AddWithValue("@candidate", target.CandidateId);
                insert.Parameters.AddWithValue("@version", target.WorkerVersion);
                insert.Parameters.AddWithValue("@order", action.ActionOrder);
                insert.Parameters.AddWithValue("@type", action.ActionType);
                insert.Parameters.AddWithValue("@reason", action.Reason);
                insert.Parameters.AddWithValue("@solr_id", action.SolrDocumentId);
                insert.Parameters.AddWithValue("@path", action.CanonicalPath);
                insert.Parameters.AddWithValue("@source_file", (object?)action.SourceFilePath ?? DBNull.Value);
                insert.Parameters.AddWithValue("@source_length", (object?)action.SourceFileLength ?? DBNull.Value);
                insert.Parameters.AddWithValue("@source_mtime", (object?)action.SourceFileLastWriteUtc ?? DBNull.Value);
                insert.Parameters.AddWithValue("@solr_update", (object?)action.SolrLastUpdateUtc ?? DBNull.Value);
                insert.Parameters.AddWithValue("@key", action.IdempotencyKey);
                insert.Parameters.AddWithValue("@now", now);
                if (insert.ExecuteNonQuery() != 1)
                    throw new EventConflictException("Failed to insert a concrete Solr dry-run action.");
                inserted++;
            }

            using (var finalCount = new MySqlCommand("""
                SELECT COUNT(*) FROM wazuh_audit_poc.solr_mutation_action
                WHERE mutation_id=@mutation;
                """, connection, tx))
            {
                finalCount.Parameters.AddWithValue("@mutation", target.MutationId);
                var count = Convert.ToInt32(finalCount.ExecuteScalar(), System.Globalization.CultureInfo.InvariantCulture);
                if (count != actions.Count)
                    throw new EventConflictException("Stored concrete action count does not match the deterministic current plan.");
            }

            tx.Commit();
            return new SolrConcreteActionWriteResult(actions.Count, inserted, existing);
        }
        catch
        {
            try { tx.Rollback(); } catch { }
            throw;
        }
    }

    private static void LockAndRevalidate(MySqlConnection connection, MySqlTransaction tx, SolrMutationTarget target)
    {
        using var cmd = new MySqlCommand("""
            SELECT m.operation, m.status, q.status, q.event_version, q.completed_version
            FROM wazuh_audit_poc.solr_mutation_queue m
            INNER JOIN wazuh_audit_poc.candidate_work_queue q
               ON q.source_instance=m.source_instance
              AND q.agent_id=m.agent_id
              AND q.candidate_id=m.candidate_id
            WHERE m.mutation_id=@mutation
            FOR UPDATE;
            """, connection, tx);
        cmd.Parameters.AddWithValue("@mutation", target.MutationId);
        using var reader = cmd.ExecuteReader();
        if (!reader.Read()) throw new EventConflictException("Target Solr mutation disappeared before concrete planning.");
        var current = target with
        {
            Operation = reader.GetString(0),
            MutationStatus = reader.GetString(1),
            QueueStatus = reader.GetString(2),
            EventVersion = reader.GetUInt64(3),
            CompletedVersion = reader.GetUInt64(4)
        };
        ValidateTarget(current);
        if (current.EventVersion != target.EventVersion || current.CompletedVersion != target.CompletedVersion)
            throw new EventConflictException("Candidate queue version changed during concrete Solr planning. Retry against the newer completed worker version.");
    }

    private static void ValidateTarget(SolrMutationTarget target)
    {
        if (target.Operation != "reindex_candidate" || target.MutationStatus != "planned")
            throw new SolrConcreteActionException(
                $"Latest Solr mutation is operation={target.Operation}, status={target.MutationStatus}; Step 10A requires a planned reindex_candidate mutation.");
        if (target.QueueStatus != "completed" || target.EventVersion != target.CompletedVersion || target.WorkerVersion != target.CompletedVersion)
            throw new SolrConcreteActionException(
                "Candidate queue is not quiescent at the target worker version. Finish/re-run the worker before concrete Solr planning.");
    }

    private static bool SameImmutable(SolrConcreteActionSpec a, SolrConcreteActionSpec b) =>
        a.ActionOrder == b.ActionOrder &&
        a.ActionType == b.ActionType &&
        a.Reason == b.Reason &&
        a.SolrDocumentId == b.SolrDocumentId &&
        SolrPathMapper.NormalizeForComparison(a.CanonicalPath) == SolrPathMapper.NormalizeForComparison(b.CanonicalPath) &&
        string.Equals(a.SourceFilePath, b.SourceFilePath, StringComparison.OrdinalIgnoreCase) &&
        a.SourceFileLength == b.SourceFileLength &&
        a.SourceFileLastWriteUtc == b.SourceFileLastWriteUtc &&
        a.SolrLastUpdateUtc == b.SolrLastUpdateUtc &&
        a.IdempotencyKey == b.IdempotencyKey;

    private static DateTime DbUtcNow(MySqlConnection connection, MySqlTransaction tx)
    {
        using var cmd = new MySqlCommand("SELECT UTC_TIMESTAMP(6);", connection, tx);
        var value = cmd.ExecuteScalar() ?? throw new InvalidOperationException("Database UTC clock was unavailable.");
        return DateTime.SpecifyKind(Convert.ToDateTime(value, System.Globalization.CultureInfo.InvariantCulture), DateTimeKind.Utc);
    }
}
