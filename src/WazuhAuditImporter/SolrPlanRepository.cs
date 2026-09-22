using System.Data;
using MySqlConnector;

namespace WazuhAuditImporter;

public static class SolrPlanRepository
{
    public static SolrPlanWriteResult EnsurePlan(MySqlConnection connection, SolrPlanSpec plan)
    {
        using var tx = connection.BeginTransaction(IsolationLevel.ReadCommitted);
        try
        {
            var now = DbUtcNow(connection, tx);

            ulong mutationId = 0;
            string? existingOperation = null;
            string? existingStatus = null;
            string? existingPlanJson = null;
            string? existingKey = null;
            int existingAdded = 0, existingRemoved = 0, existingChanged = 0;

            using (var select = new MySqlCommand("""
                SELECT mutation_id, operation, status, added_count, removed_count, changed_count,
                       plan_json, idempotency_key
                FROM wazuh_audit_poc.solr_mutation_queue
                WHERE source_instance=@source
                  AND agent_id=@agent
                  AND candidate_id=@candidate
                  AND worker_version=@version
                FOR UPDATE;
                """, connection, tx))
            {
                select.Parameters.AddWithValue("@source", plan.SourceInstance);
                select.Parameters.AddWithValue("@agent", plan.AgentId);
                select.Parameters.AddWithValue("@candidate", plan.CandidateId);
                select.Parameters.AddWithValue("@version", plan.WorkerVersion);
                using var reader = select.ExecuteReader();
                if (reader.Read())
                {
                    mutationId = reader.GetUInt64(0);
                    existingOperation = reader.GetString(1);
                    existingStatus = reader.GetString(2);
                    existingAdded = Convert.ToInt32(reader.GetValue(3));
                    existingRemoved = Convert.ToInt32(reader.GetValue(4));
                    existingChanged = Convert.ToInt32(reader.GetValue(5));
                    existingPlanJson = reader.GetString(6);
                    existingKey = reader.GetString(7);
                }
            }

            if (mutationId != 0)
            {
                // Status may legitimately move later (planned -> applied/failed/etc.), so
                // idempotency is based on the immutable plan identity/content, not status.
                if (!string.Equals(existingOperation, plan.Operation, StringComparison.Ordinal) ||
                    !string.Equals(existingPlanJson, plan.PlanJson, StringComparison.Ordinal) ||
                    !string.Equals(existingKey, plan.IdempotencyKey, StringComparison.Ordinal) ||
                    existingAdded != plan.AddedCount ||
                    existingRemoved != plan.RemovedCount ||
                    existingChanged != plan.ChangedCount)
                {
                    throw new EventConflictException(
                        $"Solr dry-run plan already exists for candidate {plan.CandidateId} version {plan.WorkerVersion} with different immutable content.");
                }

                tx.Commit();
                return new SolrPlanWriteResult(
                    mutationId,
                    existingOperation!,
                    existingStatus!,
                    Inserted: false,
                    existingAdded,
                    existingRemoved,
                    existingChanged);
            }

            using (var insert = new MySqlCommand("""
                INSERT INTO wazuh_audit_poc.solr_mutation_queue
                (source_instance, agent_id, candidate_id, worker_version,
                 operation, status, added_count, removed_count, changed_count,
                 plan_json, idempotency_key, attempt_count,
                 planned_at_utc, updated_at_utc, applied_at_utc, last_error)
                VALUES
                (@source, @agent, @candidate, @version,
                 @operation, @status, @added, @removed, @changed,
                 @plan_json, @key, 0,
                 @now, @now, NULL, NULL);
                """, connection, tx))
            {
                insert.Parameters.AddWithValue("@source", plan.SourceInstance);
                insert.Parameters.AddWithValue("@agent", plan.AgentId);
                insert.Parameters.AddWithValue("@candidate", plan.CandidateId);
                insert.Parameters.AddWithValue("@version", plan.WorkerVersion);
                insert.Parameters.AddWithValue("@operation", plan.Operation);
                insert.Parameters.AddWithValue("@status", plan.Status);
                insert.Parameters.AddWithValue("@added", plan.AddedCount);
                insert.Parameters.AddWithValue("@removed", plan.RemovedCount);
                insert.Parameters.AddWithValue("@changed", plan.ChangedCount);
                insert.Parameters.AddWithValue("@plan_json", plan.PlanJson);
                insert.Parameters.AddWithValue("@key", plan.IdempotencyKey);
                insert.Parameters.AddWithValue("@now", now);
                if (insert.ExecuteNonQuery() != 1)
                    throw new EventConflictException("Failed to insert the Solr dry-run plan.");
                mutationId = checked((ulong)insert.LastInsertedId);
            }

            tx.Commit();
            return new SolrPlanWriteResult(
                mutationId,
                plan.Operation,
                plan.Status,
                Inserted: true,
                plan.AddedCount,
                plan.RemovedCount,
                plan.ChangedCount);
        }
        catch
        {
            try { tx.Rollback(); } catch { }
            throw;
        }
    }

    private static DateTime DbUtcNow(MySqlConnection connection, MySqlTransaction tx)
    {
        using var cmd = new MySqlCommand("SELECT UTC_TIMESTAMP(6);", connection, tx);
        var value = cmd.ExecuteScalar() ?? throw new InvalidOperationException("Database UTC clock was unavailable.");
        return DateTime.SpecifyKind(Convert.ToDateTime(value, System.Globalization.CultureInfo.InvariantCulture), DateTimeKind.Utc);
    }
}
