using System.Data;
using MySqlConnector;

namespace WazuhAuditImporter;

public static class PipelineRepository
{
    public static PipelineMutationSnapshot? ReadLatestSnapshot(
        MySqlConnection connection,
        ImportSettings settings,
        string candidateId)
    {
        using var cmd = new MySqlCommand("""
            SELECT m.mutation_id, m.candidate_id, m.worker_version, m.operation, m.status,
                   q.status, q.event_version, q.completed_version,
                   (SELECT COUNT(*) FROM wazuh_audit_poc.solr_mutation_action a
                     WHERE a.mutation_id=m.mutation_id) AS action_count,
                   (SELECT COUNT(*) FROM wazuh_audit_poc.solr_mutation_action a
                     WHERE a.mutation_id=m.mutation_id AND a.status<>'planned') AS nonplanned_action_count,
                   (SELECT COUNT(*) FROM wazuh_audit_poc.solr_action_payload p
                     WHERE p.mutation_id=m.mutation_id AND p.status='ready') AS ready_payload_count,
                   (SELECT COUNT(*) FROM wazuh_audit_poc.solr_action_payload p
                     WHERE p.mutation_id=m.mutation_id AND p.status='blocked') AS blocked_payload_count
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
        if (!reader.Read()) return null;
        return new PipelineMutationSnapshot(
            reader.GetUInt64(0),
            reader.GetString(1),
            reader.GetUInt64(2),
            reader.GetString(3),
            reader.GetString(4),
            reader.GetString(5),
            reader.GetUInt64(6),
            reader.GetUInt64(7),
            Convert.ToInt32(reader.GetValue(8), System.Globalization.CultureInfo.InvariantCulture),
            Convert.ToInt32(reader.GetValue(9), System.Globalization.CultureInfo.InvariantCulture),
            Convert.ToInt32(reader.GetValue(10), System.Globalization.CultureInfo.InvariantCulture),
            Convert.ToInt32(reader.GetValue(11), System.Globalization.CultureInfo.InvariantCulture));
    }

    public static bool MarkNoActionMutationSkipped(
        MySqlConnection connection,
        ImportSettings settings,
        PipelineMutationSnapshot snapshot)
    {
        using var tx = connection.BeginTransaction(IsolationLevel.ReadCommitted);
        try
        {
            string operation;
            string mutationStatus;
            string queueStatus;
            ulong workerVersion;
            ulong eventVersion;
            ulong completedVersion;
            using (var lockCmd = new MySqlCommand("""
                SELECT m.operation, m.status, m.worker_version,
                       q.status, q.event_version, q.completed_version
                FROM wazuh_audit_poc.solr_mutation_queue m
                INNER JOIN wazuh_audit_poc.candidate_work_queue q
                   ON q.source_instance=m.source_instance
                  AND q.agent_id=m.agent_id
                  AND q.candidate_id=m.candidate_id
                WHERE m.mutation_id=@mutation
                  AND m.source_instance=@source
                  AND m.agent_id=@agent
                  AND m.candidate_id=@candidate
                FOR UPDATE;
                """, connection, tx))
            {
                lockCmd.Parameters.AddWithValue("@mutation", snapshot.MutationId);
                lockCmd.Parameters.AddWithValue("@source", settings.SourceInstance);
                lockCmd.Parameters.AddWithValue("@agent", settings.AgentId);
                lockCmd.Parameters.AddWithValue("@candidate", snapshot.CandidateId);
                using var reader = lockCmd.ExecuteReader();
                if (!reader.Read()) throw new EventConflictException("Mutation disappeared before no-action finalization.");
                operation = reader.GetString(0);
                mutationStatus = reader.GetString(1);
                workerVersion = reader.GetUInt64(2);
                queueStatus = reader.GetString(3);
                eventVersion = reader.GetUInt64(4);
                completedVersion = reader.GetUInt64(5);
            }

            if (operation != "reindex_candidate" || mutationStatus != "planned" ||
                workerVersion != snapshot.WorkerVersion || queueStatus != "completed" ||
                eventVersion != workerVersion || completedVersion != workerVersion)
                throw new EventConflictException("Mutation/queue state changed before no-action finalization.");

            using (var count = new MySqlCommand("""
                SELECT COUNT(*) FROM wazuh_audit_poc.solr_mutation_action
                WHERE mutation_id=@mutation;
                """, connection, tx))
            {
                count.Parameters.AddWithValue("@mutation", snapshot.MutationId);
                if (Convert.ToInt32(count.ExecuteScalar(), System.Globalization.CultureInfo.InvariantCulture) != 0)
                    throw new EventConflictException("Concrete actions appeared before no-action finalization.");
            }

            var now = DbUtcNow(connection, tx);
            using var update = new MySqlCommand("""
                UPDATE wazuh_audit_poc.solr_mutation_queue
                SET status='skipped', updated_at_utc=@now, last_error=NULL
                WHERE mutation_id=@mutation AND status='planned';
                """, connection, tx);
            update.Parameters.AddWithValue("@now", now);
            update.Parameters.AddWithValue("@mutation", snapshot.MutationId);
            if (update.ExecuteNonQuery() != 1)
                throw new EventConflictException("Could not mark no-action mutation skipped.");
            tx.Commit();
            return true;
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
