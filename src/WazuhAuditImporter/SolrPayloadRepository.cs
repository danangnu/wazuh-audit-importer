using System.Data;
using MySqlConnector;

namespace WazuhAuditImporter;

public static class SolrPayloadRepository
{
    public static IReadOnlyList<SolrStoredAction> ReadActions(MySqlConnection connection, SolrMutationTarget target)
    {
        using var cmd = new MySqlCommand("""
            SELECT action_id, mutation_id, source_instance, agent_id, candidate_id, worker_version,
                   action_order, action_type, status, reason, solr_document_id, canonical_path,
                   source_file_path, source_file_length, source_file_last_write_utc, idempotency_key
            FROM wazuh_audit_poc.solr_mutation_action
            WHERE mutation_id=@mutation
            ORDER BY action_order;
            """, connection);
        cmd.Parameters.AddWithValue("@mutation", target.MutationId);
        var rows = new List<SolrStoredAction>();
        using var reader = cmd.ExecuteReader();
        while (reader.Read())
        {
            rows.Add(new SolrStoredAction(
                reader.GetUInt64(0), reader.GetUInt64(1), reader.GetString(2), reader.GetString(3), reader.GetString(4),
                reader.GetUInt64(5), Convert.ToInt32(reader.GetValue(6)), reader.GetString(7), reader.GetString(8),
                reader.GetString(9), reader.GetString(10), reader.GetString(11), reader.IsDBNull(12) ? null : reader.GetString(12),
                reader.IsDBNull(13) ? null : Convert.ToUInt64(reader.GetValue(13)),
                reader.IsDBNull(14) ? null : DateTime.SpecifyKind(reader.GetDateTime(14), DateTimeKind.Utc),
                reader.GetString(15)));
        }
        if (rows.Count == 0)
            throw new SolrPayloadException("No Step 10A concrete actions exist for the latest mutation. Run solr-plan-actions first.");
        if (rows.Any(x => x.MutationId != target.MutationId || x.CandidateId != target.CandidateId || x.WorkerVersion != target.WorkerVersion))
            throw new SolrPayloadException("Concrete actions do not match the latest candidate mutation.");
        return rows;
    }

    public static IReadOnlyDictionary<ulong, SolrPayloadSpec> ReadExistingPayloads(MySqlConnection connection, ulong mutationId)
    {
        using var cmd = new MySqlCommand("""
            SELECT action_id, mutation_id, action_type, status, extractor, payload_json,
                   payload_sha256, source_file_sha256, content_sha256, content_char_count,
                   source_file_length, source_file_last_write_utc, block_reason, generated_at_utc
            FROM wazuh_audit_poc.solr_action_payload
            WHERE mutation_id=@mutation;
            """, connection);
        cmd.Parameters.AddWithValue("@mutation", mutationId);
        var rows = new Dictionary<ulong, SolrPayloadSpec>();
        using var reader = cmd.ExecuteReader();
        while (reader.Read())
        {
            var spec = new SolrPayloadSpec(
                reader.GetUInt64(0), reader.GetUInt64(1), reader.GetString(2), reader.GetString(3), reader.GetString(4),
                reader.IsDBNull(5) ? null : reader.GetString(5), reader.IsDBNull(6) ? null : reader.GetString(6),
                reader.IsDBNull(7) ? null : reader.GetString(7), reader.IsDBNull(8) ? null : reader.GetString(8),
                reader.IsDBNull(9) ? null : Convert.ToUInt64(reader.GetValue(9)),
                reader.IsDBNull(10) ? null : Convert.ToUInt64(reader.GetValue(10)),
                reader.IsDBNull(11) ? null : DateTime.SpecifyKind(reader.GetDateTime(11), DateTimeKind.Utc),
                reader.IsDBNull(12) ? null : reader.GetString(12),
                DateTime.SpecifyKind(reader.GetDateTime(13), DateTimeKind.Utc));
            rows.Add(spec.ActionId, spec);
        }
        return rows;
    }

    public static SolrPayloadWriteResult EnsurePayloads(MySqlConnection connection, SolrMutationTarget target,
        IReadOnlyList<SolrPayloadSpec> payloads)
    {
        using var tx = connection.BeginTransaction(IsolationLevel.ReadCommitted);
        try
        {
            Revalidate(connection, tx, target);
            var inserted = 0;
            var existing = 0;
            foreach (var p in payloads)
            {
                SolrPayloadSpec? stored = null;
                using (var select = new MySqlCommand("""
                    SELECT action_id, mutation_id, action_type, status, extractor, payload_json,
                           payload_sha256, source_file_sha256, content_sha256, content_char_count,
                           source_file_length, source_file_last_write_utc, block_reason, generated_at_utc
                    FROM wazuh_audit_poc.solr_action_payload
                    WHERE action_id=@action
                    FOR UPDATE;
                    """, connection, tx))
                {
                    select.Parameters.AddWithValue("@action", p.ActionId);
                    using var reader = select.ExecuteReader();
                    if (reader.Read())
                    {
                        stored = new SolrPayloadSpec(
                            reader.GetUInt64(0), reader.GetUInt64(1), reader.GetString(2), reader.GetString(3), reader.GetString(4),
                            reader.IsDBNull(5) ? null : reader.GetString(5), reader.IsDBNull(6) ? null : reader.GetString(6),
                            reader.IsDBNull(7) ? null : reader.GetString(7), reader.IsDBNull(8) ? null : reader.GetString(8),
                            reader.IsDBNull(9) ? null : Convert.ToUInt64(reader.GetValue(9)),
                            reader.IsDBNull(10) ? null : Convert.ToUInt64(reader.GetValue(10)),
                            reader.IsDBNull(11) ? null : DateTime.SpecifyKind(reader.GetDateTime(11), DateTimeKind.Utc),
                            reader.IsDBNull(12) ? null : reader.GetString(12),
                            DateTime.SpecifyKind(reader.GetDateTime(13), DateTimeKind.Utc));
                    }
                }
                if (stored is not null)
                {
                    if (!SameImmutable(stored, p))
                        throw new EventConflictException($"Stored Solr payload conflicts with regenerated action {p.ActionId}. Do not overwrite reviewed payloads.");
                    existing++;
                    continue;
                }

                using var insert = new MySqlCommand("""
                    INSERT INTO wazuh_audit_poc.solr_action_payload
                    (action_id, mutation_id, action_type, status, extractor, payload_json, payload_sha256,
                     source_file_sha256, content_sha256, content_char_count, source_file_length,
                     source_file_last_write_utc, block_reason, generated_at_utc)
                    VALUES
                    (@action,@mutation,@type,@status,@extractor,@json,@payload_hash,
                     @source_hash,@content_hash,@chars,@source_length,@source_mtime,@reason,@generated);
                    """, connection, tx);
                insert.Parameters.AddWithValue("@action", p.ActionId);
                insert.Parameters.AddWithValue("@mutation", p.MutationId);
                insert.Parameters.AddWithValue("@type", p.ActionType);
                insert.Parameters.AddWithValue("@status", p.Status);
                insert.Parameters.AddWithValue("@extractor", p.Extractor);
                insert.Parameters.AddWithValue("@json", (object?)p.PayloadJson ?? DBNull.Value);
                insert.Parameters.AddWithValue("@payload_hash", (object?)p.PayloadSha256 ?? DBNull.Value);
                insert.Parameters.AddWithValue("@source_hash", (object?)p.SourceFileSha256 ?? DBNull.Value);
                insert.Parameters.AddWithValue("@content_hash", (object?)p.ContentSha256 ?? DBNull.Value);
                insert.Parameters.AddWithValue("@chars", (object?)p.ContentCharCount ?? DBNull.Value);
                insert.Parameters.AddWithValue("@source_length", (object?)p.SourceFileLength ?? DBNull.Value);
                insert.Parameters.AddWithValue("@source_mtime", (object?)p.SourceFileLastWriteUtc ?? DBNull.Value);
                insert.Parameters.AddWithValue("@reason", (object?)p.BlockReason ?? DBNull.Value);
                insert.Parameters.AddWithValue("@generated", p.GeneratedAtUtc);
                if (insert.ExecuteNonQuery() != 1) throw new EventConflictException("Failed to store Solr dry-run payload.");
                inserted++;
            }
            tx.Commit();
            return new SolrPayloadWriteResult(payloads.Count, inserted, existing);
        }
        catch
        {
            try { tx.Rollback(); } catch { }
            throw;
        }
    }

    private static void Revalidate(MySqlConnection connection, MySqlTransaction tx, SolrMutationTarget target)
    {
        using var cmd = new MySqlCommand("""
            SELECT m.status, q.status, q.event_version, q.completed_version
            FROM wazuh_audit_poc.solr_mutation_queue m
            JOIN wazuh_audit_poc.candidate_work_queue q
              ON q.source_instance=m.source_instance AND q.agent_id=m.agent_id AND q.candidate_id=m.candidate_id
            WHERE m.mutation_id=@mutation
            FOR UPDATE;
            """, connection, tx);
        cmd.Parameters.AddWithValue("@mutation", target.MutationId);
        using var reader = cmd.ExecuteReader();
        if (!reader.Read()) throw new EventConflictException("Target mutation disappeared before payload storage.");
        var mutationStatus = reader.GetString(0);
        var queueStatus = reader.GetString(1);
        var eventVersion = reader.GetUInt64(2);
        var completedVersion = reader.GetUInt64(3);
        if (mutationStatus != "planned" || queueStatus != "completed" || eventVersion != target.WorkerVersion || completedVersion != target.WorkerVersion)
            throw new EventConflictException("Candidate/mutation state changed before payload storage. Re-run reconciliation and planning.");
    }

    private static bool SameImmutable(SolrPayloadSpec a, SolrPayloadSpec b) =>
        a.ActionId == b.ActionId && a.MutationId == b.MutationId && a.ActionType == b.ActionType &&
        a.Status == b.Status && a.Extractor == b.Extractor && a.PayloadJson == b.PayloadJson &&
        a.PayloadSha256 == b.PayloadSha256 && a.SourceFileSha256 == b.SourceFileSha256 &&
        a.ContentSha256 == b.ContentSha256 && a.ContentCharCount == b.ContentCharCount &&
        a.SourceFileLength == b.SourceFileLength && a.SourceFileLastWriteUtc == b.SourceFileLastWriteUtc &&
        a.BlockReason == b.BlockReason;
}
