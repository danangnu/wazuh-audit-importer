using MySqlConnector;

namespace WazuhAuditImporter;

public static class SchemaContract
{
    private sealed record Spec(string Name, string Type, long? Length, bool Nullable,
        string? Collation, string? EnumType, bool AutoIncrement);
    private static readonly Dictionary<string, Spec[]> Expected = new()
    {
        ["audit_event"] = [
            new("audit_event_id", "bigint", null, false, null, null, true),
            new("source_instance", "varchar", 64, false, "ascii_bin", null, false),
            new("wazuh_event_id", "varchar", 64, false, "ascii_bin", null, false),
            new("agent_id", "varchar", 32, false, "ascii_bin", null, false),
            new("agent_name", "varchar", 191, false, null, null, false),
            new("agent_ip", "varchar", 45, true, "ascii_bin", null, false),
            new("manager_name", "varchar", 191, false, null, null, false),
            new("candidate_id", "varchar", 32, false, "ascii_bin", null, false),
            new("event_type", "enum", null, false, null, "enum('added','modified','deleted')", false),
            new("detection_mode", "varchar", 32, true, "ascii_bin", null, false),
            new("rule_id", "varchar", 32, true, "ascii_bin", null, false),
            new("rule_level", "smallint", null, true, null, null, false),
            new("event_time_utc", "datetime", null, false, null, null, false),
            new("ingested_at_utc", "datetime", null, false, null, null, false),
            new("source_path", "text", null, false, null, null, false),
            new("file_owner_name", "varchar", 255, true, null, null, false),
            new("actor_name", "varchar", 255, true, null, null, false),
            new("actor_process", "text", null, true, null, null, false),
            new("reported_size_bytes", "bigint", null, true, null, null, false),
            new("reported_sha256", "char", 64, true, "ascii_bin", null, false),
            new("raw_json", "longtext", null, false, null, null, false)
        ],
        ["candidate_work_queue"] = [
            new("work_item_id", "bigint", null, false, null, null, true),
            new("source_instance", "varchar", 64, false, "ascii_bin", null, false),
            new("agent_id", "varchar", 32, false, "ascii_bin", null, false),
            new("candidate_id", "varchar", 32, false, "ascii_bin", null, false),
            new("candidate_folder", "text", null, false, null, null, false),
            new("status", "enum", null, false, null, "enum('pending','processing','retry','completed','failed')", false),
            new("event_version", "bigint", null, false, null, null, false),
            new("claimed_version", "bigint", null, true, null, null, false),
            new("completed_version", "bigint", null, false, null, null, false),
            new("attempt_count", "int", null, false, null, null, false),
            new("last_audit_event_id", "bigint", null, false, null, null, false),
            new("available_at_utc", "datetime", null, false, null, null, false),
            new("lease_token", "char", 36, true, "ascii_bin", null, false),
            new("lease_expires_at_utc", "datetime", null, true, null, null, false),
            new("created_at_utc", "datetime", null, false, null, null, false),
            new("updated_at_utc", "datetime", null, false, null, null, false),
            new("last_error", "text", null, true, null, null, false)
        ],
        ["collector_checkpoint"] = [
            new("source_instance", "varchar", 64, false, "ascii_bin", null, false),
            new("stream_key", "varchar", 64, false, "ascii_bin", null, false),
            new("input_kind", "varchar", 32, false, "ascii_bin", null, false),
            new("input_location", "text", null, false, null, null, false),
            new("cursor_text", "longtext", null, true, null, null, false),
            new("last_wazuh_event_id", "varchar", 64, true, "ascii_bin", null, false),
            new("updated_at_utc", "datetime", null, false, null, null, false)
        ],
        ["solr_mutation_queue"] = [
            new("mutation_id", "bigint", null, false, null, null, true),
            new("source_instance", "varchar", 64, false, "ascii_bin", null, false),
            new("agent_id", "varchar", 32, false, "ascii_bin", null, false),
            new("candidate_id", "varchar", 32, false, "ascii_bin", null, false),
            new("worker_version", "bigint", null, false, null, null, false),
            new("operation", "enum", null, false, null, "enum('reindex_candidate','none')", false),
            new("status", "enum", null, false, null, "enum('planned','not_required','processing','applied','failed','skipped')", false),
            new("added_count", "int", null, false, null, null, false),
            new("removed_count", "int", null, false, null, null, false),
            new("changed_count", "int", null, false, null, null, false),
            new("plan_json", "longtext", null, false, null, null, false),
            new("idempotency_key", "char", 64, false, "ascii_bin", null, false),
            new("attempt_count", "int", null, false, null, null, false),
            new("planned_at_utc", "datetime", null, false, null, null, false),
            new("updated_at_utc", "datetime", null, false, null, null, false),
            new("applied_at_utc", "datetime", null, true, null, null, false),
            new("last_error", "text", null, true, null, null, false)
        ],
        ["solr_mutation_action"] = [
            new("action_id", "bigint", null, false, null, null, true),
            new("mutation_id", "bigint", null, false, null, null, false),
            new("source_instance", "varchar", 64, false, "ascii_bin", null, false),
            new("agent_id", "varchar", 32, false, "ascii_bin", null, false),
            new("candidate_id", "varchar", 32, false, "ascii_bin", null, false),
            new("worker_version", "bigint", null, false, null, null, false),
            new("action_order", "int", null, false, null, null, false),
            new("action_type", "enum", null, false, null, "enum('delete_document','index_document')", false),
            new("status", "enum", null, false, null, "enum('planned','processing','applied','failed','skipped')", false),
            new("reason", "varchar", 64, false, "ascii_bin", null, false),
            new("solr_document_id", "varchar", 255, false, null, null, false),
            new("canonical_path", "text", null, false, null, null, false),
            new("source_file_path", "text", null, true, null, null, false),
            new("source_file_length", "bigint", null, true, null, null, false),
            new("source_file_last_write_utc", "datetime", null, true, null, null, false),
            new("solr_last_update_utc", "datetime", null, true, null, null, false),
            new("idempotency_key", "char", 64, false, "ascii_bin", null, false),
            new("attempt_count", "int", null, false, null, null, false),
            new("planned_at_utc", "datetime", null, false, null, null, false),
            new("updated_at_utc", "datetime", null, false, null, null, false),
            new("applied_at_utc", "datetime", null, true, null, null, false),
            new("last_error", "text", null, true, null, null, false)
        ]
    };

    public static void Verify(MySqlConnection connection, ImportSettings settings)
    {
        using (var identity = new MySqlCommand("SELECT @@hostname, @@port, VERSION(), DATABASE();", connection))
        using (var reader = identity.ExecuteReader())
        {
            reader.Read();
            var host = reader.GetString(0);
            if (!host.Equals(settings.ExpectedDatabaseServer, StringComparison.OrdinalIgnoreCase) ||
                reader.GetString(3) != "wazuh_audit_poc")
                throw new InvalidOperationException("Unexpected database server or database. No import attempted.");
            Console.WriteLine($"DB server={host}; port={reader.GetValue(1)}; version={reader.GetString(2)}; database={reader.GetString(3)}");
        }
        foreach (var (table, specs) in Expected)
        {
            using (var cmd = new MySqlCommand("""
                SELECT ENGINE FROM information_schema.TABLES
                WHERE TABLE_SCHEMA='wazuh_audit_poc' AND TABLE_NAME=@table;
                """, connection))
            {
                cmd.Parameters.AddWithValue("@table", table);
                if (!string.Equals(Convert.ToString(cmd.ExecuteScalar()), "InnoDB", StringComparison.OrdinalIgnoreCase))
                    throw new InvalidOperationException($"Missing InnoDB table: {table}. Do not drop/recreate existing tables.");
            }
            var seen = new HashSet<string>(StringComparer.Ordinal);
            using (var cmd = new MySqlCommand("""
                SELECT COLUMN_NAME, DATA_TYPE, CHARACTER_MAXIMUM_LENGTH, IS_NULLABLE,
                       COLLATION_NAME, COLUMN_TYPE, EXTRA, DATETIME_PRECISION
                FROM information_schema.COLUMNS
                WHERE TABLE_SCHEMA='wazuh_audit_poc' AND TABLE_NAME=@table;
                """, connection))
            {
                cmd.Parameters.AddWithValue("@table", table);
                using var reader = cmd.ExecuteReader();
                while (reader.Read())
                {
                    var name = reader.GetString(0);
                    var spec = specs.SingleOrDefault(s => s.Name == name);
                    if (spec is null) continue;
                    seen.Add(name);
                    var mismatch = reader.GetString(1).ToLowerInvariant() != spec.Type ||
                        (reader.GetString(3) == "YES") != spec.Nullable;
                    if (spec.Length is long length)
                        mismatch |= reader.IsDBNull(2) || Convert.ToInt64(reader.GetValue(2)) != length;
                    if (spec.Collation is not null)
                        mismatch |= reader.IsDBNull(4) || reader.GetString(4) != spec.Collation;
                    if (spec.EnumType is not null)
                        mismatch |= reader.GetString(5) != spec.EnumType;
                    if (spec.AutoIncrement)
                        mismatch |= !reader.GetString(6).Contains("auto_increment", StringComparison.OrdinalIgnoreCase);
                    if (spec.Type is "int" or "bigint" or "smallint")
                        mismatch |= !reader.GetString(5).Contains("unsigned", StringComparison.OrdinalIgnoreCase);
                    if (spec.Type == "datetime")
                        mismatch |= reader.IsDBNull(7) || Convert.ToInt32(reader.GetValue(7)) != 6;
                    if (mismatch)
                        throw new InvalidOperationException($"Schema mismatch: {table}.{name}. Stop; do not drop the table.");
                }
            }
            if (specs.Any(s => !seen.Contains(s.Name)))
                throw new InvalidOperationException($"Required columns are missing from {table}.");
        }
        VerifyUnique(connection, "audit_event", "uq_audit_source_event", ["source_instance", "wazuh_event_id"]);
        VerifyUnique(connection, "candidate_work_queue", "uq_queue_source_agent_candidate",
            ["source_instance", "agent_id", "candidate_id"]);
        VerifyUnique(connection, "solr_mutation_queue", "uq_solr_plan_version",
            ["source_instance", "agent_id", "candidate_id", "worker_version"]);
        VerifyUnique(connection, "solr_mutation_queue", "uq_solr_plan_idempotency",
            ["idempotency_key"]);
        VerifyUnique(connection, "solr_mutation_action", "uq_solr_action_order",
            ["mutation_id", "action_order"]);
        VerifyUnique(connection, "solr_mutation_action", "uq_solr_action_idempotency",
            ["idempotency_key"]);
        Console.WriteLine("Schema guard: required columns, InnoDB engines and deduplication indexes matched.");
    }

    private static void VerifyUnique(MySqlConnection conn, string table, string index, string[] expected)
    {
        using var cmd = new MySqlCommand("""
            SELECT COLUMN_NAME, NON_UNIQUE, SUB_PART FROM information_schema.STATISTICS
            WHERE TABLE_SCHEMA='wazuh_audit_poc' AND TABLE_NAME=@table AND INDEX_NAME=@index
            ORDER BY SEQ_IN_INDEX;
            """, conn);
        cmd.Parameters.AddWithValue("@table", table);
        cmd.Parameters.AddWithValue("@index", index);
        using var reader = cmd.ExecuteReader();
        var actual = new List<string>();
        while (reader.Read())
        {
            if (Convert.ToInt32(reader.GetValue(1)) != 0 || !reader.IsDBNull(2))
                throw new InvalidOperationException($"Expected full unique index {index}.");
            actual.Add(reader.GetString(0));
        }
        if (!actual.SequenceEqual(expected))
            throw new InvalidOperationException($"Missing or incompatible unique index {index}.");
    }
}
