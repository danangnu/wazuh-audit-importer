using System.Data;
using MySqlConnector;

namespace WazuhAuditImporter;

public static class AuditRepository
{
    public static MySqlConnection Open(ImportSettings settings, string user, string password)
    {
        settings.Validate();
        var builder = new MySqlConnectionStringBuilder
        {
            Server = settings.DatabaseHost,
            Port = settings.DatabasePort,
            Database = settings.DatabaseName,
            UserID = user,
            Password = password,
            SslMode = MySqlSslMode.Preferred,
            Pooling = false,
            PersistSecurityInfo = false,
            ConnectionTimeout = 10,
            DefaultCommandTimeout = 30,
            DateTimeKind = MySqlDateTimeKind.Utc
        };
        var connection = new MySqlConnection(builder.ConnectionString);
        try
        {
            connection.Open();
            // Session-only changes; never alter global settings on the shared DB server.
            using var session = new MySqlCommand("""
                SET SESSION sql_mode = CONCAT_WS(',', NULLIF(@@SESSION.sql_mode, ''), 'STRICT_ALL_TABLES');
                SET SESSION time_zone = '+00:00';
                """, connection);
            session.ExecuteNonQuery();
            SchemaContract.Verify(connection, settings);
            return connection;
        }
        catch { connection.Dispose(); throw; }
    }

    public static ImportResult Import(MySqlConnection connection, NormalizedAlert alert, ImportSettings settings)
    {
        using var tx = connection.BeginTransaction(IsolationLevel.ReadCommitted);
        try
        {
            DateTime ingested;
            using (var clock = new MySqlCommand("SELECT UTC_TIMESTAMP(6);", connection, tx))
                ingested = DateTime.SpecifyKind(Convert.ToDateTime(clock.ExecuteScalar()), DateTimeKind.Utc);

            ulong eventRowId;
            using (var cmd = new MySqlCommand(InsertEventSql, connection, tx))
            {
                Add(cmd, "source", alert.SourceInstance);
                Add(cmd, "event_id", alert.WazuhEventId);
                Add(cmd, "agent_id", alert.AgentId);
                Add(cmd, "agent_name", alert.AgentName);
                Add(cmd, "agent_ip", alert.AgentIp);
                Add(cmd, "manager", alert.ManagerName);
                Add(cmd, "candidate", alert.CandidateId);
                Add(cmd, "event_type", alert.EventType);
                Add(cmd, "mode", alert.DetectionMode);
                Add(cmd, "rule", alert.RuleId);
                Add(cmd, "level", alert.RuleLevel);
                Add(cmd, "event_time", alert.EventTimeUtc);
                Add(cmd, "ingested", ingested);
                Add(cmd, "path", alert.SourcePath);
                Add(cmd, "owner", alert.FileOwnerName);
                Add(cmd, "actor", alert.ActorName);
                Add(cmd, "process", alert.ActorProcess);
                Add(cmd, "size", alert.ReportedSizeBytes);
                Add(cmd, "sha256", alert.ReportedSha256);
                Add(cmd, "raw", alert.RawJson);
                try
                {
                    cmd.ExecuteNonQuery();
                    eventRowId = checked((ulong)cmd.LastInsertedId);
                }
                catch (MySqlException ex) when (ex.Number == 1062)
                {
                    // Duplicate insertion is not ignored blindly. Verify the original source
                    // payload and its queue before treating this as a successful replay.
                    var duplicate = VerifyDuplicate(connection, tx, alert, settings);
                    tx.Commit();
                    return duplicate;
                }
            }

            using (var work = new MySqlCommand(UpsertQueueSql, connection, tx))
            {
                Add(work, "source", alert.SourceInstance);
                Add(work, "agent_id", alert.AgentId);
                Add(work, "candidate", alert.CandidateId);
                Add(work, "folder", alert.CandidateFolder);
                Add(work, "audit_id", eventRowId);
                Add(work, "now", ingested);
                work.ExecuteNonQuery();
            }
            var queued = ReadQueue(connection, tx, alert);
            tx.Commit();
            return new ImportResult(true, eventRowId, queued);
        }
        catch
        {
            // Roll back a new audit row too if queue work failed. If COMMIT's outcome
            // is unknown due to connection loss, the user can safely replay the event.
            try { tx.Rollback(); } catch { /* Retain the original exception. */ }
            throw;
        }
    }

    private static ImportResult VerifyDuplicate(MySqlConnection conn, MySqlTransaction tx, NormalizedAlert alert, ImportSettings settings)
    {
        ulong id;
        string storedRaw;
        using (var cmd = new MySqlCommand("""
            SELECT audit_event_id, raw_json
            FROM wazuh_audit_poc.audit_event
            WHERE source_instance=@source AND wazuh_event_id=@event_id
            FOR UPDATE;
            """, conn, tx))
        {
            Add(cmd, "source", alert.SourceInstance);
            Add(cmd, "event_id", alert.WazuhEventId);
            using var reader = cmd.ExecuteReader();
            if (!reader.Read())
                throw new EventConflictException("Duplicate-key error did not resolve to the expected event key.");
            id = reader.GetUInt64(0);
            storedRaw = reader.GetString(1);
        }
        if (!AlertParser.SameNormalizedPayload(storedRaw, alert.RawJson, settings))
            throw new EventConflictException(
                "The same source-instance/event-id already exists with different normalized audit fields. " +
                "The conflicting event transaction was rolled back and the collector checkpoint was not advanced.");
        var queued = ReadQueue(conn, tx, alert);
        // No UPDATE: replay must not increment event_version or revive completed work.
        return new ImportResult(false, id, queued);
    }

    private static QueueState ReadQueue(MySqlConnection conn, MySqlTransaction tx, NormalizedAlert alert)
    {
        using var cmd = new MySqlCommand("""
            SELECT work_item_id, status, event_version, candidate_folder
            FROM wazuh_audit_poc.candidate_work_queue
            WHERE source_instance=@source AND agent_id=@agent_id AND candidate_id=@candidate
            FOR UPDATE;
            """, conn, tx);
        Add(cmd, "source", alert.SourceInstance);
        Add(cmd, "agent_id", alert.AgentId);
        Add(cmd, "candidate", alert.CandidateId);
        using var reader = cmd.ExecuteReader();
        if (!reader.Read())
            throw new EventConflictException("An audit event exists without its candidate queue. Inspect before retrying.");
        if (!reader.GetString(3).Equals(alert.CandidateFolder, StringComparison.OrdinalIgnoreCase))
            throw new EventConflictException("The queue points to a different candidate folder. Inspect the source configuration.");
        return new QueueState(reader.GetUInt64(0), reader.GetString(1), reader.GetUInt64(2));
    }

    private static void Add(MySqlCommand cmd, string key, object? value) =>
        cmd.Parameters.AddWithValue("@" + key, value ?? DBNull.Value);

    private const string InsertEventSql = """
        INSERT INTO wazuh_audit_poc.audit_event
        (source_instance, wazuh_event_id, agent_id, agent_name, agent_ip, manager_name,
         candidate_id, event_type, detection_mode, rule_id, rule_level,
         event_time_utc, ingested_at_utc, source_path, file_owner_name, actor_name,
         actor_process, reported_size_bytes, reported_sha256, raw_json)
        VALUES
        (@source, @event_id, @agent_id, @agent_name, @agent_ip, @manager,
         @candidate, @event_type, @mode, @rule, @level,
         @event_time, @ingested, @path, @owner, @actor,
         @process, @size, @sha256, @raw);
        """;

    // Assignment order matters on MariaDB: update status LAST so every earlier
    // CASE sees the OLD status. Preserve active leases and retry backoff.
    // This importer does NOT claim/complete jobs or recover expired leases.
    private const string UpsertQueueSql = """
        INSERT INTO wazuh_audit_poc.candidate_work_queue
        (source_instance, agent_id, candidate_id, candidate_folder,
         status, event_version, completed_version, attempt_count,
         last_audit_event_id, available_at_utc, created_at_utc, updated_at_utc)
        VALUES
        (@source, @agent_id, @candidate, @folder, 'pending', 1, 0, 0,
         @audit_id, @now, @now, @now)
        ON DUPLICATE KEY UPDATE
            event_version = event_version + 1,
            last_audit_event_id = VALUES(last_audit_event_id),
            available_at_utc = CASE WHEN status IN ('processing','retry')
                THEN available_at_utc ELSE VALUES(available_at_utc) END,
            attempt_count = CASE WHEN status IN ('processing','retry')
                THEN attempt_count ELSE 0 END,
            claimed_version = CASE WHEN status='processing' THEN claimed_version ELSE NULL END,
            lease_token = CASE WHEN status='processing' THEN lease_token ELSE NULL END,
            lease_expires_at_utc = CASE WHEN status='processing' THEN lease_expires_at_utc ELSE NULL END,
            last_error = CASE WHEN status IN ('processing','retry') THEN last_error ELSE NULL END,
            updated_at_utc = VALUES(updated_at_utc),
            status = CASE WHEN status IN ('processing','retry') THEN status ELSE 'pending' END;
        """;
}
