using System.Text.Json;
using MySqlConnector;

namespace WazuhAuditImporter;

public static class CheckpointRepository
{
    public static CollectorCursor? Read(MySqlConnection connection, ImportSettings settings)
    {
        using var cmd = new MySqlCommand("""
            SELECT cursor_text, last_wazuh_event_id
            FROM wazuh_audit_poc.collector_checkpoint
            WHERE source_instance=@source AND stream_key=@stream;
            """, connection);
        cmd.Parameters.AddWithValue("@source", settings.SourceInstance);
        cmd.Parameters.AddWithValue("@stream", settings.CollectorStreamKey);
        using var reader = cmd.ExecuteReader();
        if (!reader.Read()) return null;
        if (reader.IsDBNull(0))
            throw new EventConflictException("Collector checkpoint exists without cursor_text.");
        var cursorJson = reader.GetString(0);
        string? last = reader.IsDBNull(1) ? null : reader.GetString(1);
        using var doc = JsonDocument.Parse(cursorJson);
        if (doc.RootElement.ValueKind != JsonValueKind.Object ||
            !doc.RootElement.TryGetProperty("through_utc", out var through) ||
            through.ValueKind != JsonValueKind.String)
            throw new EventConflictException("Collector checkpoint cursor format is invalid.");
        var parsed = AlertParser.ParseTimestamp(through.GetString()!);
        return new CollectorCursor(parsed, last);
    }

    public static void Upsert(MySqlConnection connection, ImportSettings settings, CollectorCursor cursor)
    {
        using var tx = connection.BeginTransaction();
        try
        {
            DateTime now;
            using (var clock = new MySqlCommand("SELECT UTC_TIMESTAMP(6);", connection, tx))
                now = DateTime.SpecifyKind(Convert.ToDateTime(clock.ExecuteScalar()), DateTimeKind.Utc);

            var cursorText = JsonSerializer.Serialize(new
            {
                through_utc = cursor.ThroughUtc.ToUniversalTime().ToString("yyyy-MM-dd'T'HH:mm:ss.ffffff'Z'")
            });

            using var cmd = new MySqlCommand("""
                INSERT INTO wazuh_audit_poc.collector_checkpoint
                (source_instance, stream_key, input_kind, input_location, cursor_text,
                 last_wazuh_event_id, updated_at_utc)
                VALUES
                (@source, @stream, 'wazuh-indexer-search', @location, @cursor, @last, @now)
                ON DUPLICATE KEY UPDATE
                    input_kind=VALUES(input_kind),
                    input_location=VALUES(input_location),
                    cursor_text=VALUES(cursor_text),
                    last_wazuh_event_id=VALUES(last_wazuh_event_id),
                    updated_at_utc=VALUES(updated_at_utc);
                """, connection, tx);
            cmd.Parameters.AddWithValue("@source", settings.SourceInstance);
            cmd.Parameters.AddWithValue("@stream", settings.CollectorStreamKey);
            cmd.Parameters.AddWithValue("@location", settings.IndexerBaseUrl + "/" + settings.IndexerIndexPattern);
            cmd.Parameters.AddWithValue("@cursor", cursorText);
            cmd.Parameters.AddWithValue("@last", (object?)cursor.LastWazuhEventId ?? DBNull.Value);
            cmd.Parameters.AddWithValue("@now", now);
            cmd.ExecuteNonQuery();
            tx.Commit();
        }
        catch
        {
            try { tx.Rollback(); } catch { }
            throw;
        }
    }
}
