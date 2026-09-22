using System.Globalization;
using System.Text;
using System.Text.Json;
using MySqlConnector;

namespace WazuhAuditImporter;

public static class Cli
{
    public static int Run(string[] args)
    {
        try
        {
            if (args.Length == 0 || args[0] is "help" or "--help" or "-h")
            { Help(); return 0; }
            var command = args[0];
            if (command is not ("import" or "check-db" or "collect-once"))
                throw new FormatException("Command must be import, check-db, collect-once or help.");
            string? file = null, config = null, username = null, indexerUser = null;
            var apply = false;
            var i = 1;
            if (command == "import")
            {
                if (i == args.Length || args[i].StartsWith("--", StringComparison.Ordinal))
                    throw new FormatException("import requires a JSON file path.");
                file = args[i++];
            }
            var seen = new HashSet<string>(StringComparer.Ordinal);
            while (i < args.Length)
            {
                var option = args[i++];
                if (!seen.Add(option)) throw new FormatException("Repeated option: " + option);
                if (option == "--apply")
                {
                    if (command != "import") throw new FormatException("--apply is only valid with import.");
                    apply = true;
                }
                else if (option is "--config" or "--db-user" or "--indexer-user")
                {
                    if (i == args.Length || args[i].StartsWith("--", StringComparison.Ordinal))
                        throw new FormatException("Missing value for " + option);
                    if (option == "--config") config = args[i++];
                    else if (option == "--db-user") username = args[i++];
                    else indexerUser = args[i++];
                }
                else throw new FormatException("Unknown option: " + option);
            }
            var settings = ImportSettings.Load(config);
            Console.WriteLine("Wazuh Audit Importer - pilot");
            Console.WriteLine("No Solr writes. No source-document access.\n");

            NormalizedAlert? alert = null;
            if (command == "import")
            {
                var info = new FileInfo(file!);
                if (!info.Exists) throw new FileNotFoundException("JSON file not found.", file);
                if (info.Length > AlertParser.MaximumInputBytes)
                    throw new FormatException("File exceeds the 4 MiB single-event limit.");
                var raw = File.ReadAllText(file!, new UTF8Encoding(false, true));
                var parsed = AlertParser.Parse(raw, settings);
                if (parsed.Alert is null)
                {
                    Console.WriteLine("IGNORED: " + parsed.IgnoredReason);
                    Console.WriteLine("No database connection or writes.");
                    return 0;
                }
                alert = parsed.Alert;
                PrintPreview(alert);
                if (!apply)
                {
                    Console.WriteLine("\nPREVIEW ONLY: no database connection or writes.");
                    Console.WriteLine("Run the same import with --apply to save the audit event and candidate work item.");
                    return 0;
                }
            }

            username ??= settings.DatabaseUser;
            if (string.IsNullOrWhiteSpace(username))
            {
                if (Console.IsInputRedirected) throw new InvalidOperationException("Use --db-user for non-interactive input.");
                Console.Write("MariaDB username (local account): ");
                username = Console.ReadLine()?.Trim();
            }
            if (string.IsNullOrWhiteSpace(username)) throw new FormatException("A database username is required.");
            var password = Environment.GetEnvironmentVariable("WAZUH_DB_PASSWORD") ?? ReadPassword("MariaDB password (not saved): ");
            using var connection = AuditRepository.Open(settings, username, password);
            password = string.Empty;

            if (command == "check-db")
            {
                using var counts = new MySqlCommand("""
                    SELECT
                        (SELECT COUNT(*) FROM wazuh_audit_poc.audit_event),
                        (SELECT COUNT(*) FROM wazuh_audit_poc.candidate_work_queue),
                        (SELECT COUNT(*) FROM wazuh_audit_poc.collector_checkpoint);
                    """, connection);
                using var reader = counts.ExecuteReader();
                reader.Read();
                Console.WriteLine($"Rows: audit_event={reader.GetValue(0)}; candidate_work_queue={reader.GetValue(1)}; collector_checkpoint={reader.GetValue(2)}");
                Console.WriteLine("Database check completed. No application rows changed.");
                return 0;
            }

            if (command == "collect-once")
            {
                indexerUser ??= "admin";
                var indexerPassword = Environment.GetEnvironmentVariable("WAZUH_INDEXER_PASSWORD") ??
                    ReadPassword($"Wazuh Indexer password for {indexerUser} (not saved): ");
                var summary = IndexerCollector.CollectOnce(settings, connection, indexerUser, indexerPassword);
                indexerPassword = string.Empty;
                Console.WriteLine($"\nCOLLECT-ONCE complete: seen={summary.Seen}; accepted={summary.Accepted}; inserted={summary.Inserted}; duplicates={summary.Duplicates}; ignored={summary.Ignored}");
                Console.WriteLine($"Checkpoint advanced through UTC {summary.ThroughUtc:yyyy-MM-dd'T'HH:mm:ss.ffffff'Z'} only after successful processing.");
                Console.WriteLine("No worker was run. No Solr writes.");
                return 0;
            }

            var result = AuditRepository.Import(connection, alert!, settings);
            Console.WriteLine(result.Inserted
                ? "\nIMPORTED: one new audit event; candidate queue updated in the same transaction."
                : "\nDUPLICATE: source payload matches the stored event; audit row and queue unchanged.");
            Console.WriteLine($"audit_event_id={result.AuditEventId}; wazuh_event_id={alert!.WazuhEventId}");
            Console.WriteLine($"candidate={alert.CandidateId}; work_item_id={result.Queue.WorkItemId}; status={result.Queue.Status}; event_version={result.Queue.EventVersion}");
            Console.WriteLine("No collector checkpoint was advanced. No worker was run. No Solr writes.");
            return 0;
        }
        catch (EventConflictException ex)
        {
            Console.Error.WriteLine("CONFLICT: " + ex.Message);
            return 4;
        }
        catch (HttpRequestException ex)
        {
            Console.Error.WriteLine("INDEXER ERROR: " + ex.Message);
            Console.Error.WriteLine("Check that the SSH tunnel to 127.0.0.1:19200 is open. No checkpoint should be advanced on failure.");
            return 5;
        }
        catch (MySqlException ex)
        {
            var explanation = ex.Number switch
            {
                1045 => "Authentication rejected. Check the local database username/password; do not post the password.",
                1044 or 1142 => "The account lacks access to the audit schema/tables. Ask the DB administrator for scoped permission.",
                1049 => "Audit database not found. Confirm the schema was created on this local server.",
                1205 or 1213 => "Transaction lock timeout/deadlock. Stop and retry after other writers finish.",
                _ => "Database operation failed. Stop and report this error number. Do not drop tables or reset data."
            };
            Console.Error.WriteLine($"MariaDB error {ex.Number}: {explanation}");
            Console.Error.WriteLine("A connection failure during COMMIT can have an uncertain result. Replay/deduplication is intentional.");
            return 3;
        }
        catch (Exception ex) when (ex is JsonException or FormatException or IOException or
            UnauthorizedAccessException or InvalidOperationException or ArgumentException)
        {
            Console.Error.WriteLine("ERROR: " + ex.Message);
            return 2;
        }
    }

    private static string ReadPassword(string prompt)
    {
        if (Console.IsInputRedirected)
            throw new InvalidOperationException("Password input requires a terminal or the appropriate environment variable.");
        Console.Write(prompt);
        var buffer = new StringBuilder();
        while (true)
        {
            var key = Console.ReadKey(intercept: true);
            if (key.Key == ConsoleKey.Enter) { Console.WriteLine(); return buffer.ToString(); }
            if (key.Key == ConsoleKey.Backspace && buffer.Length > 0)
            { buffer.Length--; Console.Write("\b \b"); }
            else if (!char.IsControl(key.KeyChar) && buffer.Length < 4096)
            { buffer.Append(key.KeyChar); Console.Write('*'); }
        }
    }

    private static void PrintPreview(NormalizedAlert a) => Console.WriteLine(JsonSerializer.Serialize(new
    {
        source_instance = a.SourceInstance,
        wazuh_event_id = a.WazuhEventId,
        agent_id = a.AgentId,
        agent_name = a.AgentName,
        manager_name = a.ManagerName,
        candidate_id = a.CandidateId,
        candidate_folder = a.CandidateFolder,
        event_type = a.EventType,
        detection_mode = a.DetectionMode,
        event_time_utc = a.EventTimeUtc.ToString("yyyy-MM-dd'T'HH:mm:ss.ffffff'Z'", CultureInfo.InvariantCulture),
        source_path = a.SourcePath,
        file_owner_name = a.FileOwnerName,
        actor_name = a.ActorName,
        actor_process = a.ActorProcess,
        reported_size_bytes = a.ReportedSizeBytes,
        reported_sha256 = a.ReportedSha256
    }, new JsonSerializerOptions { WriteIndented = true }));

    private static void Help() => Console.WriteLine("""
        WazuhAuditImporter (net9.0)

          import <event.json>                       Preview only; no DB connection.
          import <event.json> --apply               Save one alert and queue its candidate.
          check-db                                  Check schema/identity/counts; no row writes.
          collect-once                              Read scoped FIM alerts through local SSH tunnel,
                                                    import/deduplicate them, then advance checkpoint.

        Optional: --config <path.json>  --db-user <username>  --indexer-user <username>
        DB password: WAZUH_DB_PASSWORD or interactive prompt.
        Indexer password: WAZUH_INDEXER_PASSWORD or interactive prompt.
        Collector default Indexer URL: https://127.0.0.1:19200 (local SSH tunnel only).
        Default DB: 127.0.0.1:3306 / wazuh_audit_poc, expected host MGMTNB08.
        Default scope: FLOSVR01 / 001 / candidate 1180097 only.
        This tool never processes queued work or writes to Solr.
        """);
}
