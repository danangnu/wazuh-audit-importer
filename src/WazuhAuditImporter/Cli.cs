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
            if (command is not ("import" or "check-db" or "collect-once" or "collect" or "worker-preflight" or "work-once" or "work" or "solr-readonly" or "solr-collision-audit" or "solr-plan-actions" or "solr-build-payloads" or "solr-execute" or "baseline-status" or "baseline-capture" or "baseline-approve" or "baseline-triage" or "baseline-approve-clean" or "baseline-review-small-drift" or "baseline-approve-small-drift" or "baseline-review-step18-small-drift" or "baseline-approve-step18-small-drift" or "recovery-inspect" or "pilot-report" or "pipeline-once" or "pipeline"))
                throw new FormatException("Unknown command. Run help for the supported commands, including the controlled Step 18 SmallDrift review and approval.");
            string? file = null, config = null, username = null, indexerUser = null, workerRoot = null, stateDir = null, reportDir = null, candidateIdsCsv = null, candidateId = null;
            string? baselineSha256 = null, reviewer = null, approvalNote = null;
            ulong? mutationId = null;
            var candidateLimit = SolrCollisionAudit.DefaultCandidateLimit;
            var maxIdLookups = SolrCollisionAudit.DefaultMaxIdLookups;
            var apply = false;
            var acknowledgeSmallDrift = false;
            double? legacyScanSeconds = null;
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
                    if (command is not ("import" or "solr-execute" or "baseline-approve" or "baseline-approve-clean" or "baseline-approve-small-drift" or "baseline-approve-step18-small-drift")) throw new FormatException("--apply is only valid with import, solr-execute, baseline-approve, baseline-approve-clean or a controlled SmallDrift approval.");
                    apply = true;
                }
                else if (option == "--ack-small-drift")
                {
                    if (command is not ("baseline-approve-small-drift" or "baseline-approve-step18-small-drift")) throw new FormatException("--ack-small-drift is only valid with a controlled SmallDrift approval.");
                    acknowledgeSmallDrift = true;
                }
                else if (option == "--mutation-id")
                {
                    if (command is not ("solr-execute" or "recovery-inspect")) throw new FormatException("--mutation-id is only valid with solr-execute or recovery-inspect.");
                    if (i == args.Length || args[i].StartsWith("--", StringComparison.Ordinal) ||
                        !ulong.TryParse(args[i++], System.Globalization.NumberStyles.None, System.Globalization.CultureInfo.InvariantCulture, out var parsedMutation) || parsedMutation == 0)
                        throw new FormatException("--mutation-id requires a positive integer value.");
                    mutationId = parsedMutation;
                }
                else if (option is "--candidate-limit" or "--max-id-lookups")
                {
                    if (command != "solr-collision-audit") throw new FormatException(option + " is only valid with solr-collision-audit.");
                    if (i == args.Length || args[i].StartsWith("--", StringComparison.Ordinal) ||
                        !int.TryParse(args[i++], NumberStyles.None, CultureInfo.InvariantCulture, out var parsed))
                        throw new FormatException(option + " requires a positive integer value.");
                    if (option == "--candidate-limit") candidateLimit = parsed;
                    else maxIdLookups = parsed;
                }
                else if (option == "--legacy-scan-seconds")
                {
                    if (command != "pilot-report") throw new FormatException("--legacy-scan-seconds is only valid with pilot-report.");
                    if (i == args.Length || args[i].StartsWith("--", StringComparison.Ordinal) ||
                        !double.TryParse(args[i++], NumberStyles.Float, CultureInfo.InvariantCulture, out var parsedLegacy) ||
                        parsedLegacy <= 0 || !double.IsFinite(parsedLegacy))
                        throw new FormatException("--legacy-scan-seconds requires a positive finite number.");
                    legacyScanSeconds = parsedLegacy;
                }
                else if (option == "--candidate-ids")
                {
                    if (command != "solr-collision-audit") throw new FormatException("--candidate-ids is only valid with solr-collision-audit.");
                    if (i == args.Length || args[i].StartsWith("--", StringComparison.Ordinal))
                        throw new FormatException("--candidate-ids requires a comma-separated value.");
                    candidateIdsCsv = args[i++];
                }
                else if (option == "--candidate-id")
                {
                    if (command is not ("solr-plan-actions" or "solr-build-payloads" or "baseline-capture" or "baseline-approve" or "baseline-triage" or "baseline-approve-clean" or "baseline-review-small-drift" or "baseline-approve-small-drift" or "baseline-review-step18-small-drift" or "baseline-approve-step18-small-drift" or "recovery-inspect"))
                        throw new FormatException("--candidate-id is only valid with candidate-scoped planning, baseline review/approval, or recovery inspection.");
                    if (i == args.Length || args[i].StartsWith("--", StringComparison.Ordinal))
                        throw new FormatException("--candidate-id requires a candidate ID value.");
                    candidateId = args[i++];
                }
                else if (option == "--baseline-sha256")
                {
                    if (command is not ("baseline-approve" or "baseline-approve-clean" or "baseline-approve-small-drift" or "baseline-approve-step18-small-drift")) throw new FormatException("--baseline-sha256 is only valid with baseline approval commands.");
                    if (i == args.Length || args[i].StartsWith("--", StringComparison.Ordinal))
                        throw new FormatException("--baseline-sha256 requires a 64-character SHA-256 value.");
                    baselineSha256 = args[i++];
                }
                else if (option == "--reviewer")
                {
                    if (command is not ("baseline-approve" or "baseline-approve-clean" or "baseline-approve-small-drift" or "baseline-approve-step18-small-drift")) throw new FormatException("--reviewer is only valid with baseline approval commands.");
                    if (i == args.Length || args[i].StartsWith("--", StringComparison.Ordinal))
                        throw new FormatException("--reviewer requires a value.");
                    reviewer = args[i++];
                }
                else if (option == "--approval-note")
                {
                    if (command is not ("baseline-approve" or "baseline-approve-clean" or "baseline-approve-small-drift" or "baseline-approve-step18-small-drift")) throw new FormatException("--approval-note is only valid with baseline approval commands.");
                    if (i == args.Length || args[i].StartsWith("--", StringComparison.Ordinal))
                        throw new FormatException("--approval-note requires a value.");
                    approvalNote = args[i++];
                }
                else if (option is "--config" or "--db-user" or "--indexer-user" or "--worker-root" or "--state-dir" or "--report-dir")
                {
                    if (i == args.Length || args[i].StartsWith("--", StringComparison.Ordinal))
                        throw new FormatException("Missing value for " + option);
                    if (option == "--config") config = args[i++];
                    else if (option == "--db-user") username = args[i++];
                    else if (option == "--indexer-user") indexerUser = args[i++];
                    else if (option == "--worker-root") workerRoot = args[i++];
                    else if (option == "--state-dir") stateDir = args[i++];
                    else reportDir = args[i++];
                }
                else throw new FormatException("Unknown option: " + option);
            }
            var settings = ImportSettings.Load(config);
            Console.WriteLine("Wazuh Audit Importer - pilot");
            Console.WriteLine(command switch
            {
                "worker-preflight" or "work-once" or "work" => "Candidate worker may read file metadata only. No source-file changes. No Solr writes.\n",
                "solr-readonly" => "Step 9 may read FLOSVR01 file metadata and query Solr using HTTP GET only. No Solr writes.\n",
                "solr-collision-audit" => "Step 14A audits generated legacy IDs across a controlled candidate subset and checks current Solr unique-key ownership using GET only. No DB/Solr writes.\n",
                "solr-plan-actions" => "Step 10A reads FLOSVR01 metadata and Solr using GET, then stores concrete dry-run actions in MariaDB. No Solr writes.\n",
                "solr-build-payloads" => "Step 10B may read source document content to build/stash reviewed Solr update payloads. No Solr writes.\n",
                "solr-execute" => apply
                    ? "Step 11 controlled Solr execution. --apply MAY write reviewed actions to the approved AlliedSolrCore after safety gates pass.\n"
                    : "Step 11 preflight only. Reads DB/source/Solr state; no Solr or MariaDB status writes.\n",
                "baseline-status" => "Step 14C baseline enrollment status. Reads MariaDB only; no Solr writes.\n",
                "baseline-capture" => "Step 14C baseline capture. Reads FLOSVR01 metadata + Solr GET and stores review evidence in MariaDB; no Solr writes.\n",
                "baseline-approve" => apply
                    ? "Step 14C baseline approval. Revalidates the exact captured baseline, then records operator approval in MariaDB only. No Solr writes.\n"
                    : "Step 14C baseline approval preview. Revalidates the exact captured baseline; no status or Solr writes.\n",
                "baseline-triage" => "Step 16 read-only baseline triage. Revalidates pending captures against FLOSVR01 metadata + Solr GET and writes local reports only. No approvals or Solr writes.\n",
                "baseline-approve-clean" => apply
                    ? "Step 16 clean-only baseline approval. Requires exact live fingerprint plus zero missing/stale/conflicts, then records approval in MariaDB only. No Solr writes.\n"
                    : "Step 16 clean-only approval preview. Requires exact live fingerprint plus zero missing/stale/conflicts; no status or Solr writes.\n",
                "baseline-review-small-drift" => "Step 17 controlled SmallDrift review. Revalidates only the initial three-candidate batch and prints exact missing/stale evidence. Read/report only; no approvals or Solr writes.\n",
                "baseline-approve-small-drift" => apply
                    ? "Step 17 reviewed SmallDrift approval. Requires exact live fingerprint, initial-batch scope, one missing + one stale, explicit acknowledgement, then records baseline approval only. No Solr writes.\n"
                    : "Step 17 reviewed SmallDrift approval preview. Revalidates exact one-missing/one-stale evidence; no status or Solr writes.\n",
                "baseline-review-step18-small-drift" => "Step 18 controlled three-candidate SmallDrift review. Read/report only; no approvals or Solr writes.\n",
                "baseline-approve-step18-small-drift" => apply
                    ? "Step 18 reviewed SmallDrift baseline approval. Records approval in MariaDB only; no Solr writes.\n"
                    : "Step 18 reviewed SmallDrift approval preview. No status or Solr writes.\n",
                "recovery-inspect" => "Step 14D read-only recovery inspection. Reads MariaDB state plus FLOSVR01 metadata/Solr GET. Never retries or writes Solr.\n",
                "pilot-report" => "Step 14E pilot metrics/report. Reads MariaDB, FLOSVR01 metadata and Solr GET only; writes report files only. No Solr writes.\n",
                "pipeline-once" or "pipeline" => settings.CandidateIds.Length > 1
                    ? "Step 14D failure-isolated baseline-gated multi-candidate orchestration. Explicit allowlist only; NEVER writes to Solr.\n"
                    : "Step 12 approval-gated orchestration. May collect events, reconcile metadata, read source content, store plans/payloads and run Step 11 preflight. NEVER writes to Solr.\n",
                _ => "No Solr writes. No source-document access.\n"
            });

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


            if (command == "worker-preflight")
            {
                if (string.IsNullOrWhiteSpace(workerRoot))
                    throw new FormatException("worker-preflight requires --worker-root <accessible candidate root>.");
                return CandidateWorker.Preflight(settings, workerRoot);
            }

            if (command == "solr-readonly")
            {
                if (string.IsNullOrWhiteSpace(workerRoot))
                    throw new FormatException("solr-readonly requires --worker-root <accessible FLOSVR01 candidate root>.");
                return SolrReadOnlyDiscovery.Run(settings, workerRoot, reportDir);
            }

            if (command == "solr-collision-audit")
            {
                if (string.IsNullOrWhiteSpace(workerRoot))
                    throw new FormatException("solr-collision-audit requires --worker-root <accessible FLOSVR01 candidate root>.");
                IReadOnlyList<string>? explicitIds = null;
                if (!string.IsNullOrWhiteSpace(candidateIdsCsv))
                {
                    explicitIds = candidateIdsCsv.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
                    if (explicitIds.Count == 0)
                        throw new FormatException("--candidate-ids did not contain any candidate IDs.");
                }
                return SolrCollisionAudit.Run(settings, workerRoot, reportDir, candidateLimit, maxIdLookups, explicitIds);
            }

            if ((command is "solr-plan-actions" or "solr-build-payloads" or "solr-execute" or "baseline-capture" or "baseline-approve" or "baseline-triage" or "baseline-approve-clean" or "baseline-review-small-drift" or "baseline-approve-small-drift" or "baseline-review-step18-small-drift" or "baseline-approve-step18-small-drift" or "recovery-inspect" or "pilot-report") && string.IsNullOrWhiteSpace(workerRoot))
                throw new FormatException($"{command} requires --worker-root <accessible FLOSVR01 candidate root>.");
            if (command == "solr-execute" && mutationId is null)
                throw new FormatException("solr-execute requires --mutation-id <positive integer>.");
            if (command is "baseline-approve" or "baseline-approve-clean" or "baseline-approve-small-drift" or "baseline-approve-step18-small-drift")
            {
                if (string.IsNullOrWhiteSpace(candidateId)) throw new FormatException($"{command} requires --candidate-id <id>.");
                if (string.IsNullOrWhiteSpace(baselineSha256)) throw new FormatException($"{command} requires --baseline-sha256 <sha256>.");
            }

            if ((command is "work-once" or "work" or "pipeline-once" or "pipeline") && string.IsNullOrWhiteSpace(workerRoot))
                throw new FormatException($"{command} requires --worker-root <accessible candidate root>.");
            if ((command is "work-once" or "work" or "pipeline-once" or "pipeline") && string.IsNullOrWhiteSpace(stateDir))
                throw new FormatException($"{command} requires --state-dir <persistent local worker state directory>.");

            username ??= settings.DatabaseUser;
            if (string.IsNullOrWhiteSpace(username))
            {
                if (Console.IsInputRedirected) throw new InvalidOperationException("Use --db-user for non-interactive input.");
                Console.Write("MariaDB username (local account): ");
                username = Console.ReadLine()?.Trim();
            }
            if (string.IsNullOrWhiteSpace(username)) throw new FormatException("A database username is required.");
            var password = Environment.GetEnvironmentVariable("WAZUH_DB_PASSWORD") ?? ReadPassword("MariaDB password (not saved): ");

            if (command == "work")
            {
                try
                {
                    return ContinuousWorker.Run(settings, username, password, workerRoot!, stateDir!);
                }
                finally
                {
                    password = string.Empty;
                }
            }

            if (command == "collect")
            {
                indexerUser ??= "admin";
                var indexerPassword = Environment.GetEnvironmentVariable("WAZUH_INDEXER_PASSWORD") ??
                    ReadPassword($"Wazuh Indexer password for {indexerUser} (not saved): ");
                try
                {
                    return ContinuousCollector.Run(settings, username, password, indexerUser, indexerPassword);
                }
                finally
                {
                    password = string.Empty;
                    indexerPassword = string.Empty;
                }
            }

            if (command is "pipeline-once" or "pipeline")
            {
                indexerUser ??= "admin";
                var indexerPassword = Environment.GetEnvironmentVariable("WAZUH_INDEXER_PASSWORD") ??
                    ReadPassword($"Wazuh Indexer password for {indexerUser} (not saved): ");
                try
                {
                    return command == "pipeline"
                        ? PipelineOrchestrator.RunContinuous(settings, username, password, indexerUser, indexerPassword,
                            workerRoot!, stateDir!, reportDir)
                        : PipelineOrchestrator.RunOnce(settings, username, password, indexerUser, indexerPassword,
                            workerRoot!, stateDir!, reportDir);
                }
                finally
                {
                    password = string.Empty;
                    indexerPassword = string.Empty;
                }
            }

            using var connection = AuditRepository.Open(settings, username, password);
            password = string.Empty;

            if (command == "baseline-status")
            {
                BaselineEnrollmentService.PrintStatus(settings, connection);
                return 0;
            }
            if (command == "baseline-capture")
            {
                var captured = BaselineEnrollmentService.Capture(settings, connection, workerRoot!, reportDir, candidateId);
                Console.WriteLine($"\nSTEP 14C BASELINE CAPTURE COMPLETE. candidates={captured.Count}; no Solr writes.");
                return 0;
            }
            if (command == "baseline-approve")
            {
                reviewer ??= Environment.UserDomainName + "\\" + Environment.UserName;
                _ = BaselineEnrollmentService.Approve(settings, connection, workerRoot!, candidateId!, baselineSha256!, reviewer, approvalNote, apply);
                return 0;
            }
            if (command == "baseline-triage")
            {
                return BaselineTriageService.Run(settings, connection, workerRoot!, reportDir, candidateId);
            }
            if (command == "baseline-approve-clean")
            {
                reviewer ??= Environment.UserDomainName + "\\" + Environment.UserName;
                _ = BaselineTriageService.ApproveClean(settings, connection, workerRoot!, candidateId!, baselineSha256!, reviewer, approvalNote, apply);
                return 0;
            }
            if (command == "baseline-review-small-drift")
            {
                return Step17SmallDriftService.Review(settings, connection, workerRoot!, reportDir, candidateId);
            }
            if (command == "baseline-approve-small-drift")
            {
                reviewer ??= Environment.UserDomainName + "\\" + Environment.UserName;
                _ = Step17SmallDriftService.Approve(settings, connection, workerRoot!, candidateId!, baselineSha256!, reviewer, approvalNote, acknowledgeSmallDrift, apply);
                return 0;
            }
            if (command == "baseline-review-step18-small-drift")
                return Step18SmallDriftService.Review(settings, connection, workerRoot!, reportDir, candidateId);
            if (command == "baseline-approve-step18-small-drift")
            {
                reviewer ??= Environment.UserDomainName + "\\" + Environment.UserName;
                _ = Step18SmallDriftService.Approve(settings, connection, workerRoot!, candidateId!, baselineSha256!, reviewer, approvalNote, acknowledgeSmallDrift, apply);
                return 0;
            }
            if (command == "recovery-inspect")
            {
                return RecoveryInspection.Run(settings, connection, workerRoot!, reportDir, candidateId, mutationId);
            }
            if (command == "pilot-report")
            {
                return PilotMetricsService.Run(settings, connection, workerRoot!, reportDir, legacyScanSeconds);
            }

            if (command == "solr-plan-actions")
            {
                return candidateId is null
                    ? SolrConcreteActionPlanner.Run(settings, connection, workerRoot!, reportDir)
                    : SolrConcreteActionPlanner.Run(settings, connection, workerRoot!, reportDir, candidateId);
            }
            if (command == "solr-build-payloads")
            {
                return candidateId is null
                    ? SolrPayloadPlanner.Run(settings, connection, workerRoot!, reportDir)
                    : SolrPayloadPlanner.Run(settings, connection, workerRoot!, reportDir, candidateId);
            }
            if (command == "solr-execute")
            {
                return SolrExecutor.Run(settings, connection, workerRoot!, mutationId!.Value, apply);
            }

            if (command == "check-db")
            {
                using var counts = new MySqlCommand("""
                    SELECT
                        (SELECT COUNT(*) FROM wazuh_audit_poc.audit_event),
                        (SELECT COUNT(*) FROM wazuh_audit_poc.candidate_work_queue),
                        (SELECT COUNT(*) FROM wazuh_audit_poc.collector_checkpoint),
                        (SELECT COUNT(*) FROM wazuh_audit_poc.solr_mutation_queue),
                        (SELECT COUNT(*) FROM wazuh_audit_poc.solr_mutation_action),
                        (SELECT COUNT(*) FROM wazuh_audit_poc.solr_action_payload),
                        (SELECT COUNT(*) FROM wazuh_audit_poc.candidate_baseline_enrollment),
                        (SELECT COUNT(*) FROM wazuh_audit_poc.candidate_baseline_enrollment_history);
                    """, connection);
                using var reader = counts.ExecuteReader();
                reader.Read();
                Console.WriteLine($"Rows: audit_event={reader.GetValue(0)}; candidate_work_queue={reader.GetValue(1)}; collector_checkpoint={reader.GetValue(2)}; solr_mutation_queue={reader.GetValue(3)}; solr_mutation_action={reader.GetValue(4)}; solr_action_payload={reader.GetValue(5)}; candidate_baseline_enrollment={reader.GetValue(6)}; candidate_baseline_enrollment_history={reader.GetValue(7)}");
                Console.WriteLine("Database check completed. No application rows changed.");
                return 0;
            }

            if (command == "work-once")
            {
                return CandidateWorker.RunOnce(settings, connection, workerRoot!, stateDir!);
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
        catch (SolrExecutionException ex)
        {
            Console.Error.WriteLine("SOLR EXECUTION ERROR: " + ex.Message);
            Console.Error.WriteLine("If any update POST had started, treat Solr state as uncertain until read-only verification is completed.");
            return 10;
        }
        catch (SolrPayloadException ex)
        {
            Console.Error.WriteLine("SOLR PAYLOAD ERROR: " + ex.Message);
            Console.Error.WriteLine("No Solr write was attempted.");
            return 8;
        }
        catch (SolrConcreteActionException ex)
        {
            Console.Error.WriteLine("SOLR PLAN ERROR: " + ex.Message);
            Console.Error.WriteLine("No Solr write was attempted. No concrete action rows should be committed on a blocked plan.");
            return 7;
        }
        catch (SolrReadOnlyException ex)
        {
            Console.Error.WriteLine("SOLR READ-ONLY ERROR: " + ex.Message);
            Console.Error.WriteLine("No Solr write was attempted. Verify read-only connectivity/schema before proceeding.");
            return 6;
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
          collect-once                              Read one scoped FIM window through local SSH tunnel,
                                                    import/deduplicate it, then advance checkpoint.
          collect                                   Continuously poll scoped FIM alerts, retry transient
                                                    failures, and stop cleanly with Ctrl+C.
          worker-preflight --worker-root <root>      Verify metadata read access for every explicitly allowed candidate;
                                                    no DB writes and no queue claim.
          work-once --worker-root <root>             Claim one due candidate, reconcile file metadata against
                    --state-dir <dir>                its last completed versioned snapshot, then complete/requeue.
          work --worker-root <root>                  Continuously claim/reconcile due candidates using the same
               --state-dir <dir>                     lease/version rules; stop cleanly with Ctrl+C.
          solr-readonly --worker-root <root>         Step 9: query the approved AlliedSolrCore using GET only and
                                                    compare every explicitly allowed candidate against FLOSVR01 metadata.
                       [--report-dir <dir>]          Optionally save a local JSON report; no DB/Solr writes.
          solr-collision-audit --worker-root <root> Step 14A: metadata-only controlled multi-candidate audit of the
                               [--candidate-limit N] filename-derived legacy Solr IDs plus GET-only current ID ownership.
                               [--candidate-ids a,b] Explicit IDs override automatic controlled selection.
                               [--max-id-lookups N] Default 1000; hard cap 5000 unique-key GETs per run.
                               [--report-dir <dir>]  Save JSON + CSV findings. No MariaDB connection or Solr writes.
          solr-plan-actions --worker-root <root>     Step 10A: expand a latest completed candidate reindex plan
                           [--candidate-id <id>]     into concrete delete/index rows. Required when config has >1 candidate.
                           [--report-dir <dir>]      Solr remains read-only.
          solr-build-payloads --worker-root <root>  Step 10B: build/stash exact reviewed delete/index JSON payloads.
                              [--candidate-id <id>] Required when config has >1 candidate.
                              [--report-dir <dir>]  Reads source content; never posts to Solr.
          solr-execute --mutation-id <id>           Step 11 preflight: revalidate exact mutation, payload/source hashes,
                       --worker-root <root>          and current Solr/disk state. No writes without --apply.
          solr-execute --mutation-id <id>           Step 11 controlled execution after all gates pass.
                       --worker-root <root> --apply  Posts reviewed actions, explicit commit, GET verification, DB status update.
          baseline-status                           Step 14C: show captured/approved baseline state for every allowlisted candidate.
          baseline-capture --worker-root <root>      Capture/refresh pending baseline evidence using FLOSVR01 metadata + Solr GET.
                           [--candidate-id <id>]      Without candidate-id, captures all allowlisted candidates.
                           [--report-dir <dir>]       Approved evidence is never silently replaced.
          baseline-approve --candidate-id <id>       Revalidate exact baseline fingerprint. Preview only unless --apply.
                           --baseline-sha256 <sha>
                           --worker-root <root>
                           [--reviewer <name>] [--approval-note <text>] [--apply]
          baseline-triage --worker-root <root>      Step 16: revalidate/classify pending baselines as clean/small/moderate/high/conflict/stale.
                          [--candidate-id <id>]      Read/report only; no baseline status or Solr writes.
                          [--report-dir <dir>]
          baseline-approve-clean --candidate-id <id> Step 16: clean-only approval. Rejects any missing/stale/conflict drift.
                                 --baseline-sha256 <sha>
                                 --worker-root <root>
                                 [--reviewer <name>] [--approval-note <text>] [--apply]
          baseline-review-small-drift --worker-root <root> Step 17: read-only exact review for initial candidates 1180002,1180007,1180009.
                                      [--candidate-id <id>] [--report-dir <dir>]
          baseline-approve-small-drift --candidate-id <id> Step 17: approve only exact one-missing/one-stale initial-batch drift.
                                      --baseline-sha256 <sha> --worker-root <root>
                                      [--reviewer <name>] [--approval-note <text>] [--ack-small-drift] [--apply]
          baseline-review-step18-small-drift --worker-root <root> Step 18: read-only exact review of 1180011,1180012,1180014.
                                      [--candidate-id <id>] [--report-dir <dir>]
          baseline-approve-step18-small-drift --candidate-id <id> Step 18: individual reviewed baseline enrollment only.
                                      --baseline-sha256 <sha> --worker-root <root>
                                      [--reviewer <name>] [--approval-note <text>] [--ack-small-drift] [--apply]
          recovery-inspect --worker-root <root>      Step 14D: read-only recovery inspection of latest mutation state
                           [--candidate-id <id>]      for one or every allowlisted candidate. Optionally select a specific
                           [--mutation-id <id>]       mutation. processing/failed states are never authorized for blind retry.
                           [--report-dir <dir>]
          pilot-report --worker-root <root>          Step 14E: generate JSON/CSV metrics plus a Markdown pilot delivery report.
                       [--report-dir <dir>]           Reads MariaDB, FLOSVR01 metadata and Solr GET only.
                       [--legacy-scan-seconds <n>]   Optional operator-supplied legacy scan timing for a labeled reference-only comparison.
          pipeline-once --worker-root <root>         Step 14D: baseline-gated multi-candidate cycle with per-candidate
                        --state-dir <dir>            source failure isolation; no Solr update API calls.
                        [--report-dir <dir>]
          pipeline --worker-root <root>              Step 14D continuous orchestration. Candidate source failures are
                   --state-dir <dir>                 moved to retry and do not block healthy candidates in the same cycle.
                   [--report-dir <dir>]              It NEVER calls the Solr update API; apply remains separate per mutation.

        Optional: --config <path.json>  --db-user <username>  --indexer-user <username>
                  --worker-root <fully-qualified local/UNC root>  --state-dir <local state directory>
                  --report-dir <optional local Step 9 JSON report directory>
        DB password: WAZUH_DB_PASSWORD or interactive prompt.
        Indexer password: WAZUH_INDEXER_PASSWORD or interactive prompt.
        Collector default Indexer URL: https://127.0.0.1:19200 (local SSH tunnel only).
        Default DB: 127.0.0.1:3306 / wazuh_audit_poc, expected host MGMTNB08.
        Default scope: FLOSVR01 / 001 / candidate 1180097 only.
        Step 14B config: importer.step14b.pilot.json explicitly allows only
        1180000,1180001,1180002,1180003,1180097 (maximum active allowlist = 5).
        Worker commands process only the explicit pilot queue/root. Step 8 persists a dry-run
        candidate-level Solr plan in MariaDB. Step 9 adds read-only Solr discovery. Step 10A
        stores concrete action plans; Step 10B stores reviewed payloads. Step 11 is the first
        command that can call the Solr update API, and only with an explicit mutation id plus --apply.
        Step 14C adds a candidate baseline-enrollment gate before Step 10A. Newly allowlisted candidates
        are captured as pending and remain BaselineReviewRequired until an operator approves the exact
        baseline SHA-256. Manual Step 10A, Step 10B and Step 11 are also baseline-gated.
        Step 14D adds recovery inspection plus per-candidate source-failure isolation. processing/failed
        Solr mutations are treated as uncertain and are never blindly retried. Pipeline commands never
        perform Solr update/delete/add/commit requests. Each allowlisted candidate remains independent.
        Step 14E adds read-only pilot metrics and a delivery report. It derives observed event/ingest/worker/
        payload/apply timings from persisted UTC timestamps and does not claim a legacy-scan speedup unless
        an operator supplies a measured --legacy-scan-seconds reference.
        Step 16 adds read-only baseline triage plus a clean-only approval command. Pending baselines are
        revalidated live; only exact, fully matched baselines can pass clean-only approval. Drifted, conflicted
        or stale captures stay gated and require separate operator review. No Step 16 command auto-applies Solr.
        Step 17 adds a deliberately narrow SmallDrift path for the initial three-candidate batch
        1180002,1180007,1180009. Approval requires an unchanged fingerprint, exactly one missing current
        document plus one stale Solr document, no other conflicts, and explicit --ack-small-drift with --apply.
        Approval only enrolls the reviewed baseline; it never repairs or writes Solr. Historical reconciliation
        still goes through the normal Step 10/11 review and explicit Solr --apply gate.
        Step 18 selects only 1180011,1180012,1180014 for a fresh one-for-one review. Step 17 scope is unchanged.
        No Step 18 command expands the FIM/importer allowlist or automatically applies a Solr mutation.
        """);
}
