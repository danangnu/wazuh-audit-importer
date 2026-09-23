using System.Text.Json;
using MySqlConnector;

namespace WazuhAuditImporter;

public static class SolrPayloadPlanner
{
    public static int Run(ImportSettings settings, MySqlConnection connection, string workerRoot, string? reportDir)
    {
        if (settings.CandidateIds.Length != 1)
            throw new FormatException("solr-build-payloads requires --candidate-id when the active allowlist contains multiple candidates.");
        return Run(settings, connection, workerRoot, reportDir, settings.CandidateIds[0]);
    }

    public static int Run(ImportSettings settings, MySqlConnection connection, string workerRoot, string? reportDir, string candidateId)
    {
        settings.ValidateWorker(workerRoot, Path.Combine(Path.GetTempPath(), "wazuh-payload-validation"));
        settings.ValidateAllowedCandidate(candidateId);
        var target = SolrConcreteActionRepository.ReadLatestTarget(connection, settings, candidateId);
        var actions = SolrPayloadRepository.ReadActions(connection, target);
        if (actions.Any(x => x.ActionStatus != "planned"))
            throw new SolrPayloadException("All concrete actions must remain status=planned before Step 10B payload generation.");

        var generatedAt = DbUtcNow(connection);
        var existingPayloads = SolrPayloadRepository.ReadExistingPayloads(connection, target.MutationId);
        var payloads = actions.OrderBy(x => x.ActionOrder)
            .Select(x => existingPayloads.TryGetValue(x.ActionId, out var existing)
                ? existing
                : SolrPayloadBuilder.Build(x, workerRoot, generatedAt)).ToList();
        var write = SolrPayloadRepository.EnsurePayloads(connection, target, payloads);

        Console.WriteLine("Step 10B Solr payload generation - DRY RUN ONLY.");
        Console.WriteLine("Source file CONTENT may be read for index_document actions. No source file is changed.");
        Console.WriteLine("No HTTP request to Solr update APIs is made.");
        Console.WriteLine($"Target mutation: id={target.MutationId} candidate={target.CandidateId} worker_version={target.WorkerVersion}");
        foreach (var p in payloads)
        {
            Console.WriteLine($"  PAYLOAD action_id={p.ActionId} type={p.ActionType} status={p.Status} extractor={p.Extractor}");
            if (p.Status == "blocked")
                Console.WriteLine($"      BLOCKED reason={p.BlockReason}");
            else
                Console.WriteLine($"      payload_sha256={p.PayloadSha256} content_chars={(p.ContentCharCount?.ToString() ?? "n/a")}");
        }
        Console.WriteLine($"Stored payload rows: total={write.Total}; inserted={write.Inserted}; existing={write.Existing}");

        if (!string.IsNullOrWhiteSpace(reportDir))
        {
            Directory.CreateDirectory(reportDir);
            var report = new SolrPayloadReport(target.MutationId, target.CandidateId, target.WorkerVersion,
                Path.GetFullPath(workerRoot), payloads, generatedAt);
            var path = Path.Combine(reportDir, $"solr-payloads-{candidateId}-v{target.WorkerVersion}-{DateTime.UtcNow:yyyyMMdd-HHmmss}.json");
            File.WriteAllText(path, JsonSerializer.Serialize(report, new JsonSerializerOptions { WriteIndented = true }));
            Console.WriteLine("Payload report saved: " + Path.GetFullPath(path));
        }

        Console.WriteLine("\nSTEP 10B COMPLETE. No Solr writes, deletes, adds or commits occurred.");
        if (payloads.Any(x => x.Status == "blocked"))
        {
            Console.WriteLine("One or more payloads are BLOCKED and must not be executed until their reason is resolved.");
            return 9;
        }
        return 0;
    }

    private static DateTime DbUtcNow(MySqlConnection connection)
    {
        using var cmd = new MySqlCommand("SELECT UTC_TIMESTAMP(6);", connection);
        return DateTime.SpecifyKind(Convert.ToDateTime(cmd.ExecuteScalar(), System.Globalization.CultureInfo.InvariantCulture), DateTimeKind.Utc);
    }
}
