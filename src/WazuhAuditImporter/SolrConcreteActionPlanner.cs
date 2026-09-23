using System.Text.Json;
using MySqlConnector;

namespace WazuhAuditImporter;

public static class SolrConcreteActionPlanner
{
    public static int Run(
        ImportSettings settings,
        MySqlConnection connection,
        string workerRoot,
        string? reportDirectory)
    {
        if (settings.CandidateIds.Length != 1)
            throw new FormatException("solr-plan-actions requires --candidate-id when the active allowlist contains multiple candidates.");
        return Run(settings, connection, workerRoot, reportDirectory, settings.CandidateIds[0]);
    }

    public static int Run(
        ImportSettings settings,
        MySqlConnection connection,
        string workerRoot,
        string? reportDirectory,
        string candidateId)
    {
        settings.ValidateWorker(workerRoot, Path.GetFullPath("worker-state"));
        settings.ValidateSolrReadOnly();
        settings.ValidateAllowedCandidate(candidateId);
        var target = SolrConcreteActionRepository.ReadLatestTarget(connection, settings, candidateId);

        Console.WriteLine("Step 10A concrete Solr action planning - DRY RUN ONLY.");
        Console.WriteLine("FLOSVR01 is the filesystem source of truth.");
        Console.WriteLine("Solr access is HTTP GET only. MariaDB receives plan rows only; no Solr update API is called.");
        Console.WriteLine($"Target mutation: id={target.MutationId} worker_version={target.WorkerVersion} " +
                          $"mutation_status={target.MutationStatus} queue_status={target.QueueStatus}");

        using var client = new SolrReadOnlyClient(settings);
        var schema = client.ReadSchema();
        if (!schema.UniqueKey.Equals(settings.SolrIdField, StringComparison.Ordinal))
            throw new SolrConcreteActionException($"Expected unique key '{settings.SolrIdField}', schema reports '{schema.UniqueKey}'.");

        var candidateFolder = CandidateWorker.ResolveCandidateFolder(workerRoot, candidateId);
        var disk = SolrReadOnlyDiscovery.CaptureDiskFiles(workerRoot, candidateFolder, settings.SolrCanonicalRoot);
        var solrDocs = client.QueryCandidate(candidateId);
        var readOnly = SolrReadOnlyDiscovery.Compare(
            settings, candidateId, workerRoot, candidateFolder, schema, disk, solrDocs);

        var changedRelativePaths = SolrPlanRepository.ReadChangedRelativePaths(connection, target.MutationId);
        var actions = SolrConcreteActionBuilder.Build(
            target,
            readOnly,
            disk,
            solrDocs,
            id => client.QueryById(id),
            changedRelativePaths);

        Console.WriteLine($"FLOSVR01 files observed : {readOnly.DiskFilesObserved}");
        Console.WriteLine($"Solr documents          : {readOnly.SolrDocumentsFound}");
        Console.WriteLine($"Concrete actions        : {actions.Count}");
        foreach (var action in actions)
        {
            Console.WriteLine($"  PLAN {action.ActionType.ToUpperInvariant(),-15} order={action.ActionOrder} id={action.SolrDocumentId}");
            Console.WriteLine($"       path={action.CanonicalPath}");
            if (action.SourceFilePath is not null)
                Console.WriteLine($"       source={action.SourceFilePath}");
            Console.WriteLine($"       reason={action.Reason}");
        }

        var write = SolrConcreteActionRepository.EnsureActions(connection, target, actions);
        Console.WriteLine($"Stored plan rows: total={write.PlannedCount}; inserted={write.InsertedCount}; existing={write.ExistingCount}");

        var report = new SolrConcreteActionReport(
            target.MutationId,
            target.SourceInstance,
            target.AgentId,
            target.CandidateId,
            target.WorkerVersion,
            target.MutationStatus,
            target.QueueStatus,
            target.EventVersion,
            target.CompletedVersion,
            Path.GetFullPath(workerRoot),
            Path.GetFullPath(candidateFolder),
            settings.SolrBaseUrl,
            readOnly.DiskFilesObserved,
            readOnly.SolrDocumentsFound,
            readOnly.Comparisons,
            actions,
            DateTime.UtcNow);

        if (!string.IsNullOrWhiteSpace(reportDirectory))
        {
            var full = Path.GetFullPath(reportDirectory);
            Directory.CreateDirectory(full);
            var path = Path.Combine(full,
                $"solr-actions-{candidateId}-v{target.WorkerVersion}-{DateTime.UtcNow:yyyyMMdd-HHmmss}.json");
            File.WriteAllText(path, JsonSerializer.Serialize(report, new JsonSerializerOptions { WriteIndented = true }));
            Console.WriteLine($"Action report saved: {path}");
        }

        Console.WriteLine("\nSTEP 10A COMPLETE. Actions remain status=planned. No Solr writes, deletes, adds, commits or content extraction occurred.");
        return 0;
    }
}
