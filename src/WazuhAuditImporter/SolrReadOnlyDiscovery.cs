using System.Text.Json;

namespace WazuhAuditImporter;

public static class SolrReadOnlyDiscovery
{
    public static int Run(ImportSettings settings, string workerRoot, string? reportDirectory)
    {
        settings.ValidateWorker(workerRoot, Path.GetFullPath("worker-state"));
        settings.ValidateSolrReadOnly();

        Console.WriteLine("Step 9 Solr discovery - READ ONLY.");
        Console.WriteLine("Filesystem source: FLOSVR01 through the supplied worker root.");
        Console.WriteLine("Solr operations: HTTP GET only. No update, delete, add, commit, optimize or config mutation calls exist in this command.");
        Console.WriteLine($"Solr endpoint: {settings.SolrBaseUrl}");
        Console.WriteLine($"Canonical Solr root: {settings.SolrCanonicalRoot}\n");

        using var client = new SolrReadOnlyClient(settings);
        var schema = client.ReadSchema();
        Console.WriteLine($"Schema uniqueKey: {schema.UniqueKey}");
        Console.WriteLine($"Solr version    : {schema.SolrVersion ?? "(not reported by system endpoint)"}");
        if (!schema.UniqueKey.Equals(settings.SolrIdField, StringComparison.Ordinal))
            throw new SolrReadOnlyException($"Expected Solr unique key '{settings.SolrIdField}', but schema reports '{schema.UniqueKey}'. Stop before designing execution.");
        foreach (var required in new[] { settings.SolrIdField, settings.SolrCandidateField, settings.SolrPathField, settings.SolrLastUpdateField, settings.SolrContentField })
            if (!schema.Fields.ContainsKey(required))
                throw new SolrReadOnlyException($"Required field '{required}' was not returned by the schema API.");

        var reports = new List<SolrReadOnlyReport>();
        foreach (var candidateId in settings.CandidateIds)
        {
            var candidateFolder = CandidateWorker.ResolveCandidateFolder(workerRoot, candidateId);
            var disk = CaptureDiskFiles(workerRoot, candidateFolder, settings.SolrCanonicalRoot);
            var solrDocs = client.QueryCandidate(candidateId);
            var report = Compare(settings, candidateId, workerRoot, candidateFolder, schema, disk, solrDocs);
            reports.Add(report);
            PrintReport(report);
        }

        if (!string.IsNullOrWhiteSpace(reportDirectory))
        {
            var full = Path.GetFullPath(reportDirectory);
            Directory.CreateDirectory(full);
            foreach (var report in reports)
            {
                var path = Path.Combine(full, $"solr-readonly-{report.CandidateId}-{DateTime.UtcNow:yyyyMMdd-HHmmss}.json");
                File.WriteAllText(path, JsonSerializer.Serialize(report, new JsonSerializerOptions { WriteIndented = true }));
                Console.WriteLine($"Read-only report saved: {path}");
            }
        }

        Console.WriteLine("\nSTEP 9 READ-ONLY COMPLETE. No Solr writes. No source files changed. No database rows changed.");
        return 0;
    }

    public static IReadOnlyList<DiskSolrFile> CaptureDiskFiles(string workerRoot, string candidateFolder, string canonicalRoot)
    {
        if (!Directory.Exists(candidateFolder))
            throw new DirectoryNotFoundException($"Candidate folder is not accessible: {candidateFolder}");
        var rootFull = Path.GetFullPath(workerRoot).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        var list = new List<DiskSolrFile>();
        foreach (var file in Directory.EnumerateFiles(candidateFolder, "*", SearchOption.AllDirectories))
        {
            var info = new FileInfo(file);
            var relativeToRoot = Path.GetRelativePath(rootFull, info.FullName).Replace('/', '\\');
            if (relativeToRoot.Split('\\').Any(p => p is "" or "." or ".."))
                throw new InvalidOperationException($"File path escaped the configured FLOSVR01 worker root: {info.FullName}");
            var canonical = SolrPathMapper.MapRelativeToCanonicalRoot(canonicalRoot, relativeToRoot);
            var eligibility = SolrPathMapper.LegacyEligibility(info.FullName, info.Attributes);
            list.Add(new DiskSolrFile(
                Path.GetRelativePath(candidateFolder, info.FullName).Replace('/', '\\'),
                info.FullName,
                canonical,
                SolrPathMapper.GenerateLegacySolrId(canonical),
                info.Length,
                info.LastWriteTimeUtc,
                eligibility.Eligible,
                eligibility.Reason));
        }
        return list.OrderBy(x => x.RelativePath, StringComparer.OrdinalIgnoreCase).ToList();
    }

    public static SolrReadOnlyReport Compare(
        ImportSettings settings,
        string candidateId,
        string workerRoot,
        string candidateFolder,
        SolrSchemaInfo schema,
        IReadOnlyList<DiskSolrFile> diskFiles,
        IReadOnlyList<SolrReadOnlyDocument> solrDocs)
    {
        var comparisons = new List<SolrPathComparison>();
        foreach (var skipped in diskFiles.Where(x => !x.LegacyEligible))
        {
            comparisons.Add(new SolrPathComparison(
                "SKIPPED_BY_LEGACY_FILTER",
                skipped.CanonicalSolrPath,
                skipped.RelativePath,
                skipped.LegacyId,
                null,
                null,
                skipped.LegacySkipReason));
        }

        var eligible = diskFiles.Where(x => x.LegacyEligible).ToList();
        var diskByPath = eligible.GroupBy(x => SolrPathMapper.NormalizeForComparison(x.CanonicalSolrPath), StringComparer.Ordinal)
            .ToDictionary(x => x.Key, x => x.ToList(), StringComparer.Ordinal);
        var solrByPath = solrDocs.GroupBy(x => SolrPathMapper.NormalizeForComparison(x.Path), StringComparer.Ordinal)
            .ToDictionary(x => x.Key, x => x.ToList(), StringComparer.Ordinal);

        foreach (var diskGroup in diskByPath.OrderBy(x => x.Key, StringComparer.Ordinal))
        {
            var disk = diskGroup.Value[0];
            if (!solrByPath.TryGetValue(diskGroup.Key, out var matches))
            {
                comparisons.Add(new SolrPathComparison(
                    "MISSING_IN_SOLR", disk.CanonicalSolrPath, disk.RelativePath,
                    disk.LegacyId, null, null, "Eligible FLOSVR01 file has no Solr document with the canonical path."));
                continue;
            }
            if (matches.Count > 1)
            {
                comparisons.Add(new SolrPathComparison(
                    "DUPLICATE_SOLR_PATH", disk.CanonicalSolrPath, disk.RelativePath,
                    disk.LegacyId, string.Join(",", matches.Select(x => x.Id)), null,
                    $"Solr returned {matches.Count} documents with the same normalized path."));
                continue;
            }
            var solr = matches[0];
            var idMatches = solr.Id.Equals(disk.LegacyId, StringComparison.OrdinalIgnoreCase);
            comparisons.Add(new SolrPathComparison(
                idMatches ? "MATCH" : "ID_MISMATCH",
                disk.CanonicalSolrPath,
                disk.RelativePath,
                disk.LegacyId,
                solr.Id,
                solr.LastUpdate,
                idMatches ? null : "Path matches, but Solr id differs from the active legacy genSolrId filename algorithm."));
        }

        foreach (var solrGroup in solrByPath.OrderBy(x => x.Key, StringComparer.Ordinal))
        {
            if (diskByPath.ContainsKey(solrGroup.Key)) continue;
            foreach (var solr in solrGroup.Value)
            {
                comparisons.Add(new SolrPathComparison(
                    "STALE_IN_SOLR",
                    solr.Path,
                    null,
                    null,
                    solr.Id,
                    solr.LastUpdate,
                    "Solr document path has no eligible file in the current FLOSVR01 candidate inventory."));
            }
        }

        var localCollisions = eligible
            .GroupBy(x => x.LegacyId, StringComparer.OrdinalIgnoreCase)
            .Where(g => g.Count() > 1)
            .Select(g => new LegacyIdCollision(g.Key, g.Select(x => x.RelativePath).OrderBy(x => x, StringComparer.OrdinalIgnoreCase).ToList()))
            .OrderBy(x => x.LegacyId, StringComparer.OrdinalIgnoreCase)
            .ToList();

        return new SolrReadOnlyReport(
            candidateId,
            Path.GetFullPath(workerRoot),
            Path.GetFullPath(candidateFolder),
            settings.SolrCanonicalRoot,
            settings.SolrBaseUrl,
            schema.UniqueKey,
            schema.SolrVersion,
            diskFiles.Count,
            eligible.Count,
            diskFiles.Count - eligible.Count,
            solrDocs.Count,
            comparisons.OrderBy(x => x.CanonicalPath, StringComparer.OrdinalIgnoreCase).ThenBy(x => x.Status, StringComparer.Ordinal).ToList(),
            localCollisions,
            DateTime.UtcNow);
    }

    private static void PrintReport(SolrReadOnlyReport report)
    {
        Console.WriteLine($"\n=== Candidate {report.CandidateId} ===");
        Console.WriteLine($"FLOSVR01 folder      : {report.AccessibleCandidateFolder}");
        Console.WriteLine($"Disk files observed   : {report.DiskFilesObserved}");
        Console.WriteLine($"Legacy-index eligible : {report.DiskFilesEligible}");
        Console.WriteLine($"Legacy-filter skipped : {report.DiskFilesSkippedByLegacyFilter}");
        Console.WriteLine($"Solr documents        : {report.SolrDocumentsFound}");

        foreach (var item in report.Comparisons)
        {
            Console.WriteLine($"  {item.Status,-24} {item.CanonicalPath}");
            if (item.Status is "ID_MISMATCH" or "DUPLICATE_SOLR_PATH")
                Console.WriteLine($"      expected_id={item.ExpectedLegacyId ?? "(none)"} solr_id={item.SolrId ?? "(none)"}");
            if (!string.IsNullOrWhiteSpace(item.Detail) && item.Status != "MATCH")
                Console.WriteLine($"      {item.Detail}");
        }

        foreach (var collision in report.LocalLegacyIdCollisions)
        {
            Console.WriteLine($"  POSSIBLE_ID_COLLISION      legacy_id={collision.LegacyId}");
            foreach (var path in collision.RelativePaths) Console.WriteLine($"      {path}");
        }

        var summary = report.Comparisons.GroupBy(x => x.Status)
            .OrderBy(x => x.Key, StringComparer.Ordinal)
            .Select(x => $"{x.Key}={x.Count()}");
        Console.WriteLine("Summary: " + string.Join("; ", summary));
        if (report.LocalLegacyIdCollisions.Count > 0)
            Console.WriteLine($"Local legacy-ID collision groups: {report.LocalLegacyIdCollisions.Count}");
        Console.WriteLine("Note: Step 9 does not use last_update to declare a file stale; legacy code sets last_update at indexing time, not file mtime.");
        Console.WriteLine("Note: Step 9 checks legacy-ID collisions only within the configured candidate. Cross-candidate collision auditing is a later read-only task.");
    }
}
