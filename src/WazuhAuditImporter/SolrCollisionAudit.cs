using System.Globalization;
using System.Text;
using System.Text.Json;

namespace WazuhAuditImporter;

public static class SolrCollisionAudit
{
    public const int DefaultCandidateLimit = 10;
    public const int MaximumCandidateLimit = 100;
    public const int DefaultMaxIdLookups = 1000;
    public const int MaximumIdLookups = 5000;

    public static int Run(
        ImportSettings settings,
        string workerRoot,
        string? reportDirectory,
        int candidateLimit,
        int maxIdLookups,
        IReadOnlyList<string>? explicitCandidateIds)
    {
        ValidateArguments(workerRoot, candidateLimit, maxIdLookups, explicitCandidateIds);
        settings.ValidateSolrReadOnly();

        var root = Path.GetFullPath(workerRoot).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        if (!Directory.Exists(root))
            throw new DirectoryNotFoundException($"FLOSVR01 worker root is not accessible: {root}");

        var targets = SelectCandidateDirectories(root, settings.CandidateIds, explicitCandidateIds, candidateLimit);
        var selectionMode = explicitCandidateIds is { Count: > 0 }
            ? "explicit_candidate_ids"
            : "configured_seed_plus_first_numeric_folders";

        Console.WriteLine("Step 14A cross-candidate legacy Solr ID collision audit - READ ONLY.");
        Console.WriteLine("Filesystem access: directory/file metadata only; source document content is NOT read.");
        Console.WriteLine("Solr access: schema + unique-key ownership lookups using HTTP GET only.");
        Console.WriteLine("MariaDB access: none. Solr update/delete/add/commit APIs: none.");
        Console.WriteLine($"Worker root       : {root}");
        Console.WriteLine($"Candidate selection: {selectionMode}; count={targets.Count}; limit={candidateLimit}");
        Console.WriteLine($"Solr ID lookup cap : {maxIdLookups}\n");

        var candidates = new List<CollisionAuditCandidate>();
        var eligibleFiles = new List<CollisionAuditDiskFile>();
        foreach (var target in targets)
        {
            var disk = SolrReadOnlyDiscovery.CaptureDiskFiles(root, target.AccessibleFolder, settings.SolrCanonicalRoot);
            var eligible = disk.Where(x => x.LegacyEligible).ToList();
            candidates.Add(new CollisionAuditCandidate(
                target.CandidateId,
                target.AccessibleFolder,
                disk.Count,
                eligible.Count,
                disk.Count - eligible.Count));

            eligibleFiles.AddRange(eligible.Select(x => new CollisionAuditDiskFile(
                target.CandidateId,
                x.RelativePath,
                x.AccessiblePath,
                x.CanonicalSolrPath,
                x.LegacyId,
                x.Length,
                x.LastWriteUtc)));

            Console.WriteLine($"  candidate={target.CandidateId} files={disk.Count} eligible={eligible.Count} skipped={disk.Count - eligible.Count}");
        }

        var uniqueIds = eligibleFiles.Select(x => x.LegacyId)
            .Distinct(StringComparer.Ordinal)
            .OrderBy(x => x, StringComparer.Ordinal)
            .ToList();
        EnsureLookupCap(uniqueIds.Count, maxIdLookups);

        using var client = new SolrReadOnlyClient(settings);
        var schema = client.ReadSchema();
        if (!schema.UniqueKey.Equals(settings.SolrIdField, StringComparison.Ordinal))
            throw new SolrReadOnlyException($"Expected Solr unique key '{settings.SolrIdField}', but schema reports '{schema.UniqueKey}'.");
        foreach (var required in new[] { settings.SolrIdField, settings.SolrCandidateField, settings.SolrPathField })
            if (!schema.Fields.ContainsKey(required))
                throw new SolrReadOnlyException($"Required field '{required}' was not returned by the schema API.");

        var owners = new Dictionary<string, SolrReadOnlyDocument>(StringComparer.Ordinal);
        var completedLookups = 0;
        foreach (var id in uniqueIds)
        {
            var found = client.QueryById(id);
            completedLookups++;
            if (found.Count == 1)
                owners[id] = found[0];
            if (completedLookups % 50 == 0 || completedLookups == uniqueIds.Count)
                Console.WriteLine($"  Solr ownership lookups: {completedLookups}/{uniqueIds.Count}");
        }

        var analysis = Analyze(eligibleFiles, owners);
        var report = new SolrCollisionAuditReport(
            root,
            settings.SolrCanonicalRoot,
            settings.SolrBaseUrl,
            selectionMode,
            candidateLimit,
            maxIdLookups,
            candidates,
            candidates.Sum(x => x.DiskFilesObserved),
            candidates.Sum(x => x.DiskFilesEligible),
            candidates.Sum(x => x.DiskFilesSkippedByLegacyFilter),
            uniqueIds.Count,
            completedLookups,
            owners.Count,
            analysis.CrossCandidateDiskCollisionGroups,
            analysis.WithinCandidateDiskCollisionGroups,
            analysis.SolrOwnershipConflicts,
            analysis.SolrPathConflicts,
            analysis.SolrPathAliasCount,
            analysis.SafeToExpandScope,
            analysis.DiskCollisionGroups,
            analysis.SolrConflicts,
            analysis.SolrPathAliases,
            DateTime.UtcNow);

        PrintReport(report);
        SaveReport(report, reportDirectory);

        Console.WriteLine("\nSTEP 14A COMPLETE. No MariaDB connection, no source-content reads, and no Solr writes occurred.");
        if (report.SafeToExpandScope)
        {
            Console.WriteLine("CONTROLLED SUBSET RESULT: no legacy-ID collision/ownership conflict was found in the audited files.");
            Console.WriteLine("This does not prove unscanned candidate folders are collision-free; expand the audit in controlled batches.");
        }
        else
        {
            Console.WriteLine("SCOPE EXPANSION BLOCKED FOR REVIEW: one or more legacy-ID collision/ownership findings exist.");
            Console.WriteLine("Do not broaden automatic candidate processing until the report is reviewed and the ID strategy is resolved.");
        }
        return 0;
    }

    public static IReadOnlyList<CollisionAuditTarget> SelectCandidateDirectories(
        string workerRoot,
        IReadOnlyList<string> configuredSeedIds,
        IReadOnlyList<string>? explicitCandidateIds,
        int candidateLimit)
    {
        if (candidateLimit < 1 || candidateLimit > MaximumCandidateLimit)
            throw new FormatException($"--candidate-limit must be between 1 and {MaximumCandidateLimit}.");

        var selected = new Dictionary<string, string>(StringComparer.Ordinal);
        if (explicitCandidateIds is { Count: > 0 })
        {
            if (explicitCandidateIds.Count > MaximumCandidateLimit)
                throw new FormatException($"At most {MaximumCandidateLimit} explicit candidate IDs may be audited in one run.");
            foreach (var id in explicitCandidateIds)
            {
                ValidateCandidateId(id);
                var folder = Path.Combine(workerRoot, id);
                if (!Directory.Exists(folder))
                    throw new DirectoryNotFoundException($"Explicit candidate folder is not accessible: {folder}");
                EnsureNotReparsePoint(folder);
                selected[id] = folder;
            }
        }
        else
        {
            foreach (var id in configuredSeedIds ?? Array.Empty<string>())
            {
                if (selected.Count >= candidateLimit) break;
                if (!IsCandidateId(id)) continue;
                var folder = Path.Combine(workerRoot, id);
                if (!Directory.Exists(folder)) continue;
                EnsureNotReparsePoint(folder);
                selected[id] = folder;
            }

            if (selected.Count < candidateLimit)
            {
                foreach (var folder in Directory.EnumerateDirectories(workerRoot, "*", SearchOption.TopDirectoryOnly))
                {
                    if (selected.Count >= candidateLimit) break;
                    var info = new DirectoryInfo(folder);
                    if (!IsCandidateId(info.Name)) continue;
                    if ((info.Attributes & FileAttributes.ReparsePoint) != 0) continue;
                    selected.TryAdd(info.Name, info.FullName);
                }
            }
        }

        if (selected.Count == 0)
            throw new DirectoryNotFoundException("No numeric candidate folders were selected under the supplied worker root.");

        return selected
            .Select(x => new CollisionAuditTarget(x.Key, x.Value))
            .OrderBy(x => x.CandidateId, CandidateIdComparer.Instance)
            .ToList();
    }

    public static SolrCollisionAuditAnalysis Analyze(
        IReadOnlyList<CollisionAuditDiskFile> eligibleFiles,
        IReadOnlyDictionary<string, SolrReadOnlyDocument> currentSolrOwners)
    {
        var groups = eligibleFiles
            .GroupBy(x => x.LegacyId, StringComparer.Ordinal)
            .OrderBy(x => x.Key, StringComparer.Ordinal)
            .ToList();

        var collisions = new List<LegacyIdCollisionGroup>();
        var conflicts = new List<SolrLegacyIdConflict>();
        var aliases = new List<SolrPathAliasFinding>();

        foreach (var group in groups)
        {
            var files = group
                .OrderBy(x => x.CandidateId, CandidateIdComparer.Instance)
                .ThenBy(x => x.CanonicalSolrPath, StringComparer.OrdinalIgnoreCase)
                .ToList();
            var candidates = files.Select(x => x.CandidateId)
                .Distinct(StringComparer.Ordinal)
                .OrderBy(x => x, CandidateIdComparer.Instance)
                .ToList();
            currentSolrOwners.TryGetValue(group.Key, out var owner);

            if (files.Count > 1)
            {
                var kind = candidates.Count > 1
                    ? "cross_candidate_disk_collision"
                    : "within_candidate_disk_collision";
                collisions.Add(new LegacyIdCollisionGroup(group.Key, kind, candidates, files, owner));
            }

            if (owner is null) continue;
            foreach (var file in files)
            {
                if (!owner.CandidateId.Equals(file.CandidateId, StringComparison.Ordinal))
                {
                    conflicts.Add(new SolrLegacyIdConflict(
                        group.Key,
                        "existing_solr_owner_different_candidate",
                        file.CandidateId,
                        file.RelativePath,
                        file.CanonicalSolrPath,
                        owner.CandidateId,
                        owner.Path,
                        owner.LastUpdate));
                }
                else
                {
                    var fullSolrPath = SolrPathMapper.NormalizeForComparison(owner.Path);
                    var fullDiskPath = SolrPathMapper.NormalizeForComparison(file.CanonicalSolrPath);
                    if (fullSolrPath.Equals(fullDiskPath, StringComparison.Ordinal))
                        continue;

                    var solrRelative = NormalizeCandidateRelativePath(owner.Path, file.CandidateId);
                    var diskRelative = NormalizeCandidateRelativePath(file.CanonicalSolrPath, file.CandidateId);
                    if (solrRelative is not null && diskRelative is not null &&
                        solrRelative.Equals(diskRelative, StringComparison.Ordinal))
                    {
                        aliases.Add(new SolrPathAliasFinding(
                            group.Key,
                            "existing_solr_same_document_root_alias",
                            file.CandidateId,
                            file.RelativePath,
                            file.CanonicalSolrPath,
                            owner.Path,
                            diskRelative,
                            owner.LastUpdate));
                        continue;
                    }

                    conflicts.Add(new SolrLegacyIdConflict(
                        group.Key,
                        "existing_solr_same_candidate_different_path",
                        file.CandidateId,
                        file.RelativePath,
                        file.CanonicalSolrPath,
                        owner.CandidateId,
                        owner.Path,
                        owner.LastUpdate));
                }
            }
        }

        return new SolrCollisionAuditAnalysis(collisions, conflicts, aliases);
    }

    // Step 14A audits ownership, not repository-root spelling. Once the Solr
    // candidate owner has already matched the disk candidate, compare only the
    // path inside that candidate folder. This intentionally treats historical
    // roots such as G:\Candidate, \\FLOSVR01\Candidate and
    // \\FLOSVR01\FastTrack\Candidate as the same logical document while
    // still detecting a different filename/subfolder under the same candidate.
    public static string? NormalizeCandidateRelativePath(string path, string candidateId)
    {
        if (string.IsNullOrWhiteSpace(path) || string.IsNullOrWhiteSpace(candidateId))
            return null;

        var normalized = SolrPathMapper.NormalizeWindowsPath(path);
        var marker = "\\" + candidateId + "\\";
        var index = normalized.IndexOf(marker, StringComparison.OrdinalIgnoreCase);
        if (index < 0)
            return null;

        // Root aliases are accepted only for paths that are visibly inside a
        // Candidate repository. Do not collapse arbitrary unrelated roots that
        // merely happen to contain the same numeric folder name.
        var prefix = normalized[..index];
        if (!prefix.Contains("\\Candidate\\", StringComparison.OrdinalIgnoreCase))
            return null;

        var relative = normalized[(index + marker.Length)..].TrimStart('\\');
        return string.IsNullOrWhiteSpace(relative)
            ? null
            : SolrPathMapper.NormalizeForComparison(relative);
    }

    public static void EnsureLookupCap(int uniqueIdCount, int maxIdLookups)
    {
        if (maxIdLookups < 1 || maxIdLookups > MaximumIdLookups)
            throw new FormatException($"--max-id-lookups must be between 1 and {MaximumIdLookups}.");
        if (uniqueIdCount > maxIdLookups)
            throw new InvalidOperationException(
                $"The selected candidates contain {uniqueIdCount} unique eligible legacy IDs, exceeding the Step 14A lookup cap of {maxIdLookups}. " +
                "Rerun with fewer explicit candidates/a smaller --candidate-limit, or deliberately raise --max-id-lookups within the allowed cap.");
    }

    private static void ValidateArguments(
        string workerRoot,
        int candidateLimit,
        int maxIdLookups,
        IReadOnlyList<string>? explicitCandidateIds)
    {
        if (string.IsNullOrWhiteSpace(workerRoot) || !Path.IsPathFullyQualified(workerRoot))
            throw new FormatException("Step 14A requires an explicit fully-qualified local or UNC --worker-root.");
        if (candidateLimit < 1 || candidateLimit > MaximumCandidateLimit)
            throw new FormatException($"--candidate-limit must be between 1 and {MaximumCandidateLimit}.");
        if (maxIdLookups < 1 || maxIdLookups > MaximumIdLookups)
            throw new FormatException($"--max-id-lookups must be between 1 and {MaximumIdLookups}.");
        if (explicitCandidateIds is { Count: > 0 })
        {
            if (explicitCandidateIds.Count > MaximumCandidateLimit)
                throw new FormatException($"At most {MaximumCandidateLimit} explicit candidate IDs may be audited in one run.");
            foreach (var id in explicitCandidateIds) ValidateCandidateId(id);
        }
    }

    private static void PrintReport(SolrCollisionAuditReport report)
    {
        Console.WriteLine("\n=== Step 14A summary ===");
        Console.WriteLine($"Candidates audited                    : {report.Candidates.Count}");
        Console.WriteLine($"Disk files observed                   : {report.DiskFilesObserved}");
        Console.WriteLine($"Legacy-index eligible                 : {report.DiskFilesEligible}");
        Console.WriteLine($"Legacy-filter skipped                 : {report.DiskFilesSkippedByLegacyFilter}");
        Console.WriteLine($"Unique generated legacy IDs           : {report.UniqueLegacyIds}");
        Console.WriteLine($"Solr unique-key GET lookups            : {report.SolrIdLookups}");
        Console.WriteLine($"IDs currently present in Solr         : {report.SolrIdsFound}");
        Console.WriteLine($"Cross-candidate disk collision groups : {report.CrossCandidateDiskCollisionGroups}");
        Console.WriteLine($"Within-candidate disk collision groups: {report.WithinCandidateDiskCollisionGroups}");
        Console.WriteLine($"Solr owner-different-candidate conflicts: {report.SolrOwnershipConflicts}");
        Console.WriteLine($"Solr same-candidate/path conflicts     : {report.SolrPathConflicts}");
        Console.WriteLine($"Solr same-document root aliases        : {report.SolrPathAliases}");
        Console.WriteLine($"SafeToExpandScope                     : {report.SafeToExpandScope}");

        foreach (var collision in report.DiskCollisionGroups.Take(25))
        {
            Console.WriteLine($"  COLLISION kind={collision.Kind} id={collision.LegacyId} candidates={string.Join(',', collision.CandidateIds)} files={collision.Files.Count}");
            foreach (var file in collision.Files.Take(10))
                Console.WriteLine($"      disk candidate={file.CandidateId} path={file.CanonicalSolrPath}");
            if (collision.CurrentSolrOwner is not null)
                Console.WriteLine($"      current Solr owner candidate={collision.CurrentSolrOwner.CandidateId} path={collision.CurrentSolrOwner.Path}");
        }
        if (report.DiskCollisionGroups.Count > 25)
            Console.WriteLine($"  ... {report.DiskCollisionGroups.Count - 25} additional disk collision groups are in the JSON/CSV report.");

        foreach (var conflict in report.SolrConflicts.Take(25))
            Console.WriteLine($"  SOLR_CONFLICT kind={conflict.Kind} id={conflict.LegacyId} disk_candidate={conflict.DiskCandidateId} solr_candidate={conflict.SolrCandidateId}");
        if (report.SolrConflicts.Count > 25)
            Console.WriteLine($"  ... {report.SolrConflicts.Count - 25} additional Solr conflicts are in the JSON/CSV report.");

        foreach (var alias in report.PathAliasFindings.Take(25))
            Console.WriteLine($"  SOLR_ALIAS kind={alias.Kind} id={alias.LegacyId} candidate={alias.CandidateId} relative={alias.NormalizedCandidateRelativePath}");
        if (report.PathAliasFindings.Count > 25)
            Console.WriteLine($"  ... {report.PathAliasFindings.Count - 25} additional non-blocking path aliases are in the JSON/CSV report.");
    }

    private static void SaveReport(SolrCollisionAuditReport report, string? reportDirectory)
    {
        if (string.IsNullOrWhiteSpace(reportDirectory)) return;
        var full = Path.GetFullPath(reportDirectory);
        Directory.CreateDirectory(full);
        var stamp = DateTime.UtcNow.ToString("yyyyMMdd-HHmmss", CultureInfo.InvariantCulture);
        var jsonPath = Path.Combine(full, $"solr-collision-audit-{stamp}.json");
        var csvPath = Path.Combine(full, $"solr-collision-audit-{stamp}.csv");
        File.WriteAllText(jsonPath, JsonSerializer.Serialize(report, new JsonSerializerOptions { WriteIndented = true }), new UTF8Encoding(false));

        var csv = new StringBuilder();
        csv.AppendLine("legacy_id,finding_type,disk_candidate_id,disk_relative_path,disk_canonical_path,solr_candidate_id,solr_path");
        foreach (var group in report.DiskCollisionGroups)
        {
            foreach (var file in group.Files)
            {
                csv.AppendLine(string.Join(',', new[]
                {
                    Csv(group.LegacyId), Csv(group.Kind), Csv(file.CandidateId), Csv(file.RelativePath), Csv(file.CanonicalSolrPath),
                    Csv(group.CurrentSolrOwner?.CandidateId), Csv(group.CurrentSolrOwner?.Path)
                }));
            }
        }
        foreach (var conflict in report.SolrConflicts)
        {
            csv.AppendLine(string.Join(',', new[]
            {
                Csv(conflict.LegacyId), Csv(conflict.Kind), Csv(conflict.DiskCandidateId), Csv(conflict.DiskRelativePath), Csv(conflict.DiskCanonicalPath),
                Csv(conflict.SolrCandidateId), Csv(conflict.SolrPath)
            }));
        }
        foreach (var alias in report.PathAliasFindings)
        {
            csv.AppendLine(string.Join(',', new[]
            {
                Csv(alias.LegacyId), Csv(alias.Kind), Csv(alias.CandidateId), Csv(alias.DiskRelativePath), Csv(alias.DiskCanonicalPath),
                Csv(alias.CandidateId), Csv(alias.SolrPath)
            }));
        }
        File.WriteAllText(csvPath, csv.ToString(), new UTF8Encoding(false));
        Console.WriteLine($"JSON report saved: {jsonPath}");
        Console.WriteLine($"CSV findings saved: {csvPath}");
    }

    private static string Csv(string? value)
    {
        value ??= string.Empty;
        return value.IndexOfAny([',', '"', '\r', '\n']) >= 0
            ? '"' + value.Replace("\"", "\"\"") + '"'
            : value;
    }

    private static bool IsCandidateId(string? id) =>
        !string.IsNullOrWhiteSpace(id) && id.All(char.IsAsciiDigit) && id.Length <= 32;

    private static void ValidateCandidateId(string id)
    {
        if (!IsCandidateId(id))
            throw new FormatException($"Invalid candidate ID '{id}'. Candidate IDs must contain 1-32 ASCII digits only.");
    }

    private static void EnsureNotReparsePoint(string folder)
    {
        var info = new DirectoryInfo(folder);
        if ((info.Attributes & FileAttributes.ReparsePoint) != 0)
            throw new InvalidOperationException($"Step 14A refuses candidate directory reparse points/junctions: {folder}");
    }

    public sealed record CollisionAuditTarget(string CandidateId, string AccessibleFolder);

    private sealed class CandidateIdComparer : IComparer<string>
    {
        public static readonly CandidateIdComparer Instance = new();
        public int Compare(string? x, string? y)
        {
            x ??= string.Empty;
            y ??= string.Empty;
            var nx = x.TrimStart('0'); if (nx.Length == 0) nx = "0";
            var ny = y.TrimStart('0'); if (ny.Length == 0) ny = "0";
            var length = nx.Length.CompareTo(ny.Length);
            if (length != 0) return length;
            var value = string.CompareOrdinal(nx, ny);
            return value != 0 ? value : string.CompareOrdinal(x, y);
        }
    }
}
