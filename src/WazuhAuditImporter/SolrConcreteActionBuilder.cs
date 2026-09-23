using System.Security.Cryptography;
using System.Text;

namespace WazuhAuditImporter;

public static class SolrConcreteActionBuilder
{
    public static IReadOnlyList<SolrConcreteActionSpec> Build(
        SolrMutationTarget target,
        SolrReadOnlyReport report,
        IReadOnlyList<DiskSolrFile> diskFiles,
        IReadOnlyList<SolrReadOnlyDocument> solrDocs,
        Func<string, IReadOnlyList<SolrReadOnlyDocument>> queryById,
        IReadOnlySet<string>? forceReindexRelativePaths = null)
    {
        if (!target.CandidateId.Equals(report.CandidateId, StringComparison.Ordinal))
            throw new SolrConcreteActionException("Candidate mismatch between mutation target and read-only comparison.");
        if (report.LocalLegacyIdCollisions.Count > 0)
            throw new SolrConcreteActionException("Local legacy Solr ID collision detected. Concrete actions were not persisted.");

        var ambiguous = report.Comparisons
            .Where(x => x.Status is "ID_MISMATCH" or "DUPLICATE_SOLR_PATH")
            .ToList();
        if (ambiguous.Count > 0)
            throw new SolrConcreteActionException(
                "Ambiguous Solr identity/path state detected (ID_MISMATCH or DUPLICATE_SOLR_PATH). Review before planning writes.");

        var supported = new HashSet<string>(StringComparer.Ordinal)
        {
            "MATCH", "MISSING_IN_SOLR", "STALE_IN_SOLR", "SKIPPED_BY_LEGACY_FILTER"
        };
        var unexpected = report.Comparisons.FirstOrDefault(x => !supported.Contains(x.Status));
        if (unexpected is not null)
            throw new SolrConcreteActionException($"Unsupported Step 10A comparison status '{unexpected.Status}'.");

        var diskByPath = diskFiles
            .Where(x => x.LegacyEligible)
            .GroupBy(x => SolrPathMapper.NormalizeForComparison(x.CanonicalSolrPath), StringComparer.Ordinal)
            .ToDictionary(x => x.Key, x => x.Single(), StringComparer.Ordinal);

        var staleComparisons = report.Comparisons
            .Where(x => x.Status == "STALE_IN_SOLR")
            .OrderBy(x => x.CanonicalPath, StringComparer.OrdinalIgnoreCase)
            .ToList();
        var stalePaths = staleComparisons
            .Select(x => SolrPathMapper.NormalizeForComparison(x.CanonicalPath))
            .ToHashSet(StringComparer.Ordinal);

        var actions = new List<SolrConcreteActionSpec>();
        var order = 1;

        // Deletes are deliberately ordered before indexes. This permits a same-ID
        // move/rename only when the currently occupying ID belongs to a stale document
        // in the same candidate and that stale document is already scheduled for delete.
        foreach (var stale in staleComparisons)
        {
            if (string.IsNullOrWhiteSpace(stale.SolrId))
                throw new SolrConcreteActionException($"Stale Solr document '{stale.CanonicalPath}' has no unique ID.");
            var doc = solrDocs.SingleOrDefault(x =>
                x.Id.Equals(stale.SolrId, StringComparison.Ordinal) &&
                SolrPathMapper.NormalizeForComparison(x.Path) == SolrPathMapper.NormalizeForComparison(stale.CanonicalPath));
            if (doc is null)
                throw new SolrConcreteActionException($"Stale Solr document '{stale.CanonicalPath}' could not be resolved exactly.");

            actions.Add(Create(
                target,
                order++,
                "delete_document",
                "stale_in_solr",
                doc.Id,
                doc.Path,
                null,
                null,
                null,
                doc.LastUpdate?.UtcDateTime));
        }

        foreach (var missing in report.Comparisons
                     .Where(x => x.Status == "MISSING_IN_SOLR")
                     .OrderBy(x => x.CanonicalPath, StringComparer.OrdinalIgnoreCase))
        {
            var normalized = SolrPathMapper.NormalizeForComparison(missing.CanonicalPath);
            if (!diskByPath.TryGetValue(normalized, out var disk))
                throw new SolrConcreteActionException($"Missing-in-Solr path '{missing.CanonicalPath}' was not found in eligible FLOSVR01 inventory.");
            if (string.IsNullOrWhiteSpace(disk.LegacyId))
                throw new SolrConcreteActionException($"Eligible file '{disk.RelativePath}' produced an empty legacy Solr ID.");

            var idOccupants = queryById(disk.LegacyId);
            foreach (var occupant in idOccupants)
            {
                var sameCandidate = occupant.CandidateId.Equals(target.CandidateId, StringComparison.Ordinal);
                var occupantIsScheduledDelete = sameCandidate &&
                    stalePaths.Contains(SolrPathMapper.NormalizeForComparison(occupant.Path));
                if (!occupantIsScheduledDelete)
                {
                    throw new SolrConcreteActionException(
                        $"Legacy Solr ID collision: '{disk.LegacyId}' for '{disk.CanonicalSolrPath}' is already used by candidate " +
                        $"'{occupant.CandidateId}' path '{occupant.Path}'. No concrete actions were persisted.");
                }
            }

            actions.Add(Create(
                target,
                order++,
                "index_document",
                "missing_in_solr",
                disk.LegacyId,
                disk.CanonicalSolrPath,
                disk.AccessiblePath,
                checked((ulong)disk.Length),
                TruncateToMicroseconds(DateTime.SpecifyKind(disk.LastWriteUtc, DateTimeKind.Utc)),
                null));
        }

        // A content modification can leave the same legacy id/path in Solr, so a pure
        // path reconciliation reports MATCH even though the document must be re-indexed.
        // Step 12 carries the immutable worker "changed" list forward and forces an
        // index action for those still-present, legacy-eligible files.
        if (forceReindexRelativePaths is not null)
        {
            var diskByRelative = diskFiles.ToDictionary(x => x.RelativePath, StringComparer.OrdinalIgnoreCase);
            var comparisonByPath = report.Comparisons
                .GroupBy(x => SolrPathMapper.NormalizeForComparison(x.CanonicalPath), StringComparer.Ordinal)
                .ToDictionary(x => x.Key, x => x.Single(), StringComparer.Ordinal);
            var alreadyIndexedPaths = actions
                .Where(x => x.ActionType == "index_document")
                .Select(x => SolrPathMapper.NormalizeForComparison(x.CanonicalPath))
                .ToHashSet(StringComparer.Ordinal);

            foreach (var relative in forceReindexRelativePaths.OrderBy(x => x, StringComparer.OrdinalIgnoreCase))
            {
                if (!diskByRelative.TryGetValue(relative, out var disk))
                    throw new SolrConcreteActionException(
                        $"Worker marked '{relative}' changed, but it is no longer present in the current FLOSVR01 inventory. Wait for the newer file event before planning.");
                if (!disk.LegacyEligible)
                    continue;

                var normalized = SolrPathMapper.NormalizeForComparison(disk.CanonicalSolrPath);
                if (alreadyIndexedPaths.Contains(normalized))
                    continue;
                if (!comparisonByPath.TryGetValue(normalized, out var comparison))
                    throw new SolrConcreteActionException($"Changed file '{relative}' has no current Solr comparison row.");
                if (comparison.Status == "SKIPPED_BY_LEGACY_FILTER")
                    continue;
                if (comparison.Status == "MISSING_IN_SOLR")
                    continue; // already handled above
                if (comparison.Status != "MATCH")
                    throw new SolrConcreteActionException(
                        $"Changed file '{relative}' has unsupported live comparison state '{comparison.Status}'.");

                var occupants = queryById(disk.LegacyId);
                if (occupants.Count != 1 ||
                    !occupants[0].CandidateId.Equals(target.CandidateId, StringComparison.Ordinal) ||
                    SolrPathMapper.NormalizeForComparison(occupants[0].Path) != normalized)
                    throw new SolrConcreteActionException(
                        $"Changed file '{relative}' no longer resolves to exactly one matching Solr id/path. No action was persisted.");

                actions.Add(Create(
                    target,
                    order++,
                    "index_document",
                    "source_changed",
                    disk.LegacyId,
                    disk.CanonicalSolrPath,
                    disk.AccessiblePath,
                    checked((ulong)disk.Length),
                    TruncateToMicroseconds(DateTime.SpecifyKind(disk.LastWriteUtc, DateTimeKind.Utc)),
                    occupants[0].LastUpdate?.UtcDateTime));
                alreadyIndexedPaths.Add(normalized);
            }
        }

        return actions;
    }

    private static SolrConcreteActionSpec Create(
        SolrMutationTarget target,
        int order,
        string actionType,
        string reason,
        string solrId,
        string canonicalPath,
        string? sourceFilePath,
        ulong? sourceLength,
        DateTime? sourceLastWriteUtc,
        DateTime? solrLastUpdateUtc)
    {
        var stable = string.Join("\n",
            target.SourceInstance,
            target.AgentId,
            target.CandidateId,
            target.WorkerVersion.ToString(System.Globalization.CultureInfo.InvariantCulture),
            actionType,
            solrId,
            SolrPathMapper.NormalizeForComparison(canonicalPath));
        var key = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(stable))).ToLowerInvariant();
        return new SolrConcreteActionSpec(
            order,
            actionType,
            "planned",
            reason,
            solrId,
            canonicalPath,
            sourceFilePath,
            sourceLength,
            TruncateToMicroseconds(sourceLastWriteUtc),
            TruncateToMicroseconds(solrLastUpdateUtc),
            key);
    }

    private static DateTime? TruncateToMicroseconds(DateTime? value)
    {
        if (value is null) return null;
        var utc = value.Value.Kind == DateTimeKind.Utc ? value.Value : value.Value.ToUniversalTime();
        return new DateTime(utc.Ticks - (utc.Ticks % 10), DateTimeKind.Utc);
    }
}
