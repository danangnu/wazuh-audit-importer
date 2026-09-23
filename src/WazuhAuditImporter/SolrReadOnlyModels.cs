namespace WazuhAuditImporter;

public sealed record SolrFieldInfo(
    string Name,
    string? Type,
    bool? Indexed,
    bool? Stored,
    bool? MultiValued);

public sealed record SolrSchemaInfo(
    string UniqueKey,
    IReadOnlyDictionary<string, SolrFieldInfo> Fields,
    string? SolrVersion);

public sealed record SolrReadOnlyDocument(
    string Id,
    string CandidateId,
    string Path,
    DateTimeOffset? LastUpdate);

public sealed record DiskSolrFile(
    string RelativePath,
    string AccessiblePath,
    string CanonicalSolrPath,
    string LegacyId,
    long Length,
    DateTime LastWriteUtc,
    bool LegacyEligible,
    string? LegacySkipReason);

public sealed record SolrPathComparison(
    string Status,
    string CanonicalPath,
    string? RelativePath,
    string? ExpectedLegacyId,
    string? SolrId,
    DateTimeOffset? SolrLastUpdate,
    string? Detail);

public sealed record LegacyIdCollision(
    string LegacyId,
    IReadOnlyList<string> RelativePaths);

public sealed record SolrReadOnlyReport(
    string CandidateId,
    string WorkerRoot,
    string AccessibleCandidateFolder,
    string CanonicalRoot,
    string SolrBaseUrl,
    string UniqueKey,
    string? SolrVersion,
    int DiskFilesObserved,
    int DiskFilesEligible,
    int DiskFilesSkippedByLegacyFilter,
    int SolrDocumentsFound,
    IReadOnlyList<SolrPathComparison> Comparisons,
    IReadOnlyList<LegacyIdCollision> LocalLegacyIdCollisions,
    DateTime GeneratedAtUtc);

public sealed class SolrReadOnlyException : Exception
{
    public SolrReadOnlyException(string message) : base(message) { }
    public SolrReadOnlyException(string message, Exception innerException) : base(message, innerException) { }
}
