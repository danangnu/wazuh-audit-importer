namespace WazuhAuditImporter;

public sealed record CollisionAuditCandidate(
    string CandidateId,
    string AccessibleFolder,
    int DiskFilesObserved,
    int DiskFilesEligible,
    int DiskFilesSkippedByLegacyFilter);

public sealed record CollisionAuditDiskFile(
    string CandidateId,
    string RelativePath,
    string AccessiblePath,
    string CanonicalSolrPath,
    string LegacyId,
    long Length,
    DateTime LastWriteUtc);

public sealed record LegacyIdCollisionGroup(
    string LegacyId,
    string Kind,
    IReadOnlyList<string> CandidateIds,
    IReadOnlyList<CollisionAuditDiskFile> Files,
    SolrReadOnlyDocument? CurrentSolrOwner);

public sealed record SolrLegacyIdConflict(
    string LegacyId,
    string Kind,
    string DiskCandidateId,
    string DiskRelativePath,
    string DiskCanonicalPath,
    string SolrCandidateId,
    string SolrPath,
    DateTimeOffset? SolrLastUpdate);

public sealed record SolrPathAliasFinding(
    string LegacyId,
    string Kind,
    string CandidateId,
    string DiskRelativePath,
    string DiskCanonicalPath,
    string SolrPath,
    string NormalizedCandidateRelativePath,
    DateTimeOffset? SolrLastUpdate);

public sealed record SolrCollisionAuditAnalysis(
    IReadOnlyList<LegacyIdCollisionGroup> DiskCollisionGroups,
    IReadOnlyList<SolrLegacyIdConflict> SolrConflicts,
    IReadOnlyList<SolrPathAliasFinding> SolrPathAliases)
{
    public int CrossCandidateDiskCollisionGroups =>
        DiskCollisionGroups.Count(x => x.Kind == "cross_candidate_disk_collision");

    public int WithinCandidateDiskCollisionGroups =>
        DiskCollisionGroups.Count(x => x.Kind == "within_candidate_disk_collision");

    public int SolrOwnershipConflicts =>
        SolrConflicts.Count(x => x.Kind == "existing_solr_owner_different_candidate");

    public int SolrPathConflicts =>
        SolrConflicts.Count(x => x.Kind == "existing_solr_same_candidate_different_path");

    public int SolrPathAliasCount => SolrPathAliases.Count;

    public bool SafeToExpandScope =>
        CrossCandidateDiskCollisionGroups == 0 &&
        WithinCandidateDiskCollisionGroups == 0 &&
        SolrConflicts.Count == 0;
}

public sealed record SolrCollisionAuditReport(
    string WorkerRoot,
    string CanonicalRoot,
    string SolrBaseUrl,
    string SelectionMode,
    int CandidateLimit,
    int MaxIdLookups,
    IReadOnlyList<CollisionAuditCandidate> Candidates,
    int DiskFilesObserved,
    int DiskFilesEligible,
    int DiskFilesSkippedByLegacyFilter,
    int UniqueLegacyIds,
    int SolrIdLookups,
    int SolrIdsFound,
    int CrossCandidateDiskCollisionGroups,
    int WithinCandidateDiskCollisionGroups,
    int SolrOwnershipConflicts,
    int SolrPathConflicts,
    int SolrPathAliases,
    bool SafeToExpandScope,
    IReadOnlyList<LegacyIdCollisionGroup> DiskCollisionGroups,
    IReadOnlyList<SolrLegacyIdConflict> SolrConflicts,
    IReadOnlyList<SolrPathAliasFinding> PathAliasFindings,
    DateTime GeneratedAtUtc);
