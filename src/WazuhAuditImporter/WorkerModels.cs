namespace WazuhAuditImporter;

public sealed record WorkerClaim(
    ulong WorkItemId,
    string SourceInstance,
    string AgentId,
    string CandidateId,
    string SourceCandidateFolder,
    ulong EventVersion,
    ulong ClaimedVersion,
    ulong PriorCompletedVersion,
    uint AttemptCount,
    string LeaseToken,
    DateTime LeaseExpiresUtc);

public sealed record WorkerCompletion(
    ulong WorkItemId,
    string CandidateId,
    string Status,
    ulong EventVersion,
    ulong CompletedVersion);

public sealed record SnapshotFileState(
    string RelativePath,
    long Length,
    DateTime LastWriteUtc);

public sealed record CandidateSnapshot(
    string CandidateId,
    DateTime CapturedAtUtc,
    Dictionary<string, SnapshotFileState> Files);

public sealed record ReconciliationResult(
    string CandidateId,
    bool IsBaseline,
    IReadOnlyList<string> Added,
    IReadOnlyList<string> Removed,
    IReadOnlyList<string> Changed);
