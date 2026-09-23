namespace WazuhAuditImporter;

public sealed record SolrMutationTarget(
    ulong MutationId,
    string SourceInstance,
    string AgentId,
    string CandidateId,
    ulong WorkerVersion,
    string Operation,
    string MutationStatus,
    string QueueStatus,
    ulong EventVersion,
    ulong CompletedVersion);

public sealed record SolrConcreteActionSpec(
    int ActionOrder,
    string ActionType,
    string Status,
    string Reason,
    string SolrDocumentId,
    string CanonicalPath,
    string? SourceFilePath,
    ulong? SourceFileLength,
    DateTime? SourceFileLastWriteUtc,
    DateTime? SolrLastUpdateUtc,
    string IdempotencyKey);

public sealed record SolrConcreteActionWriteResult(
    int PlannedCount,
    int InsertedCount,
    int ExistingCount);

public sealed record SolrConcreteActionReport(
    ulong MutationId,
    string SourceInstance,
    string AgentId,
    string CandidateId,
    ulong WorkerVersion,
    string MutationStatus,
    string QueueStatus,
    ulong EventVersion,
    ulong CompletedVersion,
    string WorkerRoot,
    string AccessibleCandidateFolder,
    string SolrBaseUrl,
    int DiskFilesObserved,
    int SolrDocumentsFound,
    IReadOnlyList<SolrPathComparison> Comparisons,
    IReadOnlyList<SolrConcreteActionSpec> Actions,
    DateTime GeneratedAtUtc);

public sealed class SolrConcreteActionException : Exception
{
    public SolrConcreteActionException(string message) : base(message) { }
}
