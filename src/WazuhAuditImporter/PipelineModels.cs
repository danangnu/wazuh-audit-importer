namespace WazuhAuditImporter;

public enum PipelineMutationDisposition
{
    Idle,
    WaitingForWorker,
    NeedsActions,
    NeedsPayloads,
    BlockedPayload,
    ReadyForApproval,
    Complete,
    HaltedExecution
}

public sealed record PipelineMutationSnapshot(
    ulong MutationId,
    string CandidateId,
    ulong WorkerVersion,
    string Operation,
    string MutationStatus,
    string QueueStatus,
    ulong EventVersion,
    ulong CompletedVersion,
    int ActionCount,
    int NonPlannedActionCount,
    int ReadyPayloadCount,
    int BlockedPayloadCount)
{
    public int PayloadCount => ReadyPayloadCount + BlockedPayloadCount;
    public int MissingPayloadCount => Math.Max(0, ActionCount - PayloadCount);
}

public sealed record PipelineDecisionResult(
    PipelineMutationDisposition Disposition,
    string Detail);

public sealed record PipelineCandidateCycleSummary(
    string CandidateId,
    PipelineMutationDisposition Disposition,
    ulong? MutationId,
    ulong? WorkerVersion,
    string Detail);

public sealed record PipelineCycleSummary(
    long Cycle,
    int CollectorSeen,
    int CollectorAccepted,
    int CollectorInserted,
    int CollectorDuplicates,
    int CollectorIgnored,
    int WorkerItemsProcessed,
    PipelineMutationDisposition Disposition,
    ulong? MutationId,
    ulong? WorkerVersion,
    string Detail,
    IReadOnlyList<PipelineCandidateCycleSummary> Candidates,
    DateTime CompletedAtUtc);

public sealed record PipelineCandidateLocalState(
    string CandidateId,
    string Stage,
    ulong? MutationId,
    ulong? WorkerVersion,
    string Detail);

public sealed record PipelineLocalState(
    int SchemaVersion,
    string SourceInstance,
    string AgentId,
    string CandidateId,
    string[] CandidateIds,
    long Cycle,
    string Stage,
    ulong? MutationId,
    ulong? WorkerVersion,
    string Detail,
    IReadOnlyList<PipelineCandidateLocalState> Candidates,
    DateTime UpdatedAtUtc);
