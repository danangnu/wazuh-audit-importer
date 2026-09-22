namespace WazuhAuditImporter;

public sealed record SolrPlanSpec(
    string SourceInstance,
    string AgentId,
    string CandidateId,
    ulong WorkerVersion,
    string Operation,
    string Status,
    int AddedCount,
    int RemovedCount,
    int ChangedCount,
    string PlanJson,
    string IdempotencyKey);

public sealed record SolrPlanWriteResult(
    ulong MutationId,
    string Operation,
    string Status,
    bool Inserted,
    int AddedCount,
    int RemovedCount,
    int ChangedCount);
