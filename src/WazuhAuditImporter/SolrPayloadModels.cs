namespace WazuhAuditImporter;

public sealed record SolrStoredAction(
    ulong ActionId,
    ulong MutationId,
    string SourceInstance,
    string AgentId,
    string CandidateId,
    ulong WorkerVersion,
    int ActionOrder,
    string ActionType,
    string ActionStatus,
    string Reason,
    string SolrDocumentId,
    string CanonicalPath,
    string? SourceFilePath,
    ulong? SourceFileLength,
    DateTime? SourceFileLastWriteUtc,
    string IdempotencyKey);

public sealed record SolrPayloadSpec(
    ulong ActionId,
    ulong MutationId,
    string ActionType,
    string Status,
    string Extractor,
    string? PayloadJson,
    string? PayloadSha256,
    string? SourceFileSha256,
    string? ContentSha256,
    ulong? ContentCharCount,
    ulong? SourceFileLength,
    DateTime? SourceFileLastWriteUtc,
    string? BlockReason,
    DateTime GeneratedAtUtc);

public sealed record SolrPayloadWriteResult(int Total, int Inserted, int Existing);

public sealed record SolrPayloadReport(
    ulong MutationId,
    string CandidateId,
    ulong WorkerVersion,
    string WorkerRoot,
    IReadOnlyList<SolrPayloadSpec> Payloads,
    DateTime GeneratedAtUtc);

public sealed class SolrPayloadException : Exception
{
    public SolrPayloadException(string message) : base(message) { }
}
