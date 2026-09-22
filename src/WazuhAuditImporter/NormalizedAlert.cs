namespace WazuhAuditImporter;

public sealed record NormalizedAlert
{
    public required string SourceInstance { get; init; }
    public required string WazuhEventId { get; init; }
    public required string AgentId { get; init; }
    public required string AgentName { get; init; }
    public string? AgentIp { get; init; }
    public required string ManagerName { get; init; }
    public required string CandidateId { get; init; }
    public required string CandidateFolder { get; init; }
    public required string EventType { get; init; }
    public string? DetectionMode { get; init; }
    public string? RuleId { get; init; }
    public ushort? RuleLevel { get; init; }
    public required DateTime EventTimeUtc { get; init; }
    public required string SourcePath { get; init; }
    public string? FileOwnerName { get; init; }
    public string? ActorName { get; init; }
    public string? ActorProcess { get; init; }
    public ulong? ReportedSizeBytes { get; init; }
    public string? ReportedSha256 { get; init; }
    public required string RawJson { get; init; }
}

public sealed record ParseResult(NormalizedAlert? Alert, string? IgnoredReason);
public sealed record QueueState(ulong WorkItemId, string Status, ulong EventVersion);
public sealed record ImportResult(bool Inserted, ulong AuditEventId, QueueState Queue);
public sealed class EventConflictException(string message) : Exception(message) { }
