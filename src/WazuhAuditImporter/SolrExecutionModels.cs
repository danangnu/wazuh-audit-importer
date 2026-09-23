namespace WazuhAuditImporter;

public sealed record SolrExecutionItem(
    SolrStoredAction Action,
    SolrPayloadSpec Payload);

public sealed record SolrExecutionPreflight(
    SolrMutationTarget Target,
    IReadOnlyList<SolrExecutionItem> Items,
    int DiskFilesObserved,
    int SolrDocumentsObserved,
    DateTime CheckedAtUtc);

public sealed class SolrExecutionException : Exception
{
    public SolrExecutionException(string message) : base(message) { }
    public SolrExecutionException(string message, Exception inner) : base(message, inner) { }
}
