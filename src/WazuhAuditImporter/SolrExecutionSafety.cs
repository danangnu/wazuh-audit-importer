namespace WazuhAuditImporter;

public static class SolrExecutionSafety
{
    public static void ValidateReadyItem(SolrExecutionItem item)
    {
        var a = item.Action;
        var p = item.Payload;
        if (a.ActionStatus != "planned")
            throw new SolrExecutionException($"Action {a.ActionId} is status={a.ActionStatus}; Step 11 requires planned actions.");
        if (p.ActionId != a.ActionId || p.MutationId != a.MutationId || p.ActionType != a.ActionType)
            throw new SolrExecutionException($"Payload/action identity mismatch for action {a.ActionId}.");
        if (p.Status != "ready" || !string.IsNullOrWhiteSpace(p.BlockReason))
            throw new SolrExecutionException($"Action {a.ActionId} payload is not execution-ready (status={p.Status}, reason={p.BlockReason ?? "none"}).");
        if (string.IsNullOrWhiteSpace(p.PayloadJson) || string.IsNullOrWhiteSpace(p.PayloadSha256))
            throw new SolrExecutionException($"Action {a.ActionId} ready payload is missing JSON or SHA-256 evidence.");
        var actualHash = LegacyContentExtractor.HexSha256(System.Text.Encoding.UTF8.GetBytes(p.PayloadJson));
        if (!actualHash.Equals(p.PayloadSha256, StringComparison.Ordinal))
            throw new SolrExecutionException($"Stored payload SHA-256 mismatch for action {a.ActionId}.");
    }

    public static void ValidateCurrentPayload(SolrExecutionItem stored, SolrPayloadSpec current)
    {
        var p = stored.Payload;
        if (current.Status != "ready")
            throw new SolrExecutionException($"Action {stored.Action.ActionId} no longer builds a ready payload: {current.BlockReason ?? current.Status}.");
        if (p.ActionId != current.ActionId || p.MutationId != current.MutationId || p.ActionType != current.ActionType ||
            p.Status != current.Status || p.Extractor != current.Extractor || p.PayloadJson != current.PayloadJson ||
            p.PayloadSha256 != current.PayloadSha256 || p.SourceFileSha256 != current.SourceFileSha256 ||
            p.ContentSha256 != current.ContentSha256 || p.ContentCharCount != current.ContentCharCount ||
            p.SourceFileLength != current.SourceFileLength || !SameTimestamp(p.SourceFileLastWriteUtc, current.SourceFileLastWriteUtc) ||
            p.BlockReason != current.BlockReason)
            throw new SolrExecutionException($"SOURCE/PAYLOAD DRIFT: action {stored.Action.ActionId} no longer matches the reviewed Step 10B payload.");
    }

    private static bool SameTimestamp(DateTime? a, DateTime? b)
    {
        if (a is null || b is null) return a is null && b is null;
        return Math.Abs((a.Value.ToUniversalTime() - b.Value.ToUniversalTime()).TotalMilliseconds) <= 1.0;
    }

    public static void ValidateCurrentActionPlan(
        IReadOnlyList<SolrExecutionItem> stored,
        IReadOnlyList<SolrConcreteActionSpec> current)
    {
        if (stored.Count != current.Count)
            throw new SolrExecutionException($"SOLR STATE DRIFT: stored action count={stored.Count}, current deterministic plan count={current.Count}.");
        for (var i = 0; i < stored.Count; i++)
        {
            var a = stored[i].Action;
            var b = current[i];
            if (a.ActionOrder != b.ActionOrder || a.ActionType != b.ActionType || a.Reason != b.Reason ||
                a.SolrDocumentId != b.SolrDocumentId ||
                SolrPathMapper.NormalizeForComparison(a.CanonicalPath) != SolrPathMapper.NormalizeForComparison(b.CanonicalPath) ||
                !string.Equals(a.SourceFilePath, b.SourceFilePath, StringComparison.OrdinalIgnoreCase) ||
                a.SourceFileLength != b.SourceFileLength || a.SourceFileLastWriteUtc != b.SourceFileLastWriteUtc ||
                a.IdempotencyKey != b.IdempotencyKey)
            {
                throw new SolrExecutionException(
                    $"SOLR/DISK PLAN DRIFT: action order {a.ActionOrder} no longer matches the reviewed Step 10A plan.");
            }
        }
    }
}
