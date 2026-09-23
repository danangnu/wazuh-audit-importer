using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace WazuhAuditImporter;

public static class SolrPayloadBuilder
{
    public static SolrPayloadSpec Build(SolrStoredAction action, string workerRoot, DateTime generatedAtUtc)
    {
        if (action.ActionStatus != "planned")
            throw new SolrPayloadException($"Action {action.ActionId} is status={action.ActionStatus}; Step 10B only builds planned actions.");

        if (action.ActionType == "delete_document")
        {
            var json = JsonSerializer.Serialize(new { delete = new { id = action.SolrDocumentId } });
            return Ready(action, "solr_delete_by_id", json, null, null, null, null, generatedAtUtc);
        }

        if (action.ActionType != "index_document")
            throw new SolrPayloadException($"Unsupported concrete action type: {action.ActionType}.");

        var extraction = LegacyContentExtractor.ExtractForAction(action, workerRoot);
        if (extraction.Status == "blocked")
        {
            return new SolrPayloadSpec(action.ActionId, action.MutationId, action.ActionType, "blocked",
                extraction.Extractor, null, null, extraction.SourceFileSha256, extraction.ContentSha256,
                extraction.ContentCharCount, extraction.SourceFileLength, extraction.SourceFileLastWriteUtc,
                extraction.BlockReason, generatedAtUtc);
        }

        var lastUpdate = generatedAtUtc.ToUniversalTime().ToString("yyyy-MM-dd'T'HH:mm:ss.ffffff'Z'", System.Globalization.CultureInfo.InvariantCulture);
        var payload = JsonSerializer.Serialize(new
        {
            add = new
            {
                doc = new Dictionary<string, object?>
                {
                    ["id"] = action.SolrDocumentId,
                    ["dbcandno"] = action.CandidateId,
                    ["content"] = extraction.Content!,
                    ["path"] = action.CanonicalPath,
                    ["last_update"] = lastUpdate
                }
            }
        });
        return Ready(action, extraction.Extractor, payload, extraction.SourceFileSha256,
            extraction.ContentSha256, extraction.ContentCharCount, extraction.SourceFileLength,
            generatedAtUtc, extraction.SourceFileLastWriteUtc);
    }

    private static SolrPayloadSpec Ready(SolrStoredAction action, string extractor, string json,
        string? sourceHash, string? contentHash, ulong? chars, ulong? sourceLength,
        DateTime generatedAtUtc, DateTime? sourceWrite = null)
    {
        var payloadHash = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(json))).ToLowerInvariant();
        return new SolrPayloadSpec(action.ActionId, action.MutationId, action.ActionType, "ready",
            extractor, json, payloadHash, sourceHash, contentHash, chars, sourceLength,
            sourceWrite, null, generatedAtUtc);
    }
}
