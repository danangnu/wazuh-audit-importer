using System.Net;
using System.Text;
using System.Text.Json;

namespace WazuhAuditImporter;

public sealed class SolrWriteClient : IDisposable
{
    private readonly ImportSettings _settings;
    private readonly HttpClient _http;

    public SolrWriteClient(ImportSettings settings)
    {
        _settings = settings;
        _settings.ValidateSolrReadOnly();
        _http = new HttpClient { Timeout = TimeSpan.FromSeconds(settings.SolrTimeoutSeconds) };
    }

    public void Dispose() => _http.Dispose();

    public void PostReviewedPayload(ulong actionId, string payloadJson)
    {
        if (string.IsNullOrWhiteSpace(payloadJson))
            throw new SolrExecutionException($"Action {actionId} has an empty update payload.");
        if (Encoding.UTF8.GetByteCount(payloadJson) > 16 * 1024 * 1024)
            throw new SolrExecutionException($"Action {actionId} payload exceeds the 16 MiB Step 11 pilot limit.");
        PostJson("update?wt=json", payloadJson, $"action {actionId}");
    }

    public void Commit() => PostJson("update?wt=json", "{\"commit\":{}}", "explicit commit");

    private void PostJson(string relative, string json, string operation)
    {
        var url = _settings.SolrBaseUrl.TrimEnd('/') + "/" + relative;
        try
        {
            using var content = new StringContent(json, Encoding.UTF8, "application/json");
            using var response = _http.PostAsync(url, content).GetAwaiter().GetResult();
            var bytes = response.Content.ReadAsByteArrayAsync().GetAwaiter().GetResult();
            if (bytes.Length > 2 * 1024 * 1024)
                throw new SolrExecutionException($"Solr response for {operation} exceeded the 2 MiB pilot limit.");
            if (response.StatusCode != HttpStatusCode.OK)
                throw new SolrExecutionException($"Solr update returned HTTP {(int)response.StatusCode} ({response.ReasonPhrase}) for {operation}.");
            using var doc = JsonDocument.Parse(bytes, new JsonDocumentOptions
            {
                AllowTrailingCommas = false,
                CommentHandling = JsonCommentHandling.Disallow,
                MaxDepth = 64
            });
            if (!doc.RootElement.TryGetProperty("responseHeader", out var header) ||
                header.ValueKind != JsonValueKind.Object ||
                !header.TryGetProperty("status", out var status) ||
                status.ValueKind != JsonValueKind.Number ||
                !status.TryGetInt32(out var value) || value != 0)
                throw new SolrExecutionException($"Solr update did not return responseHeader.status=0 for {operation}.");
        }
        catch (SolrExecutionException) { throw; }
        catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException or JsonException)
        {
            throw new SolrExecutionException($"Solr update request failed for {operation}: {ex.Message}", ex);
        }
    }
}
