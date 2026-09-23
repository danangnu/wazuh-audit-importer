using System.Globalization;
using System.Net;
using System.Text.Json;

namespace WazuhAuditImporter;

public sealed class SolrReadOnlyClient : IDisposable
{
    private readonly ImportSettings _settings;
    private readonly HttpClient _http;

    public SolrReadOnlyClient(ImportSettings settings)
    {
        _settings = settings;
        _settings.ValidateSolrReadOnly();
        _http = new HttpClient
        {
            Timeout = TimeSpan.FromSeconds(settings.SolrTimeoutSeconds)
        };
    }

    public void Dispose() => _http.Dispose();

    public SolrSchemaInfo ReadSchema()
    {
        Dictionary<string, SolrFieldInfo> fields;
        string uniqueKey;

        try
        {
            using var full = GetJson("schema?wt=json");
            if (!full.RootElement.TryGetProperty("schema", out var schema) || schema.ValueKind != JsonValueKind.Object)
                throw new SolrReadOnlyException("Full schema API did not return a schema object.");
            uniqueKey = ReadRequiredString(schema, "uniqueKey");
            if (!schema.TryGetProperty("fields", out var fieldArray) || fieldArray.ValueKind != JsonValueKind.Array)
                throw new SolrReadOnlyException("Full schema API did not return a fields array.");
            fields = new Dictionary<string, SolrFieldInfo>(StringComparer.Ordinal);
            foreach (var field in fieldArray.EnumerateArray())
            {
                if (field.ValueKind != JsonValueKind.Object) continue;
                var name = ReadOptionalString(field, "name");
                if (string.IsNullOrWhiteSpace(name)) continue;
                fields[name] = new SolrFieldInfo(
                    name,
                    ReadOptionalString(field, "type"),
                    ReadOptionalBoolean(field, "indexed"),
                    ReadOptionalBoolean(field, "stored"),
                    ReadOptionalBoolean(field, "multiValued"));
            }
        }
        catch (SolrReadOnlyException)
        {
            // Compatibility fallback for installations that expose only narrower
            // Schema API resources rather than the full schema document.
            using var uniqueKeyJson = GetJson("schema/uniquekey?wt=json");
            uniqueKey = ReadRequiredString(uniqueKeyJson.RootElement, "uniqueKey");
            fields = new Dictionary<string, SolrFieldInfo>(StringComparer.Ordinal);
            foreach (var name in new[]
                     {
                         _settings.SolrIdField,
                         _settings.SolrCandidateField,
                         _settings.SolrPathField,
                         _settings.SolrLastUpdateField,
                         _settings.SolrContentField
                     }.Distinct(StringComparer.Ordinal))
            {
                using var doc = GetJson($"schema/fields/{Uri.EscapeDataString(name)}?wt=json");
                if (!doc.RootElement.TryGetProperty("field", out var field) || field.ValueKind != JsonValueKind.Object)
                    throw new SolrReadOnlyException($"Schema API did not return field metadata for '{name}'.");
                var returnedName = ReadRequiredString(field, "name");
                if (!returnedName.Equals(name, StringComparison.Ordinal))
                    throw new SolrReadOnlyException($"Schema API returned unexpected field '{returnedName}' for requested '{name}'.");
                fields[name] = new SolrFieldInfo(
                    returnedName,
                    ReadOptionalString(field, "type"),
                    ReadOptionalBoolean(field, "indexed"),
                    ReadOptionalBoolean(field, "stored"),
                    ReadOptionalBoolean(field, "multiValued"));
            }
        }

        string? solrVersion = null;
        try
        {
            using var system = GetJson("admin/info/system?wt=json");
            if (system.RootElement.TryGetProperty("lucene", out var lucene) && lucene.ValueKind == JsonValueKind.Object)
            {
                solrVersion = ReadOptionalString(lucene, "solr-spec-version")
                    ?? ReadOptionalString(lucene, "solr-impl-version");
            }
        }
        catch (SolrReadOnlyException)
        {
            // Version discovery is supplementary. Schema and candidate queries remain mandatory.
        }

        return new SolrSchemaInfo(uniqueKey, fields, solrVersion);
    }

    public IReadOnlyList<SolrReadOnlyDocument> QueryCandidate(string candidateId)
    {
        if (string.IsNullOrEmpty(candidateId) || candidateId.Any(c => !char.IsAsciiDigit(c)))
            throw new ArgumentException("Candidate ID must contain digits only.", nameof(candidateId));

        var parameters = new Dictionary<string, string>
        {
            ["q"] = $"{_settings.SolrCandidateField}:{candidateId}",
            ["fl"] = string.Join(',', _settings.SolrIdField, _settings.SolrCandidateField,
                _settings.SolrPathField, _settings.SolrLastUpdateField),
            ["rows"] = _settings.SolrMaxRows.ToString(CultureInfo.InvariantCulture),
            ["wt"] = "json"
        };
        using var json = GetJson("select?" + BuildQuery(parameters));
        if (!json.RootElement.TryGetProperty("response", out var response) || response.ValueKind != JsonValueKind.Object)
            throw new SolrReadOnlyException("Solr select response did not contain an object named 'response'.");
        var numFound = ReadRequiredInt64(response, "numFound");
        if (numFound > _settings.SolrMaxRows)
            throw new SolrReadOnlyException($"Candidate {candidateId} returned {numFound} Solr documents, exceeding the Step 9 row cap of {_settings.SolrMaxRows}. No comparison was produced.");
        if (!response.TryGetProperty("docs", out var docs) || docs.ValueKind != JsonValueKind.Array)
            throw new SolrReadOnlyException("Solr select response did not contain a docs array.");

        var result = new List<SolrReadOnlyDocument>();
        foreach (var item in docs.EnumerateArray())
        {
            if (item.ValueKind != JsonValueKind.Object)
                throw new SolrReadOnlyException("Solr docs array contained a non-object value.");
            var id = ReadFlexibleRequiredScalar(item, _settings.SolrIdField);
            var dbcandno = ReadFlexibleRequiredScalar(item, _settings.SolrCandidateField);
            var path = ReadFlexibleRequiredScalar(item, _settings.SolrPathField);
            var lastUpdate = ReadOptionalDate(item, _settings.SolrLastUpdateField);
            result.Add(new SolrReadOnlyDocument(id, dbcandno, path, lastUpdate));
        }
        return result;
    }

    private JsonDocument GetJson(string relative)
    {
        var url = _settings.SolrBaseUrl.TrimEnd('/') + "/" + relative.TrimStart('/');
        try
        {
            using var response = _http.GetAsync(url, HttpCompletionOption.ResponseHeadersRead).GetAwaiter().GetResult();
            if (response.StatusCode != HttpStatusCode.OK)
                throw new SolrReadOnlyException($"Read-only Solr GET returned HTTP {(int)response.StatusCode} ({response.ReasonPhrase}) for {SafeEndpoint(relative)}.");
            var bytes = response.Content.ReadAsByteArrayAsync().GetAwaiter().GetResult();
            if (bytes.Length > 8 * 1024 * 1024)
                throw new SolrReadOnlyException("Read-only Solr response exceeded the 8 MiB pilot limit.");
            return JsonDocument.Parse(bytes, new JsonDocumentOptions
            {
                AllowTrailingCommas = false,
                CommentHandling = JsonCommentHandling.Disallow,
                MaxDepth = 64
            });
        }
        catch (SolrReadOnlyException) { throw; }
        catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException or JsonException)
        {
            throw new SolrReadOnlyException($"Read-only Solr request failed for {SafeEndpoint(relative)}: {ex.Message}", ex);
        }
    }

    private static string SafeEndpoint(string relative) => relative.Split('?')[0];

    private static string BuildQuery(IReadOnlyDictionary<string, string> values) =>
        string.Join("&", values.Select(x => Uri.EscapeDataString(x.Key) + "=" + Uri.EscapeDataString(x.Value)));

    private static string ReadRequiredString(JsonElement obj, string name)
    {
        if (!obj.TryGetProperty(name, out var value) || value.ValueKind != JsonValueKind.String)
            throw new SolrReadOnlyException($"Solr JSON field '{name}' is missing or is not a string.");
        return value.GetString() ?? string.Empty;
    }

    private static string? ReadOptionalString(JsonElement obj, string name) =>
        obj.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.String ? value.GetString() : null;

    private static bool? ReadOptionalBoolean(JsonElement obj, string name) =>
        obj.TryGetProperty(name, out var value) && value.ValueKind is JsonValueKind.True or JsonValueKind.False ? value.GetBoolean() : null;

    private static long ReadRequiredInt64(JsonElement obj, string name)
    {
        if (!obj.TryGetProperty(name, out var value) || value.ValueKind != JsonValueKind.Number || !value.TryGetInt64(out var parsed))
            throw new SolrReadOnlyException($"Solr JSON field '{name}' is missing or is not an integer.");
        return parsed;
    }

    private static string ReadFlexibleRequiredScalar(JsonElement obj, string name)
    {
        if (!obj.TryGetProperty(name, out var value))
            throw new SolrReadOnlyException($"Solr document is missing required field '{name}'.");
        return value.ValueKind switch
        {
            JsonValueKind.String => value.GetString() ?? string.Empty,
            JsonValueKind.Number => value.GetRawText(),
            _ => throw new SolrReadOnlyException($"Solr document field '{name}' is not a scalar string/number.")
        };
    }

    private static DateTimeOffset? ReadOptionalDate(JsonElement obj, string name)
    {
        if (!obj.TryGetProperty(name, out var value) || value.ValueKind == JsonValueKind.Null) return null;
        if (value.ValueKind != JsonValueKind.String)
            throw new SolrReadOnlyException($"Solr document field '{name}' is not a date string.");
        var raw = value.GetString();
        if (string.IsNullOrWhiteSpace(raw)) return null;
        if (!DateTimeOffset.TryParse(raw, CultureInfo.InvariantCulture,
                DateTimeStyles.AllowWhiteSpaces | DateTimeStyles.AssumeUniversal, out var parsed))
            throw new SolrReadOnlyException($"Solr document field '{name}' contains an unsupported date value.");
        return parsed;
    }
}
