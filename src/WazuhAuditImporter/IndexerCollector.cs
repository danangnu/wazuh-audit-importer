using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using MySqlConnector;

namespace WazuhAuditImporter;

public sealed record CollectorCursor(DateTime ThroughUtc, string? LastWazuhEventId);
public sealed record CollectorSummary(int Seen, int Accepted, int Inserted, int Duplicates, int Ignored, DateTime ThroughUtc);

public static class IndexerCollector
{
    public static CollectorSummary CollectOnce(
        ImportSettings settings,
        MySqlConnection connection,
        string indexerUser,
        string indexerPassword)
    {
        settings.ValidateCollector();
        var checkpoint = CheckpointRepository.Read(connection, settings);
        var upperBoundUtc = DateTime.UtcNow;
        var lowerBoundUtc = checkpoint is null
            ? upperBoundUtc.AddMinutes(-settings.IndexerInitialLookbackMinutes)
            : checkpoint.ThroughUtc.AddSeconds(-settings.IndexerOverlapSeconds);

        if (lowerBoundUtc >= upperBoundUtc)
            lowerBoundUtc = upperBoundUtc.AddSeconds(-settings.IndexerOverlapSeconds);

        Console.WriteLine($"Collector window UTC: {Fmt(lowerBoundUtc)} .. {Fmt(upperBoundUtc)}");
        Console.WriteLine($"Indexer endpoint: {settings.IndexerBaseUrl}; stream={settings.CollectorStreamKey}");
        Console.WriteLine("The query is read-only. Candidate/document files are not accessed by this collector.");

        using var handler = new HttpClientHandler();
        if (settings.IndexerAllowUntrustedCertificate)
            handler.ServerCertificateCustomValidationCallback = HttpClientHandler.DangerousAcceptAnyServerCertificateValidator;

        using var client = new HttpClient(handler)
        {
            BaseAddress = new Uri(settings.IndexerBaseUrl, UriKind.Absolute),
            Timeout = TimeSpan.FromSeconds(settings.IndexerTimeoutSeconds)
        };
        var token = Convert.ToBase64String(Encoding.UTF8.GetBytes(indexerUser + ":" + indexerPassword));
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Basic", token);

        var seen = 0;
        var accepted = 0;
        var inserted = 0;
        var duplicates = 0;
        var ignored = 0;
        string? lastAcceptedEventId = checkpoint?.LastWazuhEventId;

        for (var page = 0; page < settings.IndexerMaxPages; page++)
        {
            var from = checked(page * settings.IndexerPageSize);
            var query = BuildQuery(settings, lowerBoundUtc, upperBoundUtc, from);
            using var request = new HttpRequestMessage(HttpMethod.Post,
                settings.IndexerIndexPattern + "/_search");
            request.Content = new StringContent(query, Encoding.UTF8, "application/json");

            using var response = client.Send(request);
            var responseText = response.Content.ReadAsStringAsync().GetAwaiter().GetResult();
            if (!response.IsSuccessStatusCode)
                throw new InvalidOperationException(
                    $"Indexer query failed: HTTP {(int)response.StatusCode}. Stop; do not advance the checkpoint.");

            using var doc = JsonDocument.Parse(responseText);
            if (!doc.RootElement.TryGetProperty("hits", out var hitsObject) ||
                !hitsObject.TryGetProperty("hits", out var hits) || hits.ValueKind != JsonValueKind.Array)
                throw new FormatException("Indexer response is missing hits.hits array.");

            var count = hits.GetArrayLength();
            foreach (var hit in hits.EnumerateArray())
            {
                seen++;
                var raw = hit.GetRawText();
                if (Encoding.UTF8.GetByteCount(raw) > AlertParser.MaximumInputBytes)
                    throw new FormatException("Indexer returned an event larger than the 4 MiB single-event limit.");
                var parsed = AlertParser.Parse(raw, settings);
                if (parsed.Alert is null)
                {
                    ignored++;
                    continue;
                }

                accepted++;
                var result = AuditRepository.Import(connection, parsed.Alert, settings);
                if (result.Inserted) inserted++; else duplicates++;
                lastAcceptedEventId = parsed.Alert.WazuhEventId;
                Console.WriteLine($"  {(result.Inserted ? "NEW" : "DUP")} event={parsed.Alert.WazuhEventId} candidate={parsed.Alert.CandidateId} type={parsed.Alert.EventType} version={result.Queue.EventVersion}");
            }

            if (count < settings.IndexerPageSize)
                break;

            if (page == settings.IndexerMaxPages - 1)
                throw new InvalidOperationException(
                    "Collector reached its configured page limit. Checkpoint was NOT advanced; narrow the scope/window or increase limits after review.");
        }

        CheckpointRepository.Upsert(connection, settings,
            new CollectorCursor(upperBoundUtc, lastAcceptedEventId));

        return new CollectorSummary(seen, accepted, inserted, duplicates, ignored, upperBoundUtc);
    }

    private static string BuildQuery(ImportSettings settings, DateTime lowerUtc, DateTime upperUtc, int from)
    {
        var body = new
        {
            from,
            size = settings.IndexerPageSize,
            sort = new object[] { new Dictionary<string, object> { ["timestamp"] = new { order = "asc" } } },
            query = new
            {
                @bool = new
                {
                    filter = new object[]
                    {
                        new { term = new Dictionary<string, string> { ["agent.id"] = settings.AgentId } },
                        new { exists = new { field = "syscheck.path" } },
                        new { terms = new Dictionary<string, string[]> { ["syscheck.event"] = new[] { "added", "modified", "deleted" } } },
                        new { range = new Dictionary<string, object> { ["timestamp"] = new
                            {
                                gte = lowerUtc.ToString("yyyy-MM-dd'T'HH:mm:ss.ffffff'Z'"),
                                lte = upperUtc.ToString("yyyy-MM-dd'T'HH:mm:ss.ffffff'Z'")
                            }
                        } }
                    }
                }
            }
        };
        return JsonSerializer.Serialize(body);
    }

    private static string Fmt(DateTime value) => value.ToUniversalTime().ToString("yyyy-MM-dd'T'HH:mm:ss.ffffff'Z'");
}
