using System.Globalization;
using System.Text;
using System.Text.Json;
using MySqlConnector;

namespace WazuhAuditImporter;

public sealed record PilotEventVersion(
    string CandidateId,
    ulong Version,
    ulong AuditEventId,
    DateTime EventTimeUtc,
    DateTime IngestedAtUtc);

public sealed record PilotMutationRow(
    ulong MutationId,
    string CandidateId,
    ulong WorkerVersion,
    string Operation,
    string Status,
    uint AttemptCount,
    DateTime PlannedAtUtc,
    DateTime UpdatedAtUtc,
    DateTime? AppliedAtUtc);

public sealed record PilotActionAggregate(
    ulong MutationId,
    int Total,
    int Planned,
    int Processing,
    int Applied,
    int Failed,
    int Skipped,
    DateTime? FirstPlannedAtUtc,
    DateTime? LastAppliedAtUtc);

public sealed record PilotPayloadAggregate(
    ulong MutationId,
    int Total,
    int Ready,
    int Blocked,
    DateTime? LastGeneratedAtUtc);

public sealed record PilotMutationTiming(
    ulong MutationId,
    string CandidateId,
    ulong WorkerVersion,
    string Operation,
    string Status,
    uint AttemptCount,
    ulong? AuditEventId,
    DateTime? EventTimeUtc,
    DateTime? IngestedAtUtc,
    DateTime MutationPlannedAtUtc,
    DateTime? FirstActionPlannedAtUtc,
    DateTime? PayloadReadyAtUtc,
    DateTime? AppliedAtUtc,
    int ActionCount,
    int ReadyPayloadCount,
    int BlockedPayloadCount,
    double? EventToIngestSeconds,
    double? IngestToMutationSeconds,
    double? EventToMutationSeconds,
    double? MutationToPayloadSeconds,
    double? EventToReadySeconds,
    double? ReadyToAppliedSeconds,
    double? EventToAppliedSeconds);

public sealed record PilotLatencyStats(
    int Count,
    double? MinSeconds,
    double? P50Seconds,
    double? P95Seconds,
    double? AverageSeconds,
    double? MaxSeconds);

public sealed record PilotCandidateLiveState(
    string CandidateId,
    string BaselineStatus,
    int DiskFilesObserved,
    int EligibleFiles,
    int SkippedFiles,
    int SolrDocuments,
    int MatchCount,
    int MissingCount,
    int StaleCount,
    int OtherConflictCount,
    bool Synchronized);

public sealed record PilotStatusCounts(
    int AuditEvents,
    int Mutations,
    int AppliedMutations,
    int NotRequiredMutations,
    int PlannedMutations,
    int ProcessingMutations,
    int FailedMutations,
    int Actions,
    int AppliedActions,
    int ReadyPayloads,
    int BlockedPayloads,
    int ApprovedBaselines,
    int PendingBaselines,
    int SynchronizedCandidates,
    int DriftedCandidates);

public sealed record PilotLegacyComparison(
    double ReferenceSeconds,
    string ReferenceSource,
    int EventToReadySamples,
    double? EventToReadyP50Seconds,
    double? ApproximateP50SpeedupFactor,
    double? ApproximateP50SecondsSaved,
    string Caveat);

public sealed record PilotMetricsReport(
    string ReportVersion,
    DateTime GeneratedAtUtc,
    string SourceInstance,
    string AgentId,
    IReadOnlyList<string> CandidateIds,
    PilotStatusCounts Counts,
    IReadOnlyDictionary<string, PilotLatencyStats> Latencies,
    IReadOnlyList<PilotCandidateLiveState> CurrentCandidates,
    IReadOnlyList<PilotMutationTiming> Mutations,
    PilotLegacyComparison? LegacyComparison,
    IReadOnlyList<string> Caveats);

public static class PilotMetricsMath
{
    public static PilotLatencyStats Summarize(IEnumerable<double?> values)
    {
        var clean = values.Where(x => x.HasValue && x.Value >= 0 && double.IsFinite(x.Value))
            .Select(x => x!.Value).OrderBy(x => x).ToArray();
        if (clean.Length == 0) return new PilotLatencyStats(0, null, null, null, null, null);
        return new PilotLatencyStats(
            clean.Length,
            clean[0],
            Percentile(clean, 0.50),
            Percentile(clean, 0.95),
            clean.Average(),
            clean[^1]);
    }

    public static double Percentile(IReadOnlyList<double> sortedValues, double percentile)
    {
        if (sortedValues.Count == 0) throw new ArgumentException("At least one value is required.", nameof(sortedValues));
        if (percentile is < 0 or > 1) throw new ArgumentOutOfRangeException(nameof(percentile));
        if (sortedValues.Count == 1) return sortedValues[0];
        var index = percentile * (sortedValues.Count - 1);
        var lower = (int)Math.Floor(index);
        var upper = (int)Math.Ceiling(index);
        if (lower == upper) return sortedValues[lower];
        var weight = index - lower;
        return sortedValues[lower] + (sortedValues[upper] - sortedValues[lower]) * weight;
    }

    public static double? SecondsBetween(DateTime? start, DateTime? end)
    {
        if (start is null || end is null) return null;
        var seconds = (end.Value - start.Value).TotalSeconds;
        return seconds >= 0 ? seconds : null;
    }

    public static PilotLegacyComparison? BuildLegacyComparison(double? referenceSeconds, PilotLatencyStats eventToReady)
    {
        if (referenceSeconds is null) return null;
        if (referenceSeconds <= 0 || !double.IsFinite(referenceSeconds.Value))
            throw new ArgumentOutOfRangeException(nameof(referenceSeconds), "Legacy scan reference must be a positive finite number of seconds.");
        var p50 = eventToReady.P50Seconds;
        return new PilotLegacyComparison(
            referenceSeconds.Value,
            "operator-supplied legacy scan reference; not measured by WazuhAuditImporter",
            eventToReady.Count,
            p50,
            p50 is > 0 ? referenceSeconds.Value / p50.Value : null,
            p50 is not null ? referenceSeconds.Value - p50.Value : null,
            "Reference-only comparison. It is not a controlled benchmark and does not isolate hardware, load, candidate count, or operator approval time.");
    }
}

public static class PilotMetricsService
{
    public static int Run(ImportSettings settings, MySqlConnection connection, string workerRoot,
        string? reportDirectory, double? legacyScanSeconds)
    {
        settings.ValidateWorker(workerRoot, Path.Combine(Path.GetTempPath(), "wazuh-step14e-validation"));
        settings.ValidateSolrReadOnly();

        Console.WriteLine("Step 14E pilot metrics and delivery report - READ/REPORT ONLY.");
        Console.WriteLine("Reads MariaDB pilot audit state, FLOSVR01 metadata, and Solr using GET only.");
        Console.WriteLine("No source content is read. No MariaDB application rows or Solr documents are changed.\n");

        var events = LoadEvents(connection, settings);
        var mutations = LoadMutations(connection, settings);
        var actionAgg = LoadActionAggregates(connection, mutations.Select(x => x.MutationId));
        var payloadAgg = LoadPayloadAggregates(connection, mutations.Select(x => x.MutationId));
        var baseline = LoadBaselineStatuses(connection, settings);
        var timings = BuildTimings(events, mutations, actionAgg, payloadAgg);
        var live = CaptureLiveCandidateState(settings, workerRoot, baseline);

        var latencies = new Dictionary<string, PilotLatencyStats>(StringComparer.Ordinal)
        {
            ["event_to_ingest"] = PilotMetricsMath.Summarize(timings.Select(x => x.EventToIngestSeconds)),
            ["ingest_to_mutation"] = PilotMetricsMath.Summarize(timings.Select(x => x.IngestToMutationSeconds)),
            ["event_to_mutation"] = PilotMetricsMath.Summarize(timings.Select(x => x.EventToMutationSeconds)),
            ["mutation_to_payload_ready"] = PilotMetricsMath.Summarize(timings.Select(x => x.MutationToPayloadSeconds)),
            ["event_to_ready_for_approval"] = PilotMetricsMath.Summarize(timings.Select(x => x.EventToReadySeconds)),
            ["ready_to_verified_apply"] = PilotMetricsMath.Summarize(timings.Select(x => x.ReadyToAppliedSeconds)),
            ["event_to_verified_apply"] = PilotMetricsMath.Summarize(timings.Select(x => x.EventToAppliedSeconds))
        };

        var counts = BuildCounts(events, mutations, actionAgg, payloadAgg, baseline, live);
        var legacy = PilotMetricsMath.BuildLegacyComparison(legacyScanSeconds, latencies["event_to_ready_for_approval"]);
        var caveats = new List<string>
        {
            "Mutation worker_version is mapped to the corresponding unique audit event version for the same candidate, ordered by audit_event_id. Duplicate Wazuh replays do not increment the version.",
            "event_to_ready_for_approval measures system preparation through reviewed payload generation; it excludes the later operator approval delay.",
            "ready_to_verified_apply includes human/operator review time and any waiting time before explicit --apply, so it is not a pure machine-latency metric.",
            "applied_at_utc is recorded only after Solr POST/commit and post-commit GET verification succeed.",
            "No measured timing for the legacy continuous scanner is stored in the pilot database. A speedup claim is omitted unless --legacy-scan-seconds is explicitly supplied.",
            "Candidate-source outage and production Solr GET-outage live tests remain deferred to a maintenance window; Step 14D offline/recovery safeguards remain in force."
        };

        var report = new PilotMetricsReport(
            "14E-v1",
            DateTime.UtcNow,
            settings.SourceInstance,
            settings.AgentId,
            settings.CandidateIds.ToArray(),
            counts,
            latencies,
            live,
            timings,
            legacy,
            caveats);

        PrintSummary(report);
        var outputDir = Path.GetFullPath(reportDirectory ?? "pilot-reports");
        Directory.CreateDirectory(outputDir);
        var stamp = DateTime.UtcNow.ToString("yyyyMMdd-HHmmss", CultureInfo.InvariantCulture);
        var jsonPath = Path.Combine(outputDir, $"step14e-pilot-metrics-{stamp}.json");
        var csvPath = Path.Combine(outputDir, $"step14e-mutation-timings-{stamp}.csv");
        var mdPath = Path.Combine(outputDir, $"step14e-pilot-delivery-report-{stamp}.md");
        File.WriteAllText(jsonPath, JsonSerializer.Serialize(report, new JsonSerializerOptions { WriteIndented = true }), new UTF8Encoding(false));
        File.WriteAllText(csvPath, BuildCsv(timings), new UTF8Encoding(false));
        File.WriteAllText(mdPath, BuildMarkdown(report), new UTF8Encoding(false));
        Console.WriteLine($"\nJSON metrics saved : {jsonPath}");
        Console.WriteLine($"CSV timings saved : {csvPath}");
        Console.WriteLine($"Delivery report   : {mdPath}");
        Console.WriteLine("\nSTEP 14E COMPLETE. Read/report only; no Solr writes and no application-row mutations occurred.");
        return 0;
    }

    public static IReadOnlyList<PilotMutationTiming> BuildTimings(
        IReadOnlyList<PilotEventVersion> events,
        IReadOnlyList<PilotMutationRow> mutations,
        IReadOnlyDictionary<ulong, PilotActionAggregate> actionAgg,
        IReadOnlyDictionary<ulong, PilotPayloadAggregate> payloadAgg)
    {
        var byVersion = events.ToDictionary(x => (x.CandidateId, x.Version), x => x);
        var list = new List<PilotMutationTiming>();
        foreach (var mutation in mutations.OrderBy(x => x.MutationId))
        {
            byVersion.TryGetValue((mutation.CandidateId, mutation.WorkerVersion), out var ev);
            actionAgg.TryGetValue(mutation.MutationId, out var action);
            payloadAgg.TryGetValue(mutation.MutationId, out var payload);
            var eventTime = ev?.EventTimeUtc;
            var ingested = ev?.IngestedAtUtc;
            var payloadReady = payload is { Blocked: 0, Ready: > 0 } ? payload.LastGeneratedAtUtc : null;
            list.Add(new PilotMutationTiming(
                mutation.MutationId,
                mutation.CandidateId,
                mutation.WorkerVersion,
                mutation.Operation,
                mutation.Status,
                mutation.AttemptCount,
                ev?.AuditEventId,
                eventTime,
                ingested,
                mutation.PlannedAtUtc,
                action?.FirstPlannedAtUtc,
                payloadReady,
                mutation.AppliedAtUtc,
                action?.Total ?? 0,
                payload?.Ready ?? 0,
                payload?.Blocked ?? 0,
                PilotMetricsMath.SecondsBetween(eventTime, ingested),
                PilotMetricsMath.SecondsBetween(ingested, mutation.PlannedAtUtc),
                PilotMetricsMath.SecondsBetween(eventTime, mutation.PlannedAtUtc),
                PilotMetricsMath.SecondsBetween(mutation.PlannedAtUtc, payloadReady),
                PilotMetricsMath.SecondsBetween(eventTime, payloadReady),
                PilotMetricsMath.SecondsBetween(payloadReady, mutation.AppliedAtUtc),
                PilotMetricsMath.SecondsBetween(eventTime, mutation.AppliedAtUtc)));
        }
        return list;
    }

    private static IReadOnlyList<PilotEventVersion> LoadEvents(MySqlConnection connection, ImportSettings settings)
    {
        using var cmd = new MySqlCommand($"""
            SELECT audit_event_id, candidate_id, event_time_utc, ingested_at_utc
            FROM wazuh_audit_poc.audit_event
            WHERE source_instance=@source AND agent_id=@agent
              AND candidate_id IN ({ParameterList(cmdPrefix: "c", settings.CandidateIds.Length)})
            ORDER BY candidate_id, audit_event_id;
            """, connection);
        cmd.Parameters.AddWithValue("@source", settings.SourceInstance);
        cmd.Parameters.AddWithValue("@agent", settings.AgentId);
        for (var i = 0; i < settings.CandidateIds.Length; i++)
            cmd.Parameters.AddWithValue("@c" + i.ToString(CultureInfo.InvariantCulture), settings.CandidateIds[i]);
        var rows = new List<(ulong Id, string Candidate, DateTime Event, DateTime Ingest)>();
        using (var reader = cmd.ExecuteReader())
        {
            while (reader.Read())
                rows.Add((reader.GetUInt64(0), reader.GetString(1), Utc(reader.GetDateTime(2)), Utc(reader.GetDateTime(3))));
        }
        var result = new List<PilotEventVersion>();
        foreach (var group in rows.GroupBy(x => x.Candidate, StringComparer.Ordinal))
        {
            ulong version = 0;
            foreach (var row in group.OrderBy(x => x.Id))
            {
                version++;
                result.Add(new PilotEventVersion(row.Candidate, version, row.Id, row.Event, row.Ingest));
            }
        }
        return result;
    }

    private static IReadOnlyList<PilotMutationRow> LoadMutations(MySqlConnection connection, ImportSettings settings)
    {
        using var cmd = new MySqlCommand($"""
            SELECT mutation_id, candidate_id, worker_version, operation, status, attempt_count,
                   planned_at_utc, updated_at_utc, applied_at_utc
            FROM wazuh_audit_poc.solr_mutation_queue
            WHERE source_instance=@source AND agent_id=@agent
              AND candidate_id IN ({ParameterList("c", settings.CandidateIds.Length)})
            ORDER BY mutation_id;
            """, connection);
        cmd.Parameters.AddWithValue("@source", settings.SourceInstance);
        cmd.Parameters.AddWithValue("@agent", settings.AgentId);
        for (var i = 0; i < settings.CandidateIds.Length; i++)
            cmd.Parameters.AddWithValue("@c" + i.ToString(CultureInfo.InvariantCulture), settings.CandidateIds[i]);
        var list = new List<PilotMutationRow>();
        using var reader = cmd.ExecuteReader();
        while (reader.Read())
            list.Add(new PilotMutationRow(
                reader.GetUInt64(0), reader.GetString(1), reader.GetUInt64(2), reader.GetString(3), reader.GetString(4), Convert.ToUInt32(reader.GetValue(5), CultureInfo.InvariantCulture),
                Utc(reader.GetDateTime(6)), Utc(reader.GetDateTime(7)), reader.IsDBNull(8) ? null : Utc(reader.GetDateTime(8))));
        return list;
    }

    private static IReadOnlyDictionary<ulong, PilotActionAggregate> LoadActionAggregates(MySqlConnection connection, IEnumerable<ulong> mutationIds)
    {
        var ids = mutationIds.Distinct().ToArray();
        if (ids.Length == 0) return new Dictionary<ulong, PilotActionAggregate>();
        using var cmd = new MySqlCommand($"""
            SELECT mutation_id,
                   COUNT(*),
                   SUM(status='planned'), SUM(status='processing'), SUM(status='applied'), SUM(status='failed'), SUM(status='skipped'),
                   MIN(planned_at_utc), MAX(applied_at_utc)
            FROM wazuh_audit_poc.solr_mutation_action
            WHERE mutation_id IN ({ParameterList("m", ids.Length)})
            GROUP BY mutation_id;
            """, connection);
        for (var i = 0; i < ids.Length; i++) cmd.Parameters.AddWithValue("@m" + i, ids[i]);
        var map = new Dictionary<ulong, PilotActionAggregate>();
        using var reader = cmd.ExecuteReader();
        while (reader.Read())
        {
            var row = new PilotActionAggregate(
                reader.GetUInt64(0), Convert.ToInt32(reader.GetValue(1), CultureInfo.InvariantCulture),
                Convert.ToInt32(reader.GetValue(2), CultureInfo.InvariantCulture), Convert.ToInt32(reader.GetValue(3), CultureInfo.InvariantCulture),
                Convert.ToInt32(reader.GetValue(4), CultureInfo.InvariantCulture), Convert.ToInt32(reader.GetValue(5), CultureInfo.InvariantCulture),
                Convert.ToInt32(reader.GetValue(6), CultureInfo.InvariantCulture), reader.IsDBNull(7) ? null : Utc(reader.GetDateTime(7)),
                reader.IsDBNull(8) ? null : Utc(reader.GetDateTime(8)));
            map[row.MutationId] = row;
        }
        return map;
    }

    private static IReadOnlyDictionary<ulong, PilotPayloadAggregate> LoadPayloadAggregates(MySqlConnection connection, IEnumerable<ulong> mutationIds)
    {
        var ids = mutationIds.Distinct().ToArray();
        if (ids.Length == 0) return new Dictionary<ulong, PilotPayloadAggregate>();
        using var cmd = new MySqlCommand($"""
            SELECT mutation_id, COUNT(*), SUM(status='ready'), SUM(status='blocked'), MAX(generated_at_utc)
            FROM wazuh_audit_poc.solr_action_payload
            WHERE mutation_id IN ({ParameterList("m", ids.Length)})
            GROUP BY mutation_id;
            """, connection);
        for (var i = 0; i < ids.Length; i++) cmd.Parameters.AddWithValue("@m" + i, ids[i]);
        var map = new Dictionary<ulong, PilotPayloadAggregate>();
        using var reader = cmd.ExecuteReader();
        while (reader.Read())
        {
            var row = new PilotPayloadAggregate(
                reader.GetUInt64(0), Convert.ToInt32(reader.GetValue(1), CultureInfo.InvariantCulture),
                Convert.ToInt32(reader.GetValue(2), CultureInfo.InvariantCulture), Convert.ToInt32(reader.GetValue(3), CultureInfo.InvariantCulture),
                reader.IsDBNull(4) ? null : Utc(reader.GetDateTime(4)));
            map[row.MutationId] = row;
        }
        return map;
    }

    private static IReadOnlyDictionary<string, string> LoadBaselineStatuses(MySqlConnection connection, ImportSettings settings)
    {
        using var cmd = new MySqlCommand($"""
            SELECT candidate_id, status
            FROM wazuh_audit_poc.candidate_baseline_enrollment
            WHERE source_instance=@source AND agent_id=@agent
              AND candidate_id IN ({ParameterList("c", settings.CandidateIds.Length)});
            """, connection);
        cmd.Parameters.AddWithValue("@source", settings.SourceInstance);
        cmd.Parameters.AddWithValue("@agent", settings.AgentId);
        for (var i = 0; i < settings.CandidateIds.Length; i++) cmd.Parameters.AddWithValue("@c" + i, settings.CandidateIds[i]);
        var map = settings.CandidateIds.ToDictionary(x => x, _ => "NOT_CAPTURED", StringComparer.Ordinal);
        using var reader = cmd.ExecuteReader();
        while (reader.Read()) map[reader.GetString(0)] = reader.GetString(1).ToUpperInvariant();
        return map;
    }

    private static IReadOnlyList<PilotCandidateLiveState> CaptureLiveCandidateState(ImportSettings settings, string workerRoot,
        IReadOnlyDictionary<string, string> baseline)
    {
        using var client = new SolrReadOnlyClient(settings);
        var schema = client.ReadSchema();
        var result = new List<PilotCandidateLiveState>();
        foreach (var candidateId in settings.CandidateIds)
        {
            var folder = CandidateWorker.ResolveCandidateFolder(workerRoot, candidateId);
            var disk = SolrReadOnlyDiscovery.CaptureDiskFiles(workerRoot, folder, settings.SolrCanonicalRoot);
            var docs = client.QueryCandidate(candidateId);
            var report = SolrReadOnlyDiscovery.Compare(settings, candidateId, workerRoot, folder, schema, disk, docs);
            var match = report.Comparisons.Count(x => x.Status == "MATCH");
            var missing = report.Comparisons.Count(x => x.Status == "MISSING_IN_SOLR");
            var stale = report.Comparisons.Count(x => x.Status == "STALE_IN_SOLR");
            var other = report.Comparisons.Count(x => x.Status != "MATCH" && x.Status != "MISSING_IN_SOLR" &&
                x.Status != "STALE_IN_SOLR" && x.Status != "SKIPPED_BY_LEGACY_FILTER");
            result.Add(new PilotCandidateLiveState(
                candidateId,
                baseline.TryGetValue(candidateId, out var status) ? status : "NOT_CAPTURED",
                report.DiskFilesObserved,
                report.DiskFilesEligible,
                report.DiskFilesSkippedByLegacyFilter,
                report.SolrDocumentsFound,
                match,
                missing,
                stale,
                other,
                missing == 0 && stale == 0 && other == 0 && report.LocalLegacyIdCollisions.Count == 0));
        }
        return result;
    }

    private static PilotStatusCounts BuildCounts(
        IReadOnlyList<PilotEventVersion> events,
        IReadOnlyList<PilotMutationRow> mutations,
        IReadOnlyDictionary<ulong, PilotActionAggregate> actions,
        IReadOnlyDictionary<ulong, PilotPayloadAggregate> payloads,
        IReadOnlyDictionary<string, string> baselines,
        IReadOnlyList<PilotCandidateLiveState> live)
    {
        return new PilotStatusCounts(
            events.Count,
            mutations.Count,
            mutations.Count(x => x.Status == "applied"),
            mutations.Count(x => x.Status == "not_required"),
            mutations.Count(x => x.Status == "planned"),
            mutations.Count(x => x.Status == "processing"),
            mutations.Count(x => x.Status == "failed"),
            actions.Values.Sum(x => x.Total),
            actions.Values.Sum(x => x.Applied),
            payloads.Values.Sum(x => x.Ready),
            payloads.Values.Sum(x => x.Blocked),
            baselines.Values.Count(x => x == "APPROVED"),
            baselines.Values.Count(x => x == "PENDING"),
            live.Count(x => x.Synchronized),
            live.Count(x => !x.Synchronized));
    }

    private static void PrintSummary(PilotMetricsReport report)
    {
        Console.WriteLine("=== Step 14E pilot summary ===");
        Console.WriteLine($"Candidates in active allowlist     : {report.CandidateIds.Count}");
        Console.WriteLine($"Unique audit events                : {report.Counts.AuditEvents}");
        Console.WriteLine($"Mutations                          : {report.Counts.Mutations} (applied={report.Counts.AppliedMutations}, not_required={report.Counts.NotRequiredMutations}, planned={report.Counts.PlannedMutations}, processing={report.Counts.ProcessingMutations}, failed={report.Counts.FailedMutations})");
        Console.WriteLine($"Actions                            : {report.Counts.Actions} (applied={report.Counts.AppliedActions})");
        Console.WriteLine($"Payloads                           : ready={report.Counts.ReadyPayloads}; blocked={report.Counts.BlockedPayloads}");
        Console.WriteLine($"Baselines                          : approved={report.Counts.ApprovedBaselines}; pending={report.Counts.PendingBaselines}");
        Console.WriteLine($"Current live reconciliation        : synchronized={report.Counts.SynchronizedCandidates}; drifted={report.Counts.DriftedCandidates}");
        PrintLatency("event -> MariaDB ingest", report.Latencies["event_to_ingest"]);
        PrintLatency("event -> ready for approval", report.Latencies["event_to_ready_for_approval"]);
        PrintLatency("ready -> verified apply (operator wait included)", report.Latencies["ready_to_verified_apply"]);
        PrintLatency("event -> verified apply", report.Latencies["event_to_verified_apply"]);
        if (report.LegacyComparison is null)
            Console.WriteLine("Legacy scanner comparison          : NOT COMPUTED (no measured legacy reference supplied)");
        else
            Console.WriteLine($"Legacy scanner reference           : {report.LegacyComparison.ReferenceSeconds:F3}s; approximate p50 event-to-ready factor={FormatNumber(report.LegacyComparison.ApproximateP50SpeedupFactor)}x");

        Console.WriteLine("\nCandidate live state:");
        foreach (var candidate in report.CurrentCandidates)
            Console.WriteLine($"  {candidate.CandidateId}: baseline={candidate.BaselineStatus} sync={(candidate.Synchronized ? "MATCH" : "DRIFT")} disk_eligible={candidate.EligibleFiles} solr={candidate.SolrDocuments} match={candidate.MatchCount} missing={candidate.MissingCount} stale={candidate.StaleCount} other={candidate.OtherConflictCount}");
    }

    private static void PrintLatency(string name, PilotLatencyStats stats) =>
        Console.WriteLine($"Latency {name,-41}: n={stats.Count} p50={FormatSeconds(stats.P50Seconds)} p95={FormatSeconds(stats.P95Seconds)} avg={FormatSeconds(stats.AverageSeconds)}");

    private static string BuildCsv(IReadOnlyList<PilotMutationTiming> rows)
    {
        var sb = new StringBuilder();
        sb.AppendLine("mutation_id,candidate_id,worker_version,operation,status,attempt_count,audit_event_id,event_time_utc,ingested_at_utc,mutation_planned_at_utc,first_action_planned_at_utc,payload_ready_at_utc,applied_at_utc,action_count,ready_payload_count,blocked_payload_count,event_to_ingest_seconds,ingest_to_mutation_seconds,event_to_mutation_seconds,mutation_to_payload_seconds,event_to_ready_seconds,ready_to_applied_seconds,event_to_applied_seconds");
        foreach (var x in rows)
        {
            var values = new object?[] { x.MutationId, x.CandidateId, x.WorkerVersion, x.Operation, x.Status, x.AttemptCount, x.AuditEventId,
                Iso(x.EventTimeUtc), Iso(x.IngestedAtUtc), Iso(x.MutationPlannedAtUtc), Iso(x.FirstActionPlannedAtUtc), Iso(x.PayloadReadyAtUtc), Iso(x.AppliedAtUtc),
                x.ActionCount, x.ReadyPayloadCount, x.BlockedPayloadCount, Num(x.EventToIngestSeconds), Num(x.IngestToMutationSeconds), Num(x.EventToMutationSeconds),
                Num(x.MutationToPayloadSeconds), Num(x.EventToReadySeconds), Num(x.ReadyToAppliedSeconds), Num(x.EventToAppliedSeconds) };
            sb.AppendLine(string.Join(",", values.Select(Csv)));
        }
        return sb.ToString();
    }

    private static string BuildMarkdown(PilotMetricsReport report)
    {
        var sb = new StringBuilder();
        sb.AppendLine("# Wazuh-to-Solr event-driven pilot report");
        sb.AppendLine();
        sb.AppendLine($"Generated UTC: `{report.GeneratedAtUtc:O}`");
        sb.AppendLine();
        sb.AppendLine("## Scope and safety boundary");
        sb.AppendLine();
        sb.AppendLine($"- Active pilot allowlist: {string.Join(", ", report.CandidateIds.Select(x => $"`{x}`"))}.");
        sb.AppendLine("- FLOSVR01 remains the filesystem source of truth.");
        sb.AppendLine("- Wazuh events trigger candidate-level reconciliation; a raw delete event is never treated as a direct Solr delete.");
        sb.AppendLine("- Baseline enrollment/review remains required for newly allowlisted candidates.");
        sb.AppendLine("- Solr execution remains explicit and approval-gated; the supervisor never invokes `solr-execute --apply` automatically.");
        sb.AppendLine("- This Step 14E report performs MariaDB reads, FLOSVR01 metadata reads, and Solr GET requests only.");
        sb.AppendLine();
        sb.AppendLine("## Current pilot state");
        sb.AppendLine();
        sb.AppendLine($"- Unique audit events: **{report.Counts.AuditEvents}**");
        sb.AppendLine($"- Mutations: **{report.Counts.Mutations}**; applied **{report.Counts.AppliedMutations}**; not-required **{report.Counts.NotRequiredMutations}**; planned **{report.Counts.PlannedMutations}**; processing **{report.Counts.ProcessingMutations}**; failed **{report.Counts.FailedMutations}**.");
        sb.AppendLine($"- Concrete actions: **{report.Counts.Actions}**; applied **{report.Counts.AppliedActions}**.");
        sb.AppendLine($"- Payloads: ready **{report.Counts.ReadyPayloads}**; blocked **{report.Counts.BlockedPayloads}**.");
        sb.AppendLine($"- Baseline enrollment: approved **{report.Counts.ApprovedBaselines}**; pending review **{report.Counts.PendingBaselines}**.");
        sb.AppendLine($"- Current live reconciliation: synchronized candidates **{report.Counts.SynchronizedCandidates}**; candidates with known drift **{report.Counts.DriftedCandidates}**.");
        sb.AppendLine();
        sb.AppendLine("| Candidate | Baseline | Live state | Eligible disk files | Solr docs | Match | Missing | Stale | Other conflicts |");
        sb.AppendLine("|---|---|---:|---:|---:|---:|---:|---:|---:|");
        foreach (var c in report.CurrentCandidates)
            sb.AppendLine($"| {c.CandidateId} | {c.BaselineStatus} | {(c.Synchronized ? "MATCH" : "DRIFT")} | {c.EligibleFiles} | {c.SolrDocuments} | {c.MatchCount} | {c.MissingCount} | {c.StaleCount} | {c.OtherConflictCount} |");
        sb.AppendLine();
        sb.AppendLine("## Observed latency");
        sb.AppendLine();
        sb.AppendLine("Latency is calculated from persisted UTC timestamps. Small sample sizes should be interpreted descriptively, not as a production SLA.");
        sb.AppendLine();
        sb.AppendLine("| Metric | Samples | Min (s) | P50 (s) | P95 (s) | Average (s) | Max (s) |");
        sb.AppendLine("|---|---:|---:|---:|---:|---:|---:|");
        foreach (var key in new[] { "event_to_ingest", "ingest_to_mutation", "event_to_mutation", "mutation_to_payload_ready", "event_to_ready_for_approval", "ready_to_verified_apply", "event_to_verified_apply" })
        {
            var s = report.Latencies[key];
            sb.AppendLine($"| {MetricLabel(key)} | {s.Count} | {MdNum(s.MinSeconds)} | {MdNum(s.P50Seconds)} | {MdNum(s.P95Seconds)} | {MdNum(s.AverageSeconds)} | {MdNum(s.MaxSeconds)} |");
        }
        sb.AppendLine();
        sb.AppendLine("`event → ready for approval` is the closest observed measure of machine-side event-driven preparation. `ready → verified apply` includes operator review/wait time by design.");
        sb.AppendLine();
        sb.AppendLine("## Legacy continuous-scan comparison");
        sb.AppendLine();
        if (report.LegacyComparison is null)
        {
            sb.AppendLine("A measured legacy continuous-scan timing is **not stored in the pilot database**, so this report does not claim an X-times speedup or a specific seconds-saved figure. Supply a measured legacy reference with `--legacy-scan-seconds` to add a clearly labeled reference-only comparison.");
        }
        else
        {
            var l = report.LegacyComparison;
            sb.AppendLine($"Operator-supplied legacy scan reference: **{l.ReferenceSeconds:F3} seconds**. The observed p50 event-to-ready latency is **{MdNum(l.EventToReadyP50Seconds)} seconds** across **{l.EventToReadySamples}** samples. Approximate reference ratio: **{MdNum(l.ApproximateP50SpeedupFactor)}x**; approximate seconds difference: **{MdNum(l.ApproximateP50SecondsSaved)}**.");
            sb.AppendLine();
            sb.AppendLine($"Caveat: {l.Caveat}");
        }
        sb.AppendLine();
        sb.AppendLine("## Safety and recovery evidence");
        sb.AppendLine();
        sb.AppendLine("- Reviewed payload/source drift is rejected before Solr write; a fresh event creates a new mutation/version.");
        sb.AppendLine("- Processing/failed mutations are operator-blocked by recovery inspection; blind retry is never authorized.");
        sb.AppendLine("- WAZUH-LAB/tunnel recovery and actual WAZUH-LAB DHCP IP-change recovery were exercised during the pilot.");
        sb.AppendLine("- Pending baseline candidates remain blocked from Step 10A/10B/11 until explicit baseline approval.");
        sb.AppendLine("- Candidate-source-unavailable and production Solr GET-outage live disruption tests remain deferred to an approved maintenance window.");
        sb.AppendLine();
        sb.AppendLine("## Pilot conclusion");
        sb.AppendLine();
        sb.AppendLine("The pilot demonstrates an event-triggered, candidate-reconciled, approval-gated path from FLOSVR01 changes to verified Solr state. It avoids treating raw audit deletes as Solr deletes, preserves audit history, detects historical candidate drift, blocks unreviewed candidate baselines, and revalidates live source/Solr state immediately before any approved write.");
        sb.AppendLine();
        sb.AppendLine("A broader rollout should keep the baseline enrollment gate, explicit candidate allowlists, collision audit, recovery inspection, and manual Solr approval until a larger production sample and maintenance-window failure tests are complete.");
        sb.AppendLine();
        sb.AppendLine("## Measurement caveats");
        sb.AppendLine();
        foreach (var caveat in report.Caveats) sb.AppendLine("- " + caveat);
        return sb.ToString();
    }

    private static string MetricLabel(string key) => key switch
    {
        "event_to_ingest" => "Wazuh event → MariaDB ingest",
        "ingest_to_mutation" => "MariaDB ingest → worker mutation plan",
        "event_to_mutation" => "Wazuh event → worker mutation plan",
        "mutation_to_payload_ready" => "Worker mutation plan → payload ready",
        "event_to_ready_for_approval" => "Wazuh event → ready for approval",
        "ready_to_verified_apply" => "Ready for approval → verified apply (operator wait included)",
        "event_to_verified_apply" => "Wazuh event → verified apply",
        _ => key
    };

    private static string ParameterList(string cmdPrefix, int count) =>
        string.Join(",", Enumerable.Range(0, count).Select(i => "@" + cmdPrefix + i.ToString(CultureInfo.InvariantCulture)));

    private static DateTime Utc(DateTime value) => DateTime.SpecifyKind(value, DateTimeKind.Utc);
    private static string? Iso(DateTime? value) => value?.ToUniversalTime().ToString("O", CultureInfo.InvariantCulture);
    private static string? Num(double? value) => value?.ToString("0.######", CultureInfo.InvariantCulture);
    private static string FormatSeconds(double? value) => value is null ? "n/a" : value.Value.ToString("0.###s", CultureInfo.InvariantCulture);
    private static string FormatNumber(double? value) => value is null ? "n/a" : value.Value.ToString("0.###", CultureInfo.InvariantCulture);
    private static string MdNum(double? value) => value is null ? "n/a" : value.Value.ToString("0.###", CultureInfo.InvariantCulture);
    private static string Csv(object? value)
    {
        var text = Convert.ToString(value, CultureInfo.InvariantCulture) ?? string.Empty;
        if (text.IndexOfAny([',', '"', '\r', '\n']) >= 0) text = '"' + text.Replace("\"", "\"\"") + '"';
        return text;
    }
}
