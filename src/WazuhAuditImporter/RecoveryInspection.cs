using System.Text.Json;
using MySqlConnector;

namespace WazuhAuditImporter;

public enum RecoveryDisposition
{
    NoMutation,
    HealthyTerminal,
    PlannedRequiresNormalPreflight,
    UncertainProcessing,
    UncertainFailed,
    Inconsistent
}

public sealed record RecoveryActionCounts(
    int Total,
    int Planned,
    int Processing,
    int Applied,
    int Failed,
    int Skipped);

public sealed record RecoveryMutationState(
    ulong MutationId,
    string CandidateId,
    ulong WorkerVersion,
    string Operation,
    string Status,
    int AttemptCount,
    string? LastError,
    RecoveryActionCounts Actions);

public sealed record RecoveryCandidateInspection(
    string CandidateId,
    RecoveryMutationState? Mutation,
    RecoveryDisposition Disposition,
    bool BlindRetryAllowed,
    string Detail,
    BaselineEnrollmentEvidence? LiveEvidence,
    string? LiveEvidenceError,
    DateTime CheckedAtUtc);

public static class RecoveryPolicy
{
    public static RecoveryDisposition Classify(string mutationStatus, string operation, RecoveryActionCounts actions)
    {
        if (mutationStatus is "processing") return RecoveryDisposition.UncertainProcessing;
        if (mutationStatus is "failed") return RecoveryDisposition.UncertainFailed;

        if (mutationStatus is "applied")
            return actions.Total == actions.Applied
                ? RecoveryDisposition.HealthyTerminal
                : RecoveryDisposition.Inconsistent;

        if (mutationStatus is "skipped" or "not_required" || operation == "none")
            return actions.Processing == 0 && actions.Failed == 0
                ? RecoveryDisposition.HealthyTerminal
                : RecoveryDisposition.Inconsistent;

        if (mutationStatus == "planned" && operation == "reindex_candidate")
            return actions.Processing == 0 && actions.Applied == 0 && actions.Failed == 0 && actions.Skipped == 0
                ? RecoveryDisposition.PlannedRequiresNormalPreflight
                : RecoveryDisposition.Inconsistent;

        return RecoveryDisposition.Inconsistent;
    }

    public static bool BlindRetryAllowed(RecoveryDisposition disposition) => false;

    public static string Detail(RecoveryDisposition disposition) => disposition switch
    {
        RecoveryDisposition.NoMutation => "No mutation exists for this candidate.",
        RecoveryDisposition.HealthyTerminal => "Latest mutation is terminal and internally consistent.",
        RecoveryDisposition.PlannedRequiresNormalPreflight => "Mutation remains planned. Use the normal Step 10/11 gates; this recovery command never retries or applies it.",
        RecoveryDisposition.UncertainProcessing => "Mutation is still processing. Solr state is uncertain; DO NOT blind-retry. Inspect current disk/Solr state and execution logs first.",
        RecoveryDisposition.UncertainFailed => "Mutation is failed. A request may have reached Solr before failure; DO NOT blind-retry. Inspect current disk/Solr state and execution logs first.",
        _ => "Mutation/action state is inconsistent. Operator investigation is required before any Solr execution."
    };
}

public static class RecoveryInspection
{
    public static int Run(
        ImportSettings settings,
        MySqlConnection connection,
        string workerRoot,
        string? reportDirectory,
        string? candidateId,
        ulong? mutationId)
    {
        settings.ValidateWorker(workerRoot, Path.Combine(Path.GetTempPath(), "wazuh-step14d-recovery-validation"));
        if (candidateId is not null) settings.ValidateAllowedCandidate(candidateId);

        IReadOnlyList<string> candidates;
        if (mutationId is not null)
        {
            var scopedCandidate = ReadMutationCandidate(connection, settings, mutationId.Value);
            if (candidateId is not null && !string.Equals(candidateId, scopedCandidate, StringComparison.Ordinal))
                throw new FormatException("--candidate-id does not match the selected --mutation-id.");
            candidates = new[] { scopedCandidate };
        }
        else
        {
            candidates = candidateId is null ? settings.CandidateIds : new[] { candidateId };
        }

        var results = new List<RecoveryCandidateInspection>();
        foreach (var id in candidates)
        {
            var mutation = mutationId is not null
                ? ReadMutation(connection, settings, mutationId.Value)
                : ReadLatestMutation(connection, settings, id);

            var disposition = mutation is null
                ? RecoveryDisposition.NoMutation
                : RecoveryPolicy.Classify(mutation.Status, mutation.Operation, mutation.Actions);

            BaselineEnrollmentEvidence? live = null;
            string? liveError = null;
            try
            {
                live = BaselineEnrollmentService.CaptureLive(settings, workerRoot, id).Evidence;
            }
            catch (Exception ex) when (ex is DirectoryNotFoundException or UnauthorizedAccessException or IOException or SolrReadOnlyException)
            {
                liveError = ex.Message;
            }

            var result = new RecoveryCandidateInspection(
                id,
                mutation,
                disposition,
                RecoveryPolicy.BlindRetryAllowed(disposition),
                RecoveryPolicy.Detail(disposition),
                live,
                liveError,
                DateTime.UtcNow);
            results.Add(result);
            Print(result);
        }

        SaveReport(reportDirectory, results);
        Console.WriteLine("\nSTEP 14D RECOVERY INSPECTION COMPLETE. Read-only: no MariaDB rows or Solr documents were changed.");
        Console.WriteLine("Blind retry is never authorized by this command. processing/failed mutations remain operator-blocked.");
        return results.Any(x => x.Disposition is RecoveryDisposition.UncertainProcessing or RecoveryDisposition.UncertainFailed or RecoveryDisposition.Inconsistent)
            ? 12
            : 0;
    }

    private static string ReadMutationCandidate(MySqlConnection connection, ImportSettings settings, ulong mutationId)
    {
        using var cmd = new MySqlCommand("""
            SELECT candidate_id
            FROM wazuh_audit_poc.solr_mutation_queue
            WHERE mutation_id=@mutation AND source_instance=@source AND agent_id=@agent
            LIMIT 1;
            """, connection);
        cmd.Parameters.AddWithValue("@mutation", mutationId);
        cmd.Parameters.AddWithValue("@source", settings.SourceInstance);
        cmd.Parameters.AddWithValue("@agent", settings.AgentId);
        var value = cmd.ExecuteScalar();
        if (value is null) throw new InvalidOperationException($"Mutation {mutationId} was not found in the configured pilot scope.");
        var candidate = Convert.ToString(value, System.Globalization.CultureInfo.InvariantCulture) ?? string.Empty;
        settings.ValidateAllowedCandidate(candidate);
        return candidate;
    }

    private static RecoveryMutationState? ReadLatestMutation(MySqlConnection connection, ImportSettings settings, string candidateId)
    {
        using var cmd = new MySqlCommand("""
            SELECT mutation_id
            FROM wazuh_audit_poc.solr_mutation_queue
            WHERE source_instance=@source AND agent_id=@agent AND candidate_id=@candidate
            ORDER BY worker_version DESC, mutation_id DESC
            LIMIT 1;
            """, connection);
        cmd.Parameters.AddWithValue("@source", settings.SourceInstance);
        cmd.Parameters.AddWithValue("@agent", settings.AgentId);
        cmd.Parameters.AddWithValue("@candidate", candidateId);
        var value = cmd.ExecuteScalar();
        if (value is null) return null;
        return ReadMutation(connection, settings, Convert.ToUInt64(value, System.Globalization.CultureInfo.InvariantCulture));
    }

    private static RecoveryMutationState ReadMutation(MySqlConnection connection, ImportSettings settings, ulong mutationId)
    {
        ulong id;
        string candidate;
        ulong workerVersion;
        string operation;
        string status;
        int attempts;
        string? lastError;
        using (var cmd = new MySqlCommand("""
            SELECT mutation_id, candidate_id, worker_version, operation, status, attempt_count, last_error
            FROM wazuh_audit_poc.solr_mutation_queue
            WHERE mutation_id=@mutation AND source_instance=@source AND agent_id=@agent
            LIMIT 1;
            """, connection))
        {
            cmd.Parameters.AddWithValue("@mutation", mutationId);
            cmd.Parameters.AddWithValue("@source", settings.SourceInstance);
            cmd.Parameters.AddWithValue("@agent", settings.AgentId);
            using var reader = cmd.ExecuteReader();
            if (!reader.Read()) throw new InvalidOperationException($"Mutation {mutationId} was not found in the configured pilot scope.");
            id = reader.GetUInt64(0);
            candidate = reader.GetString(1);
            workerVersion = reader.GetUInt64(2);
            operation = reader.GetString(3);
            status = reader.GetString(4);
            attempts = Convert.ToInt32(reader.GetValue(5), System.Globalization.CultureInfo.InvariantCulture);
            lastError = reader.IsDBNull(6) ? null : reader.GetString(6);
        }
        settings.ValidateAllowedCandidate(candidate);

        var counts = new Dictionary<string, int>(StringComparer.Ordinal)
        {
            ["planned"] = 0, ["processing"] = 0, ["applied"] = 0, ["failed"] = 0, ["skipped"] = 0
        };
        var total = 0;
        using (var actions = new MySqlCommand("""
            SELECT status, COUNT(*)
            FROM wazuh_audit_poc.solr_mutation_action
            WHERE mutation_id=@mutation
            GROUP BY status;
            """, connection))
        {
            actions.Parameters.AddWithValue("@mutation", mutationId);
            using var reader = actions.ExecuteReader();
            while (reader.Read())
            {
                var key = reader.GetString(0);
                var count = Convert.ToInt32(reader.GetValue(1), System.Globalization.CultureInfo.InvariantCulture);
                total += count;
                if (counts.ContainsKey(key)) counts[key] = count;
            }
        }

        return new RecoveryMutationState(
            id, candidate, workerVersion, operation, status, attempts, lastError,
            new RecoveryActionCounts(total, counts["planned"], counts["processing"], counts["applied"], counts["failed"], counts["skipped"]));
    }

    private static void Print(RecoveryCandidateInspection result)
    {
        Console.WriteLine("\n=== Step 14D recovery inspection ===");
        Console.WriteLine($"Candidate        : {result.CandidateId}");
        if (result.Mutation is null)
        {
            Console.WriteLine("Mutation         : none");
        }
        else
        {
            var m = result.Mutation;
            Console.WriteLine($"Mutation         : {m.MutationId} worker_version={m.WorkerVersion} operation={m.Operation} status={m.Status} attempts={m.AttemptCount}");
            Console.WriteLine($"Action states    : total={m.Actions.Total} planned={m.Actions.Planned} processing={m.Actions.Processing} applied={m.Actions.Applied} failed={m.Actions.Failed} skipped={m.Actions.Skipped}");
            if (!string.IsNullOrWhiteSpace(m.LastError)) Console.WriteLine($"Last error       : {m.LastError}");
        }
        Console.WriteLine($"Recovery class   : {result.Disposition}");
        Console.WriteLine($"Blind retry      : {result.BlindRetryAllowed}");
        Console.WriteLine($"Detail           : {result.Detail}");
        if (result.LiveEvidence is not null)
        {
            var e = result.LiveEvidence;
            Console.WriteLine($"Live disk/Solr   : disk={e.DiskFileCount} eligible={e.EligibleFileCount} solr={e.SolrDocumentCount} match={e.MatchCount} missing={e.MissingCount} stale={e.StaleCount} other={e.OtherConflictCount}");
        }
        else if (!string.IsNullOrWhiteSpace(result.LiveEvidenceError))
        {
            Console.WriteLine($"Live verification: UNAVAILABLE ({result.LiveEvidenceError})");
        }
    }

    private static void SaveReport(string? reportDirectory, IReadOnlyList<RecoveryCandidateInspection> results)
    {
        if (string.IsNullOrWhiteSpace(reportDirectory)) return;
        var full = Path.GetFullPath(reportDirectory);
        Directory.CreateDirectory(full);
        var path = Path.Combine(full, $"step14d-recovery-{DateTime.UtcNow:yyyyMMdd-HHmmss}.json");
        File.WriteAllText(path, JsonSerializer.Serialize(results, new JsonSerializerOptions { WriteIndented = true }));
        Console.WriteLine($"Recovery report saved: {path}");
    }
}
