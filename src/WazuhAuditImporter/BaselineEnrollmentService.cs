using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using MySqlConnector;

namespace WazuhAuditImporter;

public static class BaselineEnrollmentService
{
    public static BaselineEnrollmentSnapshot EnsureCaptured(
        ImportSettings settings,
        MySqlConnection connection,
        string workerRoot,
        string? reportDirectory,
        string candidateId)
    {
        settings.ValidateAllowedCandidate(candidateId);
        var existing = BaselineEnrollmentRepository.Read(connection, settings, candidateId);
        if (existing is not null) return existing;
        var capture = CaptureLive(settings, workerRoot, candidateId);
        var stored = BaselineEnrollmentRepository.UpsertPending(connection, settings, capture);
        SaveReport(reportDirectory, capture);
        return stored;
    }

    public static IReadOnlyList<BaselineEnrollmentSnapshot> Capture(
        ImportSettings settings,
        MySqlConnection connection,
        string workerRoot,
        string? reportDirectory,
        string? candidateId)
    {
        settings.ValidateWorker(workerRoot, Path.Combine(Path.GetTempPath(), "wazuh-baseline-validation"));
        IReadOnlyList<string> ids = candidateId is null ? settings.CandidateIds : new[] { candidateId };
        var result = new List<BaselineEnrollmentSnapshot>();
        foreach (var id in ids)
        {
            settings.ValidateAllowedCandidate(id);
            var current = BaselineEnrollmentRepository.Read(connection, settings, id);
            if (current?.Status == BaselineEnrollmentPolicy.Approved)
            {
                Console.WriteLine($"candidate={id} baseline already APPROVED sha256={current.BaselineSha256}; capture not replaced.");
                result.Add(current);
                continue;
            }

            var capture = CaptureLive(settings, workerRoot, id);
            var stored = BaselineEnrollmentRepository.UpsertPending(connection, settings, capture);
            SaveReport(reportDirectory, capture);
            Print(stored);
            result.Add(stored);
        }
        return result;
    }

    public static BaselineEnrollmentSnapshot Approve(
        ImportSettings settings,
        MySqlConnection connection,
        string workerRoot,
        string candidateId,
        string baselineSha256,
        string reviewer,
        string? note,
        bool apply)
    {
        settings.ValidateWorker(workerRoot, Path.Combine(Path.GetTempPath(), "wazuh-baseline-approval-validation"));
        settings.ValidateAllowedCandidate(candidateId);
        var stored = BaselineEnrollmentRepository.Read(connection, settings, candidateId)
            ?? throw new InvalidOperationException($"Candidate {candidateId} has no captured baseline. Run baseline-capture first.");
        if (stored.Status == BaselineEnrollmentPolicy.Approved)
        {
            BaselineEnrollmentPolicy.ValidateApprovalToken(stored.BaselineSha256, baselineSha256);
            Console.WriteLine($"Candidate {candidateId} baseline is already APPROVED with the supplied fingerprint.");
            return stored;
        }

        BaselineEnrollmentPolicy.ValidateApprovalToken(stored.BaselineSha256, baselineSha256);
        var live = CaptureLive(settings, workerRoot, candidateId);
        BaselineEnrollmentPolicy.ValidateApprovalToken(stored.BaselineSha256, live.BaselineSha256);

        Console.WriteLine("Step 14C baseline approval preflight.");
        Console.WriteLine($"Candidate       : {candidateId}");
        Console.WriteLine($"Baseline SHA256 : {stored.BaselineSha256}");
        Console.WriteLine($"Disk files      : {stored.DiskFileCount} ({stored.EligibleFileCount} eligible, {stored.SkippedFileCount} skipped)");
        Console.WriteLine($"Solr documents  : {stored.SolrDocumentCount}");
        Console.WriteLine($"MATCH={stored.MatchCount}; MISSING={stored.MissingCount}; STALE={stored.StaleCount}; OTHER_CONFLICTS={stored.OtherConflictCount}");
        Console.WriteLine("Live baseline fingerprint still matches the reviewed capture: PASS");

        if (!apply)
        {
            Console.WriteLine("\nAPPROVAL PREVIEW ONLY. No baseline status changed and no Solr write occurred.");
            Console.WriteLine($"Rerun with --apply --baseline-sha256 {stored.BaselineSha256} after operator review.");
            return stored;
        }

        var approved = BaselineEnrollmentRepository.Approve(connection, settings, candidateId,
            baselineSha256, reviewer, note);
        Console.WriteLine($"\nSTEP 14C BASELINE APPROVED. candidate={candidateId}; approved_by={approved.ApprovedBy}; sha256={approved.BaselineSha256}");
        Console.WriteLine("This approval only enrolls the candidate for future reconciliation. It does not write to Solr.");
        return approved;
    }

    public static void PrintStatus(ImportSettings settings, MySqlConnection connection)
    {
        Console.WriteLine("=== Step 14C baseline enrollment status ===");
        foreach (var candidateId in settings.CandidateIds)
        {
            var snapshot = BaselineEnrollmentRepository.Read(connection, settings, candidateId);
            if (snapshot is null)
            {
                Console.WriteLine($"candidate={candidateId} status=MISSING (not captured; reconciliation planning is gated)");
                continue;
            }
            Print(snapshot);
        }
        Console.WriteLine("No Solr writes were performed.");
    }

    public static void RequireApproved(
        MySqlConnection connection,
        ImportSettings settings,
        string candidateId,
        string operation)
    {
        var snapshot = BaselineEnrollmentRepository.Read(connection, settings, candidateId);
        if (!BaselineEnrollmentPolicy.IsApproved(snapshot))
        {
            var state = snapshot?.Status ?? "missing";
            var sha = snapshot?.BaselineSha256 ?? "n/a";
            throw new InvalidOperationException(
                $"Step 14C baseline enrollment gate blocked {operation} for candidate {candidateId}: status={state}, baseline_sha256={sha}. Capture/review and explicitly approve the baseline first.");
        }
    }

    public static BaselineEnrollmentCapture CaptureLive(
        ImportSettings settings,
        string workerRoot,
        string candidateId)
    {
        settings.ValidateAllowedCandidate(candidateId);
        settings.ValidateSolrReadOnly();
        var candidateFolder = CandidateWorker.ResolveCandidateFolder(workerRoot, candidateId);
        using var client = new SolrReadOnlyClient(settings);
        var schema = client.ReadSchema();
        if (!schema.UniqueKey.Equals(settings.SolrIdField, StringComparison.Ordinal))
            throw new SolrReadOnlyException($"Expected Solr unique key '{settings.SolrIdField}', schema reports '{schema.UniqueKey}'.");
        var disk = SolrReadOnlyDiscovery.CaptureDiskFiles(workerRoot, candidateFolder, settings.SolrCanonicalRoot);
        var docs = client.QueryCandidate(candidateId);
        var report = SolrReadOnlyDiscovery.Compare(settings, candidateId, workerRoot, candidateFolder, schema, disk, docs);
        var evidence = BuildEvidence(report);
        var (json, sha) = ComputeFingerprint(evidence);
        return new BaselineEnrollmentCapture(evidence, sha, json, DateTime.UtcNow);
    }


    public static (string Json, string Sha256) ComputeFingerprint(BaselineEnrollmentEvidence evidence)
    {
        var json = JsonSerializer.Serialize(evidence, new JsonSerializerOptions { WriteIndented = false });
        var sha = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(json))).ToLowerInvariant();
        return (json, sha);
    }

    public static BaselineEnrollmentEvidence BuildEvidence(SolrReadOnlyReport report)
    {
        var match = report.Comparisons.Count(x => x.Status == "MATCH");
        var missing = report.Comparisons.Count(x => x.Status == "MISSING_IN_SOLR");
        var stale = report.Comparisons.Count(x => x.Status == "STALE_IN_SOLR");
        var other = report.Comparisons.Count(x =>
                        x.Status != "MATCH" &&
                        x.Status != "MISSING_IN_SOLR" &&
                        x.Status != "STALE_IN_SOLR" &&
                        x.Status != "SKIPPED_BY_LEGACY_FILTER")
                    + report.LocalLegacyIdCollisions.Count;
        return new BaselineEnrollmentEvidence(
            report.CandidateId,
            report.AccessibleCandidateFolder,
            report.CanonicalRoot,
            report.DiskFilesObserved,
            report.DiskFilesEligible,
            report.DiskFilesSkippedByLegacyFilter,
            report.SolrDocumentsFound,
            match,
            missing,
            stale,
            other,
            report.Comparisons,
            report.LocalLegacyIdCollisions);
    }

    private static void SaveReport(string? reportDirectory, BaselineEnrollmentCapture capture)
    {
        if (string.IsNullOrWhiteSpace(reportDirectory)) return;
        var full = Path.GetFullPath(reportDirectory);
        Directory.CreateDirectory(full);
        var path = Path.Combine(full,
            $"baseline-{capture.Evidence.CandidateId}-{DateTime.UtcNow:yyyyMMdd-HHmmss}.json");
        File.WriteAllText(path, JsonSerializer.Serialize(new
        {
            capture.Evidence,
            capture.BaselineSha256,
            capture.CapturedAtUtc
        }, new JsonSerializerOptions { WriteIndented = true }));
        Console.WriteLine($"Baseline report saved: {path}");
    }

    private static void Print(BaselineEnrollmentSnapshot snapshot)
    {
        Console.WriteLine(
            $"candidate={snapshot.CandidateId} status={snapshot.Status.ToUpperInvariant()} sha256={snapshot.BaselineSha256} " +
            $"disk={snapshot.DiskFileCount} eligible={snapshot.EligibleFileCount} skipped={snapshot.SkippedFileCount} " +
            $"solr={snapshot.SolrDocumentCount} match={snapshot.MatchCount} missing={snapshot.MissingCount} stale={snapshot.StaleCount} other={snapshot.OtherConflictCount}" +
            (snapshot.ApprovedBy is null ? string.Empty : $" approved_by={snapshot.ApprovedBy}"));
    }
}
