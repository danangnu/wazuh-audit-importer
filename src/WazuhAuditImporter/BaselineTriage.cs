using System.Globalization;
using System.Text;
using System.Text.Json;
using MySqlConnector;

namespace WazuhAuditImporter;

public enum BaselineTriageDisposition
{
    Approved,
    CleanPending,
    SmallDrift,
    ModerateDrift,
    HighDrift,
    BlockingConflict,
    StaleCapture,
    MissingBaseline
}

public sealed record BaselineTriageRow(
    string CandidateId,
    string EnrollmentStatus,
    BaselineTriageDisposition Disposition,
    string? StoredBaselineSha256,
    string? LiveBaselineSha256,
    bool? LiveFingerprintMatchesStored,
    int DiskFileCount,
    int EligibleFileCount,
    int SkippedFileCount,
    int SolrDocumentCount,
    int MatchCount,
    int MissingCount,
    int StaleCount,
    int OtherConflictCount,
    bool EligibleForCleanApproval,
    string Detail)
{
    public string CountsSource => Disposition == BaselineTriageDisposition.Approved
        ? "stored_baseline" : LiveBaselineSha256 is not null ? "live_revalidation" : "unavailable";
    public bool LiveStateChecked => LiveBaselineSha256 is not null;
}

public static class BaselineTriagePolicy
{
    public static bool IsClean(int eligible, int match, int missing, int stale, int other) =>
        missing == 0 && stale == 0 && other == 0 && match == eligible;

    public static BaselineTriageDisposition Classify(
        string enrollmentStatus,
        bool liveFingerprintMatchesStored,
        int eligible,
        int solr,
        int match,
        int missing,
        int stale,
        int other)
    {
        if (string.Equals(enrollmentStatus, BaselineEnrollmentPolicy.Approved, StringComparison.Ordinal))
            return BaselineTriageDisposition.Approved;
        if (!string.Equals(enrollmentStatus, BaselineEnrollmentPolicy.Pending, StringComparison.Ordinal))
            return BaselineTriageDisposition.MissingBaseline;
        if (!liveFingerprintMatchesStored)
            return BaselineTriageDisposition.StaleCapture;
        if (other > 0)
            return BaselineTriageDisposition.BlockingConflict;
        if (IsClean(eligible, match, missing, stale, other))
            return BaselineTriageDisposition.CleanPending;

        var delta = missing + stale + other;
        var solrToEligibleRatio = eligible > 0 ? solr / (double)eligible : solr > 0 ? double.PositiveInfinity : 1d;
        if (stale >= 20 || delta >= 20 || (solr >= 20 && solrToEligibleRatio >= 5d))
            return BaselineTriageDisposition.HighDrift;
        if (delta >= 5 || stale >= 4)
            return BaselineTriageDisposition.ModerateDrift;
        return BaselineTriageDisposition.SmallDrift;
    }

    public static void RequireCleanPending(BaselineEnrollmentSnapshot snapshot)
    {
        if (!string.Equals(snapshot.Status, BaselineEnrollmentPolicy.Pending, StringComparison.Ordinal))
            throw new EventConflictException($"Candidate {snapshot.CandidateId} is not a pending baseline (status={snapshot.Status}).");
        if (!IsClean(snapshot.EligibleFileCount, snapshot.MatchCount, snapshot.MissingCount, snapshot.StaleCount, snapshot.OtherConflictCount))
            throw new EventConflictException(
                $"Step 16 clean-only approval rejected candidate {snapshot.CandidateId}: " +
                $"eligible={snapshot.EligibleFileCount} match={snapshot.MatchCount} missing={snapshot.MissingCount} " +
                $"stale={snapshot.StaleCount} other={snapshot.OtherConflictCount}. Drifted/conflicted baselines require separate operator review.");
    }
}

public static class BaselineTriageService
{
    public static int Run(
        ImportSettings settings,
        MySqlConnection connection,
        string workerRoot,
        string? reportDirectory,
        string? candidateId)
    {
        settings.ValidateWorker(workerRoot, Path.Combine(Path.GetTempPath(), "wazuh-step16-triage-validation"));
        IReadOnlyList<string> ids = candidateId is null ? settings.CandidateIds : new[] { candidateId! };
        var rows = new List<BaselineTriageRow>();

        Console.WriteLine("=== Step 16 baseline triage ===");
        Console.WriteLine("Pending baselines are revalidated against current FLOSVR01 metadata + Solr GET.");
        Console.WriteLine("Approved rows show historical STORED BASELINE counts, not current Solr state. Use recovery-inspect for live verification.");
        Console.WriteLine("This command is read-only: no baseline approvals and no Solr writes.\n");

        foreach (var id in ids)
        {
            settings.ValidateAllowedCandidate(id);
            var stored = BaselineEnrollmentRepository.Read(connection, settings, id);
            if (stored is null)
            {
                rows.Add(new BaselineTriageRow(id, "missing", BaselineTriageDisposition.MissingBaseline,
                    null, null, null, 0, 0, 0, 0, 0, 0, 0, 0, false,
                    "No captured baseline exists. Capture it before review."));
                continue;
            }

            if (stored.Status == BaselineEnrollmentPolicy.Approved)
            {
                rows.Add(new BaselineTriageRow(id, stored.Status, BaselineTriageDisposition.Approved,
                    stored.BaselineSha256, null, null,
                    stored.DiskFileCount, stored.EligibleFileCount, stored.SkippedFileCount,
                    stored.SolrDocumentCount, stored.MatchCount, stored.MissingCount,
                    stored.StaleCount, stored.OtherConflictCount, false,
                    "Already approved; these are historical stored baseline counts. No live state check was performed for this row. Use recovery-inspect for current disk/Solr state."));
                continue;
            }

            var live = BaselineEnrollmentService.CaptureLive(settings, workerRoot, id);
            var e = live.Evidence;
            var same = string.Equals(stored.BaselineSha256, live.BaselineSha256, StringComparison.OrdinalIgnoreCase);
            var disposition = BaselineTriagePolicy.Classify(stored.Status, same,
                e.EligibleFileCount, e.SolrDocumentCount, e.MatchCount, e.MissingCount, e.StaleCount, e.OtherConflictCount);
            var eligibleForApproval = disposition == BaselineTriageDisposition.CleanPending;
            rows.Add(new BaselineTriageRow(id, stored.Status, disposition,
                stored.BaselineSha256, live.BaselineSha256, same,
                e.DiskFileCount, e.EligibleFileCount, e.SkippedFileCount,
                e.SolrDocumentCount, e.MatchCount, e.MissingCount, e.StaleCount,
                e.OtherConflictCount, eligibleForApproval, BuildDetail(disposition)));
        }

        foreach (var row in rows)
        {
            Console.WriteLine(
                $"candidate={row.CandidateId} status={row.EnrollmentStatus.ToUpperInvariant()} triage={row.Disposition.ToString().ToUpperInvariant()} " +
                $"clean_approval={(row.EligibleForCleanApproval ? "YES" : "NO")} sha256={row.StoredBaselineSha256 ?? "n/a"} " +
                $"counts_source={row.CountsSource} live_checked={row.LiveStateChecked.ToString().ToLowerInvariant()} " +
                $"disk={row.DiskFileCount} eligible={row.EligibleFileCount} solr={row.SolrDocumentCount} " +
                $"match={row.MatchCount} missing={row.MissingCount} stale={row.StaleCount} other={row.OtherConflictCount}" +
                (row.LiveFingerprintMatchesStored is null ? string.Empty : $" fingerprint_match={row.LiveFingerprintMatchesStored.Value.ToString().ToLowerInvariant()}"));
        }

        PrintSummary(rows);
        SaveReports(reportDirectory, rows);
        Console.WriteLine("\nSTEP 16 TRIAGE COMPLETE. Read-only: no MariaDB baseline status changes and no Solr writes occurred.");
        return 0;
    }

    public static BaselineEnrollmentSnapshot ApproveClean(
        ImportSettings settings,
        MySqlConnection connection,
        string workerRoot,
        string candidateId,
        string baselineSha256,
        string reviewer,
        string? note,
        bool apply)
    {
        settings.ValidateWorker(workerRoot, Path.Combine(Path.GetTempPath(), "wazuh-step16-clean-approval-validation"));
        settings.ValidateAllowedCandidate(candidateId);
        var stored = BaselineEnrollmentRepository.Read(connection, settings, candidateId)
            ?? throw new InvalidOperationException($"Candidate {candidateId} has no captured baseline. Run baseline-capture first.");

        BaselineEnrollmentPolicy.ValidateApprovalToken(stored.BaselineSha256, baselineSha256);
        if (stored.Status == BaselineEnrollmentPolicy.Approved)
        {
            Console.WriteLine($"Candidate {candidateId} baseline is already APPROVED with the supplied fingerprint.");
            return stored;
        }

        BaselineTriagePolicy.RequireCleanPending(stored);
        var live = BaselineEnrollmentService.CaptureLive(settings, workerRoot, candidateId);
        BaselineEnrollmentPolicy.ValidateApprovalToken(stored.BaselineSha256, live.BaselineSha256);
        if (!BaselineTriagePolicy.IsClean(live.Evidence.EligibleFileCount, live.Evidence.MatchCount,
                live.Evidence.MissingCount, live.Evidence.StaleCount, live.Evidence.OtherConflictCount))
            throw new EventConflictException($"Candidate {candidateId} is no longer clean at live revalidation; approval blocked.");

        Console.WriteLine("Step 16 clean-only baseline approval preflight.");
        Console.WriteLine($"Candidate       : {candidateId}");
        Console.WriteLine($"Baseline SHA256 : {stored.BaselineSha256}");
        Console.WriteLine($"Disk files      : {live.Evidence.DiskFileCount} ({live.Evidence.EligibleFileCount} eligible, {live.Evidence.SkippedFileCount} skipped)");
        Console.WriteLine($"Solr documents  : {live.Evidence.SolrDocumentCount}");
        Console.WriteLine($"MATCH={live.Evidence.MatchCount}; MISSING={live.Evidence.MissingCount}; STALE={live.Evidence.StaleCount}; OTHER_CONFLICTS={live.Evidence.OtherConflictCount}");
        Console.WriteLine("Stored fingerprint = live fingerprint: PASS");
        Console.WriteLine("Clean baseline policy: PASS");

        if (!apply)
        {
            Console.WriteLine("\nAPPROVAL PREVIEW ONLY. No baseline status changed and no Solr write occurred.");
            Console.WriteLine($"Rerun with --apply --baseline-sha256 {stored.BaselineSha256} after operator review.");
            return stored;
        }

        var approved = BaselineEnrollmentRepository.Approve(connection, settings, candidateId,
            baselineSha256, reviewer, note ?? "Step 16 clean baseline enrollment");
        Console.WriteLine($"\nSTEP 16 CLEAN BASELINE APPROVED. candidate={candidateId}; approved_by={approved.ApprovedBy}; sha256={approved.BaselineSha256}");
        Console.WriteLine("This approval only enrolls the candidate for future reconciliation. It does not write to Solr.");
        return approved;
    }

    private static string BuildDetail(BaselineTriageDisposition disposition) => disposition switch
    {
        BaselineTriageDisposition.CleanPending => "Exact live fingerprint is unchanged and eligible disk/Solr state is fully matched. Eligible for individual Step 16 clean-only approval.",
        BaselineTriageDisposition.SmallDrift => "Small live missing/stale set. Do not clean-approve; review reconciliation evidence individually.",
        BaselineTriageDisposition.ModerateDrift => "Moderate live drift. Do not clean-approve; inspect missing/stale actions before any enrollment decision.",
        BaselineTriageDisposition.HighDrift => "High historical/live drift. Keep gated and investigate separately before enrollment.",
        BaselineTriageDisposition.BlockingConflict => "Conflict evidence exists. Keep gated; resolve conflicts before approval.",
        BaselineTriageDisposition.StaleCapture => "Captured baseline fingerprint no longer matches live state. Recapture/review before approval.",
        _ => "No Step 16 clean approval action."
    };

    private static void PrintSummary(IReadOnlyList<BaselineTriageRow> rows)
    {
        Console.WriteLine("\nStep 16 triage summary:");
        foreach (BaselineTriageDisposition value in Enum.GetValues(typeof(BaselineTriageDisposition)))
        {
            var count = rows.Count(x => x.Disposition == value);
            if (count > 0) Console.WriteLine($"  {value,-18}: {count}");
        }
        var cleanIds = rows.Where(x => x.EligibleForCleanApproval).Select(x => x.CandidateId).ToArray();
        Console.WriteLine($"  Clean-approval candidates: {(cleanIds.Length == 0 ? "none" : string.Join(',', cleanIds))}");
    }

    private static void SaveReports(string? reportDirectory, IReadOnlyList<BaselineTriageRow> rows)
    {
        if (string.IsNullOrWhiteSpace(reportDirectory)) return;
        var full = Path.GetFullPath(reportDirectory);
        Directory.CreateDirectory(full);
        var stamp = DateTime.UtcNow.ToString("yyyyMMdd-HHmmss", CultureInfo.InvariantCulture);
        var jsonPath = Path.Combine(full, $"step16-baseline-triage-{stamp}.json");
        var csvPath = Path.Combine(full, $"step16-baseline-triage-{stamp}.csv");
        var mdPath = Path.Combine(full, $"step16-baseline-triage-{stamp}.md");

        File.WriteAllText(jsonPath, JsonSerializer.Serialize(new
        {
            GeneratedAtUtc = DateTime.UtcNow,
            Rows = rows
        }, new JsonSerializerOptions { WriteIndented = true }));

        var csv = new StringBuilder();
        csv.AppendLine("candidate_id,enrollment_status,triage,clean_approval,stored_sha256,live_sha256,fingerprint_match,disk,eligible,skipped,solr,match,missing,stale,other,detail,counts_source,live_checked");
        foreach (var r in rows)
        {
            csv.AppendLine(string.Join(',', new[]
            {
                Csv(r.CandidateId), Csv(r.EnrollmentStatus), Csv(r.Disposition.ToString()), Csv(r.EligibleForCleanApproval ? "yes" : "no"),
                Csv(r.StoredBaselineSha256), Csv(r.LiveBaselineSha256), Csv(r.LiveFingerprintMatchesStored?.ToString().ToLowerInvariant()),
                r.DiskFileCount.ToString(CultureInfo.InvariantCulture), r.EligibleFileCount.ToString(CultureInfo.InvariantCulture),
                r.SkippedFileCount.ToString(CultureInfo.InvariantCulture), r.SolrDocumentCount.ToString(CultureInfo.InvariantCulture),
                r.MatchCount.ToString(CultureInfo.InvariantCulture), r.MissingCount.ToString(CultureInfo.InvariantCulture),
                r.StaleCount.ToString(CultureInfo.InvariantCulture), r.OtherConflictCount.ToString(CultureInfo.InvariantCulture), Csv(r.Detail),
                Csv(r.CountsSource), Csv(r.LiveStateChecked.ToString().ToLowerInvariant())
            }));
        }
        File.WriteAllText(csvPath, csv.ToString());

        var md = new StringBuilder();
        md.AppendLine("# Step 16 Baseline Triage");
        md.AppendLine();
        md.AppendLine("Read-only triage of the controlled 25-candidate cohort. Only `CLEANPENDING` rows are eligible for the Step 16 clean-only approval command; no drifted candidate is auto-approved.");
        md.AppendLine();
        md.AppendLine("Approved rows contain historical stored baseline counts and have not been checked live. Use `recovery-inspect` for current Solr state.");
        md.AppendLine();
        md.AppendLine("| Candidate | Enrollment | Triage | Counts source | Live checked | Clean approval | Match | Missing | Stale | Other |");
        md.AppendLine("|---|---|---|---|---|---:|---:|---:|---:|---:|");
        foreach (var r in rows)
            md.AppendLine($"| {r.CandidateId} | {r.EnrollmentStatus} | {r.Disposition} | {r.CountsSource} | {r.LiveStateChecked} | {(r.EligibleForCleanApproval ? "YES" : "NO")} | {r.MatchCount} | {r.MissingCount} | {r.StaleCount} | {r.OtherConflictCount} |");
        md.AppendLine();
        md.AppendLine("High-drift, conflict, stale-capture and other drifted baselines remain operator-gated. This report does not authorize Solr writes.");
        File.WriteAllText(mdPath, md.ToString());

        Console.WriteLine($"Triage JSON saved : {jsonPath}");
        Console.WriteLine($"Triage CSV saved  : {csvPath}");
        Console.WriteLine($"Triage report     : {mdPath}");
    }

    private static string Csv(string? value)
    {
        value ??= string.Empty;
        return "\"" + value.Replace("\"", "\"\"") + "\"";
    }
}
