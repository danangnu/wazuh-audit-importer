using System.Globalization;
using System.Text;
using System.Text.Json;
using MySqlConnector;

namespace WazuhAuditImporter;

public sealed record Step18SmallDriftReview(
    string CandidateId,
    string BaselineSha256,
    bool FingerprintMatch,
    int DiskFileCount,
    int EligibleFileCount,
    int SolrDocumentCount,
    int MatchCount,
    int MissingCount,
    int StaleCount,
    int OtherConflictCount,
    bool EligibleForStep18Approval,
    IReadOnlyList<SolrPathComparison> Missing,
    IReadOnlyList<SolrPathComparison> Stale,
    string Detail);

public static class Step18SmallDriftPolicy
{
    private static readonly HashSet<string> ExpansionCandidates = new(StringComparer.Ordinal)
    {
        "1180011", "1180012", "1180014"
    };

    public static IReadOnlyCollection<string> ExpansionBatch => ExpansionCandidates;

    public static bool IsExpansionCandidate(string candidateId) => ExpansionCandidates.Contains(candidateId);

    public static void RequireExpansionCandidate(string candidateId)
    {
        if (!IsExpansionCandidate(candidateId))
            throw new EventConflictException(
                $"Step 18 controlled SmallDrift expansion is limited to candidates {string.Join(',', ExpansionCandidates.OrderBy(x => x, StringComparer.Ordinal))}; candidate {candidateId} is outside this controlled batch.");
    }

    public static bool IsSimpleOneForOneSmallDrift(
        string enrollmentStatus,
        bool fingerprintMatch,
        int eligible,
        int solr,
        int match,
        int missing,
        int stale,
        int other)
    {
        if (!string.Equals(enrollmentStatus, BaselineEnrollmentPolicy.Pending, StringComparison.Ordinal)) return false;
        if (!fingerprintMatch || eligible <= 0 || solr <= 0 || other != 0) return false;
        if (missing != 1 || stale != 1) return false;
        return BaselineTriagePolicy.Classify(enrollmentStatus, fingerprintMatch, eligible, solr, match, missing, stale, other)
               == BaselineTriageDisposition.SmallDrift;
    }

    public static void RequireSimpleOneForOne(
        BaselineEnrollmentSnapshot stored,
        BaselineEnrollmentCapture live)
    {
        RequireExpansionCandidate(stored.CandidateId);
        var e = live.Evidence;
        var same = string.Equals(stored.BaselineSha256, live.BaselineSha256, StringComparison.OrdinalIgnoreCase);
        if (!IsSimpleOneForOneSmallDrift(stored.Status, same, e.EligibleFileCount, e.SolrDocumentCount,
                e.MatchCount, e.MissingCount, e.StaleCount, e.OtherConflictCount))
        {
            throw new EventConflictException(
                $"Step 18 simple SmallDrift policy rejected candidate {stored.CandidateId}: " +
                $"status={stored.Status} fingerprint_match={same.ToString().ToLowerInvariant()} eligible={e.EligibleFileCount} " +
                $"solr={e.SolrDocumentCount} match={e.MatchCount} missing={e.MissingCount} stale={e.StaleCount} other={e.OtherConflictCount}. " +
                "The controlled expansion requires exactly one missing current document and one stale Solr document, with no other conflicts.");
        }
    }
}

public static class Step18SmallDriftService
{
    public static int Review(
        ImportSettings settings,
        MySqlConnection connection,
        string workerRoot,
        string? reportDirectory,
        string? candidateId)
    {
        settings.ValidateWorker(workerRoot, Path.Combine(Path.GetTempPath(), "wazuh-step18-small-drift-review-validation"));
        var ids = candidateId is null
            ? Step18SmallDriftPolicy.ExpansionBatch.OrderBy(x => x, StringComparer.Ordinal).ToArray()
            : new[] { candidateId };
        var rows = new List<Step18SmallDriftReview>();

        Console.WriteLine("=== Step 18 controlled SmallDrift review ===");
        Console.WriteLine("Controlled expansion batch: 1180011,1180012,1180014 only.");
        Console.WriteLine("FLOSVR01 metadata + Solr GET are revalidated. This command does not approve baselines and never writes Solr.\n");

        foreach (var id in ids)
        {
            settings.ValidateAllowedCandidate(id);
            Step18SmallDriftPolicy.RequireExpansionCandidate(id);
            rows.Add(BuildReview(settings, connection, workerRoot, id));
        }

        foreach (var row in rows)
        {
            PrintReview(row);
            Console.WriteLine();
        }
        SaveReports(reportDirectory, rows);
        Console.WriteLine("STEP 18 SMALLDRIFT REVIEW COMPLETE. Read/report only; no baseline approval and no Solr write occurred.");
        return 0;
    }

    public static BaselineEnrollmentSnapshot Approve(
        ImportSettings settings,
        MySqlConnection connection,
        string workerRoot,
        string candidateId,
        string baselineSha256,
        string reviewer,
        string? note,
        bool acknowledgeSmallDrift,
        bool apply)
    {
        settings.ValidateWorker(workerRoot, Path.Combine(Path.GetTempPath(), "wazuh-step18-small-drift-approval-validation"));
        settings.ValidateAllowedCandidate(candidateId);
        Step18SmallDriftPolicy.RequireExpansionCandidate(candidateId);

        var stored = BaselineEnrollmentRepository.Read(connection, settings, candidateId)
            ?? throw new InvalidOperationException($"Candidate {candidateId} has no captured baseline. Run baseline-capture first.");
        BaselineEnrollmentPolicy.ValidateApprovalToken(stored.BaselineSha256, baselineSha256);
        if (stored.Status == BaselineEnrollmentPolicy.Approved)
        {
            Console.WriteLine($"Candidate {candidateId} baseline is already APPROVED with the supplied fingerprint.");
            return stored;
        }

        var live = BaselineEnrollmentService.CaptureLive(settings, workerRoot, candidateId);
        BaselineEnrollmentPolicy.ValidateApprovalToken(stored.BaselineSha256, live.BaselineSha256);
        Step18SmallDriftPolicy.RequireSimpleOneForOne(stored, live);
        var review = BuildReview(stored, live);

        Console.WriteLine("Step 18 simple SmallDrift approval preflight.");
        PrintReview(review);
        Console.WriteLine("Approval meaning: enroll this exact reviewed drift state for controlled reconciliation. Approval itself does NOT repair Solr.");

        if (!apply)
        {
            Console.WriteLine("\nAPPROVAL PREVIEW ONLY. No baseline status changed and no Solr write occurred.");
            Console.WriteLine("After operator review, rerun with --ack-small-drift --apply using the same baseline SHA-256.");
            return stored;
        }

        if (!acknowledgeSmallDrift)
            throw new FormatException("Step 18 --apply requires --ack-small-drift to confirm the one-missing/one-stale evidence was explicitly reviewed.");

        var defaultNote = $"Step 18 reviewed simple SmallDrift enrollment; missing={live.Evidence.MissingCount}; stale={live.Evidence.StaleCount}; baseline_sha256={stored.BaselineSha256}";
        var approved = BaselineEnrollmentRepository.Approve(connection, settings, candidateId,
            baselineSha256, reviewer, note ?? defaultNote);
        Console.WriteLine($"\nSTEP 18 SMALLDRIFT BASELINE APPROVED. candidate={candidateId}; approved_by={approved.ApprovedBy}; sha256={approved.BaselineSha256}");
        Console.WriteLine("No Solr write occurred. Historical drift is still present until a separately reviewed reconciliation mutation is explicitly applied.");
        return approved;
    }

    private static Step18SmallDriftReview BuildReview(
        ImportSettings settings,
        MySqlConnection connection,
        string workerRoot,
        string candidateId)
    {
        var stored = BaselineEnrollmentRepository.Read(connection, settings, candidateId)
            ?? throw new InvalidOperationException($"Candidate {candidateId} has no captured baseline. Run baseline-capture first.");
        var live = BaselineEnrollmentService.CaptureLive(settings, workerRoot, candidateId);
        return BuildReview(stored, live);
    }

    public static Step18SmallDriftReview BuildReview(
        BaselineEnrollmentSnapshot stored,
        BaselineEnrollmentCapture live)
    {
        var e = live.Evidence;
        var same = string.Equals(stored.BaselineSha256, live.BaselineSha256, StringComparison.OrdinalIgnoreCase);
        var eligible = Step18SmallDriftPolicy.IsExpansionCandidate(stored.CandidateId) &&
                       Step18SmallDriftPolicy.IsSimpleOneForOneSmallDrift(stored.Status, same,
                           e.EligibleFileCount, e.SolrDocumentCount, e.MatchCount, e.MissingCount, e.StaleCount, e.OtherConflictCount);
        var missing = e.Comparisons.Where(x => x.Status == "MISSING_IN_SOLR").ToArray();
        var stale = e.Comparisons.Where(x => x.Status == "STALE_IN_SOLR").ToArray();
        var detail = eligible
            ? "Eligible for the controlled Step 18 one-for-one SmallDrift approval after exact operator review."
            : "Not eligible for the controlled Step 18 approval; keep baseline gated.";
        return new Step18SmallDriftReview(stored.CandidateId, stored.BaselineSha256, same,
            e.DiskFileCount, e.EligibleFileCount, e.SolrDocumentCount, e.MatchCount, e.MissingCount,
            e.StaleCount, e.OtherConflictCount, eligible, missing, stale, detail);
    }

    private static void PrintReview(Step18SmallDriftReview row)
    {
        Console.WriteLine($"candidate={row.CandidateId} sha256={row.BaselineSha256} fingerprint_match={row.FingerprintMatch.ToString().ToLowerInvariant()} " +
                          $"disk={row.DiskFileCount} eligible={row.EligibleFileCount} solr={row.SolrDocumentCount} match={row.MatchCount} " +
                          $"missing={row.MissingCount} stale={row.StaleCount} other={row.OtherConflictCount} step18_approval={(row.EligibleForStep18Approval ? "YES" : "NO")}");
        foreach (var item in row.Missing)
            Console.WriteLine($"  MISSING current file : {item.CanonicalPath}\n    expected_solr_id    : {item.ExpectedLegacyId ?? "n/a"}");
        foreach (var item in row.Stale)
            Console.WriteLine($"  STALE Solr document : {item.CanonicalPath}\n    current_solr_id     : {item.SolrId ?? "n/a"}");
        Console.WriteLine($"  {row.Detail}");
    }

    private static void SaveReports(string? reportDirectory, IReadOnlyList<Step18SmallDriftReview> rows)
    {
        if (string.IsNullOrWhiteSpace(reportDirectory)) return;
        var full = Path.GetFullPath(reportDirectory);
        Directory.CreateDirectory(full);
        var stamp = DateTime.UtcNow.ToString("yyyyMMdd-HHmmss", CultureInfo.InvariantCulture);
        var jsonPath = Path.Combine(full, $"step18-small-drift-review-{stamp}.json");
        var csvPath = Path.Combine(full, $"step18-small-drift-review-{stamp}.csv");
        var mdPath = Path.Combine(full, $"step18-small-drift-review-{stamp}.md");

        File.WriteAllText(jsonPath, JsonSerializer.Serialize(new { GeneratedAtUtc = DateTime.UtcNow, Rows = rows },
            new JsonSerializerOptions { WriteIndented = true }));

        var csv = new StringBuilder();
        csv.AppendLine("candidate_id,baseline_sha256,fingerprint_match,eligible,solr,match,missing,stale,other,step18_approval");
        foreach (var r in rows)
            csv.AppendLine(string.Join(',', new[]
            {
                Csv(r.CandidateId), Csv(r.BaselineSha256), Csv(r.FingerprintMatch.ToString().ToLowerInvariant()),
                r.EligibleFileCount.ToString(CultureInfo.InvariantCulture), r.SolrDocumentCount.ToString(CultureInfo.InvariantCulture),
                r.MatchCount.ToString(CultureInfo.InvariantCulture), r.MissingCount.ToString(CultureInfo.InvariantCulture),
                r.StaleCount.ToString(CultureInfo.InvariantCulture), r.OtherConflictCount.ToString(CultureInfo.InvariantCulture),
                Csv(r.EligibleForStep18Approval ? "yes" : "no")
            }));
        File.WriteAllText(csvPath, csv.ToString());

        var md = new StringBuilder();
        md.AppendLine("# Step 18 SmallDrift Review");
        md.AppendLine();
        md.AppendLine("Controlled expansion batch: `1180011`, `1180012`, `1180014`. Review is read-only. Approval does not itself change Solr.");
        foreach (var r in rows)
        {
            md.AppendLine();
            md.AppendLine($"## Candidate {r.CandidateId}");
            md.AppendLine($"- Baseline SHA-256: `{r.BaselineSha256}`");
            md.AppendLine($"- Fingerprint unchanged: `{r.FingerprintMatch}`");
            md.AppendLine($"- Live state: match={r.MatchCount}, missing={r.MissingCount}, stale={r.StaleCount}, other={r.OtherConflictCount}");
            md.AppendLine($"- Step 18 approval eligible: `{r.EligibleForStep18Approval}`");
            foreach (var x in r.Missing) md.AppendLine($"- MISSING current path: `{x.CanonicalPath}` (expected id `{x.ExpectedLegacyId ?? "n/a"}`)");
            foreach (var x in r.Stale) md.AppendLine($"- STALE Solr path: `{x.CanonicalPath}` (Solr id `{x.SolrId ?? "n/a"}`)");
        }
        md.AppendLine();
        md.AppendLine("No action in this report authorizes a Solr write. Any later reconciliation mutation still requires the normal Step 10/11 review and explicit `--apply`.");
        File.WriteAllText(mdPath, md.ToString());

        Console.WriteLine($"Review JSON saved : {jsonPath}");
        Console.WriteLine($"Review CSV saved  : {csvPath}");
        Console.WriteLine($"Review report     : {mdPath}");
    }

    private static string Csv(string? value)
    {
        value ??= string.Empty;
        return "\"" + value.Replace("\"", "\"\"") + "\"";
    }
}
