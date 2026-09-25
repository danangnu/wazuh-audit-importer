using System.Globalization;
using System.Text;
using System.Text.Json;
using MySqlConnector;

namespace WazuhAuditImporter;

public sealed record Step20MissingOnlyReview(
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
    bool EligibleForStep20Approval,
    IReadOnlyList<SolrPathComparison> Missing,
    IReadOnlyList<SolrPathComparison> Stale,
    string Detail);

public static class Step20MissingOnlyPolicy
{
    private static readonly HashSet<string> ExpansionCandidates = new(StringComparer.Ordinal)
    {
        "1180019"
    };

    public static IReadOnlyCollection<string> ExpansionBatch => ExpansionCandidates;

    public static bool IsExpansionCandidate(string candidateId) => ExpansionCandidates.Contains(candidateId);

    public static void RequireExpansionCandidate(string candidateId)
    {
        if (!IsExpansionCandidate(candidateId))
            throw new EventConflictException(
                $"Step 20 controlled missing-only enrollment is limited to candidates {string.Join(',', ExpansionCandidates.OrderBy(x => x, StringComparer.Ordinal))}; candidate {candidateId} is outside this controlled batch.");
    }

    public static bool IsSingleMissingOnly(
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
        if (!fingerprintMatch || eligible <= 0 || solr < 0 || other != 0) return false;
        if (missing != 1 || stale != 0 || match != eligible - 1 || solr != match) return false;
        return BaselineTriagePolicy.Classify(enrollmentStatus, fingerprintMatch, eligible, solr, match, missing, stale, other)
               == BaselineTriageDisposition.SmallDrift;
    }

    public static void RequireSingleMissingOnly(
        BaselineEnrollmentSnapshot stored,
        BaselineEnrollmentCapture live)
    {
        RequireExpansionCandidate(stored.CandidateId);
        var e = live.Evidence;
        var same = string.Equals(stored.BaselineSha256, live.BaselineSha256, StringComparison.OrdinalIgnoreCase);
        if (!IsSingleMissingOnly(stored.Status, same, e.EligibleFileCount, e.SolrDocumentCount,
                e.MatchCount, e.MissingCount, e.StaleCount, e.OtherConflictCount))
        {
            throw new EventConflictException(
                $"Step 20 missing-only policy rejected candidate {stored.CandidateId}: " +
                $"status={stored.Status} fingerprint_match={same.ToString().ToLowerInvariant()} eligible={e.EligibleFileCount} " +
                $"solr={e.SolrDocumentCount} match={e.MatchCount} missing={e.MissingCount} stale={e.StaleCount} other={e.OtherConflictCount}. " +
                "The controlled expansion requires exactly one missing current document, zero stale Solr documents, and no other conflicts.");
        }
        if (!HasExactMissingEvidence(e))
            throw new EventConflictException(MissingEvidenceBlockDetail(e));
    }

    public static bool HasExactMissingEvidence(BaselineEnrollmentEvidence evidence)
    {
        var missing = evidence.Comparisons.Where(x => x.Status == "MISSING_IN_SOLR").ToArray();
        return missing.Length == 1 && !string.IsNullOrWhiteSpace(missing[0].CanonicalPath) &&
               !string.IsNullOrWhiteSpace(missing[0].ExpectedLegacyId) &&
               IsSupportedLegacyExtractorPath(missing[0].CanonicalPath) &&
               !evidence.Comparisons.Any(x => x.Status == "STALE_IN_SOLR");
    }

    public static bool IsSupportedLegacyExtractorPath(string path) =>
        Path.GetExtension(path).ToLowerInvariant() is ".txt" or ".html" or ".htm" or ".doc" or ".docx" or ".docm" or ".rtf";

    public static string UnsupportedExtractorDetail(BaselineEnrollmentEvidence evidence)
    {
        var missing = evidence.Comparisons.SingleOrDefault(x => x.Status == "MISSING_IN_SOLR");
        var extension = missing is null ? "unknown" : Path.GetExtension(missing.CanonicalPath).ToLowerInvariant();
        return $"Step 20 cannot approve this missing-only state: '{extension}' has no validated legacy payload extractor. Supported extensions are .txt, .html, .htm, .doc, .docx, .docm, and .rtf.";
    }

    public static string MissingEvidenceBlockDetail(BaselineEnrollmentEvidence evidence)
    {
        var missing = evidence.Comparisons.Where(x => x.Status == "MISSING_IN_SOLR").ToArray();
        if (missing.Length != 1 || string.IsNullOrWhiteSpace(missing[0].CanonicalPath) ||
            string.IsNullOrWhiteSpace(missing[0].ExpectedLegacyId) ||
            evidence.Comparisons.Any(x => x.Status == "STALE_IN_SOLR"))
            return "Step 20 requires exactly one identifiable missing current file, no stale Solr documents, and no other conflicts.";
        return IsSupportedLegacyExtractorPath(missing[0].CanonicalPath)
            ? "Step 20 missing-file evidence failed validation; keep the baseline gated."
            : UnsupportedExtractorDetail(evidence);
    }
}

public static class Step20MissingOnlyService
{
    public static int Review(
        ImportSettings settings,
        MySqlConnection connection,
        string workerRoot,
        string? reportDirectory,
        string? candidateId)
    {
        settings.ValidateWorker(workerRoot, Path.Combine(Path.GetTempPath(), "wazuh-step20-missing-only-review-validation"));
        var ids = candidateId is null
            ? Step20MissingOnlyPolicy.ExpansionBatch.OrderBy(x => x, StringComparer.Ordinal).ToArray()
            : new[] { candidateId };
        var rows = new List<Step20MissingOnlyReview>();

        Console.WriteLine("=== Step 20 controlled missing-only review ===");
        Console.WriteLine("Controlled candidate: 1180019 only.");
        Console.WriteLine("FLOSVR01 metadata + Solr GET are revalidated. This command does not approve baselines and never writes Solr.\n");

        foreach (var id in ids)
        {
            settings.ValidateAllowedCandidate(id);
            Step20MissingOnlyPolicy.RequireExpansionCandidate(id);
            rows.Add(BuildReview(settings, connection, workerRoot, id));
        }

        foreach (var row in rows)
        {
            PrintReview(row);
            Console.WriteLine();
        }
        SaveReports(reportDirectory, rows);
        Console.WriteLine("STEP 20 MISSING-ONLY REVIEW COMPLETE. Read/report only; no baseline approval and no Solr write occurred.");
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
        bool acknowledgeMissingOnly,
        bool apply)
    {
        settings.ValidateWorker(workerRoot, Path.Combine(Path.GetTempPath(), "wazuh-step20-missing-only-approval-validation"));
        settings.ValidateAllowedCandidate(candidateId);
        Step20MissingOnlyPolicy.RequireExpansionCandidate(candidateId);

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
        Step20MissingOnlyPolicy.RequireSingleMissingOnly(stored, live);
        var review = BuildReview(stored, live);

        Console.WriteLine("Step 20 missing-only approval preflight.");
        PrintReview(review);
        Console.WriteLine("Approval meaning: enroll this exact reviewed drift state for controlled reconciliation. Approval itself does NOT repair Solr.");

        if (!apply)
        {
            Console.WriteLine("\nAPPROVAL PREVIEW ONLY. No baseline status changed and no Solr write occurred.");
            Console.WriteLine("After operator review, rerun with --ack-missing-only --apply using the same baseline SHA-256.");
            return stored;
        }

        if (!acknowledgeMissingOnly)
            throw new FormatException("Step 20 --apply requires --ack-missing-only to confirm the one-missing/zero-stale evidence was explicitly reviewed.");

        var defaultNote = $"Step 20 reviewed missing-only enrollment; missing={live.Evidence.MissingCount}; stale={live.Evidence.StaleCount}; baseline_sha256={stored.BaselineSha256}";
        var approved = BaselineEnrollmentRepository.Approve(connection, settings, candidateId,
            baselineSha256, reviewer, note ?? defaultNote);
        Console.WriteLine($"\nSTEP 20 MISSING-ONLY BASELINE APPROVED. candidate={candidateId}; approved_by={approved.ApprovedBy}; sha256={approved.BaselineSha256}");
        Console.WriteLine("No Solr write occurred. Historical drift is still present until a separately reviewed reconciliation mutation is explicitly applied.");
        return approved;
    }

    private static Step20MissingOnlyReview BuildReview(
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

    public static Step20MissingOnlyReview BuildReview(
        BaselineEnrollmentSnapshot stored,
        BaselineEnrollmentCapture live)
    {
        var e = live.Evidence;
        var same = string.Equals(stored.BaselineSha256, live.BaselineSha256, StringComparison.OrdinalIgnoreCase);
        var eligible = Step20MissingOnlyPolicy.IsExpansionCandidate(stored.CandidateId) &&
                       Step20MissingOnlyPolicy.IsSingleMissingOnly(stored.Status, same,
                           e.EligibleFileCount, e.SolrDocumentCount, e.MatchCount, e.MissingCount, e.StaleCount, e.OtherConflictCount) &&
                       Step20MissingOnlyPolicy.HasExactMissingEvidence(e);
        var missing = e.Comparisons.Where(x => x.Status == "MISSING_IN_SOLR").ToArray();
        var stale = e.Comparisons.Where(x => x.Status == "STALE_IN_SOLR").ToArray();
        var detail = eligible
            ? "Eligible for the controlled Step 20 missing-only approval after exact operator review."
            : Step20MissingOnlyPolicy.IsSingleMissingOnly(stored.Status, same,
                  e.EligibleFileCount, e.SolrDocumentCount, e.MatchCount, e.MissingCount, e.StaleCount, e.OtherConflictCount) &&
              !Step20MissingOnlyPolicy.HasExactMissingEvidence(e)
                ? Step20MissingOnlyPolicy.MissingEvidenceBlockDetail(e)
                : "Not eligible for the controlled Step 20 approval; keep baseline gated.";
        return new Step20MissingOnlyReview(stored.CandidateId, stored.BaselineSha256, same,
            e.DiskFileCount, e.EligibleFileCount, e.SolrDocumentCount, e.MatchCount, e.MissingCount,
            e.StaleCount, e.OtherConflictCount, eligible, missing, stale, detail);
    }

    private static void PrintReview(Step20MissingOnlyReview row)
    {
        Console.WriteLine($"candidate={row.CandidateId} sha256={row.BaselineSha256} fingerprint_match={row.FingerprintMatch.ToString().ToLowerInvariant()} " +
                          $"disk={row.DiskFileCount} eligible={row.EligibleFileCount} solr={row.SolrDocumentCount} match={row.MatchCount} " +
                          $"missing={row.MissingCount} stale={row.StaleCount} other={row.OtherConflictCount} step20_approval={(row.EligibleForStep20Approval ? "YES" : "NO")}");
        foreach (var item in row.Missing)
            Console.WriteLine($"  MISSING current file : {item.CanonicalPath}\n    expected_solr_id    : {item.ExpectedLegacyId ?? "n/a"}");
        foreach (var item in row.Stale)
            Console.WriteLine($"  STALE Solr document : {item.CanonicalPath}\n    current_solr_id     : {item.SolrId ?? "n/a"}");
        Console.WriteLine($"  {row.Detail}");
    }

    private static void SaveReports(string? reportDirectory, IReadOnlyList<Step20MissingOnlyReview> rows)
    {
        if (string.IsNullOrWhiteSpace(reportDirectory)) return;
        var full = Path.GetFullPath(reportDirectory);
        Directory.CreateDirectory(full);
        var stamp = DateTime.UtcNow.ToString("yyyyMMdd-HHmmss", CultureInfo.InvariantCulture);
        var jsonPath = Path.Combine(full, $"step20-missing-only-review-{stamp}.json");
        var csvPath = Path.Combine(full, $"step20-missing-only-review-{stamp}.csv");
        var mdPath = Path.Combine(full, $"step20-missing-only-review-{stamp}.md");

        File.WriteAllText(jsonPath, JsonSerializer.Serialize(new { GeneratedAtUtc = DateTime.UtcNow, Rows = rows },
            new JsonSerializerOptions { WriteIndented = true }));

        var csv = new StringBuilder();
        csv.AppendLine("candidate_id,baseline_sha256,fingerprint_match,eligible,solr,match,missing,stale,other,step20_approval");
        foreach (var r in rows)
            csv.AppendLine(string.Join(',', new[]
            {
                Csv(r.CandidateId), Csv(r.BaselineSha256), Csv(r.FingerprintMatch.ToString().ToLowerInvariant()),
                r.EligibleFileCount.ToString(CultureInfo.InvariantCulture), r.SolrDocumentCount.ToString(CultureInfo.InvariantCulture),
                r.MatchCount.ToString(CultureInfo.InvariantCulture), r.MissingCount.ToString(CultureInfo.InvariantCulture),
                r.StaleCount.ToString(CultureInfo.InvariantCulture), r.OtherConflictCount.ToString(CultureInfo.InvariantCulture),
                Csv(r.EligibleForStep20Approval ? "yes" : "no")
            }));
        File.WriteAllText(csvPath, csv.ToString());

        var md = new StringBuilder();
        md.AppendLine("# Step 20 Missing-only Review");
        md.AppendLine();
        md.AppendLine("Controlled candidate: `1180019`. Review is read-only. Approval does not itself change Solr.");
        foreach (var r in rows)
        {
            md.AppendLine();
            md.AppendLine($"## Candidate {r.CandidateId}");
            md.AppendLine($"- Baseline SHA-256: `{r.BaselineSha256}`");
            md.AppendLine($"- Fingerprint unchanged: `{r.FingerprintMatch}`");
            md.AppendLine($"- Live state: match={r.MatchCount}, missing={r.MissingCount}, stale={r.StaleCount}, other={r.OtherConflictCount}");
            md.AppendLine($"- Step 20 approval eligible: `{r.EligibleForStep20Approval}`");
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
