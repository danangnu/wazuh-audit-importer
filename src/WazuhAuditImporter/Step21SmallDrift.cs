using System.Globalization;
using System.Text;
using System.Text.Json;
using MySqlConnector;

namespace WazuhAuditImporter;

public sealed record Step21SmallDriftReview(
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
    bool EligibleForStep21Approval,
    IReadOnlyList<SolrPathComparison> Missing,
    IReadOnlyList<SolrPathComparison> Stale,
    string Detail)
{
    public int ProposedIndexCount => Missing.Count;
    public int ProposedDeleteCount => Stale.Count;
    public IReadOnlyList<string> MissingExtractors => Missing.Select(x => Step21SmallDriftPolicy.ExpectedExtractor(x.CanonicalPath)).ToArray();
}

public static class Step21SmallDriftPolicy
{
    // Exact reviewed cohort and shape, not a general permission for all SmallDrift.
    public static IReadOnlyCollection<string> ExpansionBatch { get; } =
        Array.AsReadOnly(new[] { "1180003", "1180006", "1180016", "1180017" });

    public static bool IsExpansionCandidate(string candidateId) => ExpansionBatch.Contains(candidateId, StringComparer.Ordinal);

    public static void RequireExpansionCandidate(string candidateId)
    {
        if (!IsExpansionCandidate(candidateId))
            throw new EventConflictException($"Step 21 is limited to {string.Join(',', ExpansionBatch)}; candidate {candidateId} is outside this controlled batch.");
    }

    public static bool IsExpectedPattern(string candidateId, string enrollmentStatus, bool fingerprintMatch,
        int eligible, int solr, int match, int missing, int stale, int other)
    {
        var expectedMissing = candidateId switch
        {
            "1180003" or "1180006" => 2,
            "1180016" or "1180017" => 1,
            _ => 0
        };
        return expectedMissing > 0 && enrollmentStatus == BaselineEnrollmentPolicy.Pending && fingerprintMatch &&
               eligible == expectedMissing && solr == 2 && match == 0 && missing == expectedMissing &&
               stale == 2 && other == 0;
    }

    public static string? GetBlockReason(BaselineEnrollmentSnapshot stored, BaselineEnrollmentCapture live)
    {
        var e = live.Evidence;
        if (!IsExpansionCandidate(stored.CandidateId)) return "Candidate is outside the Step 21 batch.";
        if (e.CandidateId != stored.CandidateId) return "Stored and live candidate identities differ.";
        var same = string.Equals(stored.BaselineSha256, live.BaselineSha256, StringComparison.OrdinalIgnoreCase);
        if (!IsExpectedPattern(stored.CandidateId, stored.Status, same, e.EligibleFileCount,
                e.SolrDocumentCount, e.MatchCount, e.MissingCount, e.StaleCount, e.OtherConflictCount))
            return "Step 21 requires an unchanged pending fingerprint and the exact candidate pattern: " +
                   "1180003/1180006: eligible=2, solr=2, match=0, missing=2, stale=2, other=0; " +
                   "1180016/1180017: eligible=1, solr=2, match=0, missing=1, stale=2, other=0.";

        if (e.LocalLegacyIdCollisions.Count != 0 || e.Comparisons.Any(x =>
                x.Status is not ("MISSING_IN_SOLR" or "STALE_IN_SOLR" or "SKIPPED_BY_LEGACY_FILTER")))
            return "Collision, matched, unknown, or conflicting comparison evidence blocks this Step 21 pattern.";
        var missing = e.Comparisons.Where(x => x.Status == "MISSING_IN_SOLR").ToArray();
        var stale = e.Comparisons.Where(x => x.Status == "STALE_IN_SOLR").ToArray();
        if (missing.Length != e.MissingCount || stale.Length != e.StaleCount || e.SkippedFileCount < 0 ||
            e.Comparisons.Count(x => x.Status == "SKIPPED_BY_LEGACY_FILTER") != e.SkippedFileCount ||
            e.DiskFileCount != e.EligibleFileCount + e.SkippedFileCount)
            return "Summary counts disagree with the exact file/document evidence.";

        var actions = missing.Concat(stale).ToArray();
        if (actions.Any(x => !IsCandidatePath(e.CanonicalRoot, e.CandidateId, x.CanonicalPath)))
            return "Every proposed index/delete path must be inside this candidate's canonical folder, without traversal.";
        if (actions.Select(x => SolrPathMapper.NormalizeForComparison(x.CanonicalPath)).Distinct(StringComparer.Ordinal).Count() != actions.Length)
            return "Duplicate or overlapping action paths require separate conflict review.";
        if (missing.Any(x => string.IsNullOrWhiteSpace(x.ExpectedLegacyId) ||
                !string.Equals(x.ExpectedLegacyId, SolrPathMapper.GenerateLegacySolrId(x.CanonicalPath), StringComparison.Ordinal) ||
                !string.IsNullOrEmpty(x.SolrId)) ||
            stale.Any(x => string.IsNullOrWhiteSpace(x.SolrId)))
            return "Every missing file needs its exact generated legacy ID; every stale document needs its actual Solr ID.";
        var ids = missing.Select(x => x.ExpectedLegacyId!).Concat(stale.Select(x => x.SolrId!)).ToArray();
        if (ids.Distinct(StringComparer.OrdinalIgnoreCase).Count() != ids.Length)
            return "Duplicate or overlapping index/delete IDs require separate collision review.";
        var unsupported = missing.Where(x => !Step20MissingOnlyPolicy.IsSupportedLegacyExtractorPath(x.CanonicalPath)).ToArray();
        if (unsupported.Length != 0)
            return "Missing files have no validated legacy payload extractor: " +
                   string.Join(", ", unsupported.Select(x => x.CanonicalPath)) +
                   ". Supported: .txt, .html, .htm, .doc, .docx, .docm, .rtf. Keep baseline gated.";
        return null;
    }

    private static bool IsCandidatePath(string root, string candidateId, string path)
    {
        if (string.IsNullOrWhiteSpace(root) || string.IsNullOrWhiteSpace(path)) return false;
        var prefix = SolrPathMapper.NormalizeWindowsPath(root) + "\\" + candidateId + "\\";
        var normalized = SolrPathMapper.NormalizeWindowsPath(path);
        if (!normalized.StartsWith(prefix, StringComparison.OrdinalIgnoreCase)) return false;
        var relative = normalized[prefix.Length..];
        return relative.Length > 0 && !relative.Contains(':') &&
               !relative.Split('\\').Any(x => string.IsNullOrWhiteSpace(x) || x is "." or ".." || x != x.TrimEnd(' ', '.'));
    }

    public static void RequireReviewedPattern(BaselineEnrollmentSnapshot stored, BaselineEnrollmentCapture live)
    {
        var reason = GetBlockReason(stored, live);
        if (reason is not null) throw new EventConflictException($"Step 21 rejected candidate {stored.CandidateId}: {reason}");
    }

    public static string ExpectedExtractor(string path) => Path.GetExtension(path).ToLowerInvariant() switch
    {
        ".txt" or ".html" or ".htm" => "legacy_readalltext",
        ".doc" or ".docx" or ".docm" or ".rtf" => "legacy_aspose_words_24_9",
        _ => "unsupported"
    };

    public static void RequireAcknowledgement(bool acknowledgeSmallDrift, bool apply)
    {
        if (apply && !acknowledgeSmallDrift)
            throw new FormatException("Step 21 --apply requires --ack-small-drift after reviewing EVERY proposed index and BOTH stale-document deletions.");
    }
}

public static class Step21SmallDriftService
{
    public static int Review(
        ImportSettings settings,
        MySqlConnection connection,
        string workerRoot,
        string? reportDirectory,
        string? candidateId)
    {
        settings.ValidateWorker(workerRoot, Path.Combine(Path.GetTempPath(), "wazuh-step21-small-drift-review-validation"));
        var ids = candidateId is null
            ? Step21SmallDriftPolicy.ExpansionBatch.OrderBy(x => x, StringComparer.Ordinal).ToArray()
            : new[] { candidateId };
        var rows = new List<Step21SmallDriftReview>();

        Console.WriteLine("=== Step 21 controlled SmallDrift review ===");
        Console.WriteLine("Controlled expansion batch: 1180003,1180006,1180016,1180017 only.");
        Console.WriteLine("FLOSVR01 metadata + Solr GET are revalidated. This command does not approve baselines and never writes Solr.\n");

        foreach (var id in ids)
        {
            settings.ValidateAllowedCandidate(id);
            Step21SmallDriftPolicy.RequireExpansionCandidate(id);
            rows.Add(BuildReview(settings, connection, workerRoot, id));
        }

        foreach (var row in rows)
        {
            PrintReview(row);
            Console.WriteLine();
        }
        SaveReports(reportDirectory, rows);
        Console.WriteLine("STEP 21 SMALLDRIFT REVIEW COMPLETE. Read/report only; no baseline approval and no Solr write occurred.");
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
        Step21SmallDriftPolicy.RequireAcknowledgement(acknowledgeSmallDrift, apply);
        settings.ValidateWorker(workerRoot, Path.Combine(Path.GetTempPath(), "wazuh-step21-small-drift-approval-validation"));
        settings.ValidateAllowedCandidate(candidateId);
        Step21SmallDriftPolicy.RequireExpansionCandidate(candidateId);

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
        Step21SmallDriftPolicy.RequireReviewedPattern(stored, live);
        var review = BuildReview(stored, live);

        Console.WriteLine("Step 21 bounded SmallDrift approval preflight.");
        PrintReview(review);
        Console.WriteLine("Approval meaning: enroll this exact reviewed drift state for controlled reconciliation. Approval itself does NOT repair Solr.");

        if (!apply)
        {
            Console.WriteLine("\nAPPROVAL PREVIEW ONLY. No baseline status changed and no Solr write occurred.");
            Console.WriteLine("After operator review, rerun with --ack-small-drift --apply using the same baseline SHA-256.");
            return stored;
        }


        var defaultNote = $"Step 21 reviewed bounded SmallDrift enrollment; missing={live.Evidence.MissingCount}; stale={live.Evidence.StaleCount}; baseline_sha256={stored.BaselineSha256}";
        var approved = BaselineEnrollmentRepository.Approve(connection, settings, candidateId,
            baselineSha256, reviewer, note ?? defaultNote);
        Console.WriteLine($"\nSTEP 21 SMALLDRIFT BASELINE APPROVED. candidate={candidateId}; approved_by={approved.ApprovedBy}; sha256={approved.BaselineSha256}");
        Console.WriteLine("No Solr write occurred. Historical drift is still present until a separately reviewed reconciliation mutation is explicitly applied.");
        return approved;
    }

    private static Step21SmallDriftReview BuildReview(
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

    public static Step21SmallDriftReview BuildReview(
        BaselineEnrollmentSnapshot stored,
        BaselineEnrollmentCapture live)
    {
        var e = live.Evidence;
        var same = string.Equals(stored.BaselineSha256, live.BaselineSha256, StringComparison.OrdinalIgnoreCase);
        var reason = Step21SmallDriftPolicy.GetBlockReason(stored, live);
        var eligible = reason is null;
        var missing = e.Comparisons.Where(x => x.Status == "MISSING_IN_SOLR").ToArray();
        var stale = e.Comparisons.Where(x => x.Status == "STALE_IN_SOLR").ToArray();
        var detail = eligible
            ? $"Eligible after exact operator review of ALL {missing.Length} index actions and {stale.Length} delete actions. No file pairing is inferred."
            : reason!;
        return new Step21SmallDriftReview(stored.CandidateId, stored.BaselineSha256, same,
            e.DiskFileCount, e.EligibleFileCount, e.SolrDocumentCount, e.MatchCount, e.MissingCount,
            e.StaleCount, e.OtherConflictCount, eligible, missing, stale, detail);
    }

    private static void PrintReview(Step21SmallDriftReview row)
    {
        Console.WriteLine($"candidate={row.CandidateId} sha256={row.BaselineSha256} fingerprint_match={row.FingerprintMatch.ToString().ToLowerInvariant()} " +
                          $"disk={row.DiskFileCount} eligible={row.EligibleFileCount} solr={row.SolrDocumentCount} match={row.MatchCount} " +
                          $"missing={row.MissingCount} stale={row.StaleCount} other={row.OtherConflictCount} step21_approval={(row.EligibleForStep21Approval ? "YES" : "NO")}");
        Console.WriteLine($"  Proposed actions: index={row.ProposedIndexCount}; delete={row.ProposedDeleteCount}. Review every deletion separately.");
        foreach (var item in row.Missing)
            Console.WriteLine($"  MISSING current file : {item.CanonicalPath}\n    expected_solr_id    : {item.ExpectedLegacyId ?? "n/a"}\n    expected_extractor : {Step21SmallDriftPolicy.ExpectedExtractor(item.CanonicalPath)}");
        foreach (var item in row.Stale)
            Console.WriteLine($"  STALE Solr document : {item.CanonicalPath}\n    current_solr_id     : {item.SolrId ?? "n/a"}");
        Console.WriteLine($"  {row.Detail}");
    }

    private static void SaveReports(string? reportDirectory, IReadOnlyList<Step21SmallDriftReview> rows)
    {
        if (string.IsNullOrWhiteSpace(reportDirectory)) return;
        var full = Path.GetFullPath(reportDirectory);
        Directory.CreateDirectory(full);
        var stamp = DateTime.UtcNow.ToString("yyyyMMdd-HHmmss", CultureInfo.InvariantCulture);
        var jsonPath = Path.Combine(full, $"step21-small-drift-review-{stamp}.json");
        var csvPath = Path.Combine(full, $"step21-small-drift-review-{stamp}.csv");
        var mdPath = Path.Combine(full, $"step21-small-drift-review-{stamp}.md");

        File.WriteAllText(jsonPath, JsonSerializer.Serialize(new { GeneratedAtUtc = DateTime.UtcNow, Rows = rows },
            new JsonSerializerOptions { WriteIndented = true }));

        var csv = new StringBuilder();
        csv.AppendLine("candidate_id,baseline_sha256,fingerprint_match,eligible,solr,match,missing,stale,other,step21_approval,index_count,delete_count,missing_paths,expected_ids,extractors,stale_paths,delete_ids,detail");
        foreach (var r in rows)
            csv.AppendLine(string.Join(',', new[]
            {
                Csv(r.CandidateId), Csv(r.BaselineSha256), Csv(r.FingerprintMatch.ToString().ToLowerInvariant()),
                r.EligibleFileCount.ToString(CultureInfo.InvariantCulture), r.SolrDocumentCount.ToString(CultureInfo.InvariantCulture),
                r.MatchCount.ToString(CultureInfo.InvariantCulture), r.MissingCount.ToString(CultureInfo.InvariantCulture),
                r.StaleCount.ToString(CultureInfo.InvariantCulture), r.OtherConflictCount.ToString(CultureInfo.InvariantCulture),
                Csv(r.EligibleForStep21Approval ? "yes" : "no"),
                r.ProposedIndexCount.ToString(CultureInfo.InvariantCulture), r.ProposedDeleteCount.ToString(CultureInfo.InvariantCulture),
                Csv(string.Join("\n", r.Missing.Select(x => x.CanonicalPath))),
                Csv(string.Join("\n", r.Missing.Select(x => x.ExpectedLegacyId))),
                Csv(string.Join("\n", r.MissingExtractors)),
                Csv(string.Join("\n", r.Stale.Select(x => x.CanonicalPath))),
                Csv(string.Join("\n", r.Stale.Select(x => x.SolrId))), Csv(r.Detail)
            }));
        File.WriteAllText(csvPath, csv.ToString());

        var md = new StringBuilder();
        md.AppendLine("# Step 21 SmallDrift Review");
        md.AppendLine();
        md.AppendLine("Controlled expansion batch: `1180003`, `1180006`, `1180016`, `1180017`. Review is read-only. Approval does not itself change Solr.");
        foreach (var r in rows)
        {
            md.AppendLine();
            md.AppendLine($"## Candidate {r.CandidateId}");
            md.AppendLine($"- Baseline SHA-256: `{r.BaselineSha256}`");
            md.AppendLine($"- Fingerprint unchanged: `{r.FingerprintMatch}`");
            md.AppendLine($"- Live state: match={r.MatchCount}, missing={r.MissingCount}, stale={r.StaleCount}, other={r.OtherConflictCount}");
            md.AppendLine($"- Step 21 approval eligible: `{r.EligibleForStep21Approval}`");
            md.AppendLine($"- Detail: {r.Detail}");
            md.AppendLine($"- Proposed actions: index={r.ProposedIndexCount}, delete={r.ProposedDeleteCount}. Review every delete ID individually.");
            foreach (var x in r.Missing) md.AppendLine($"- MISSING current path: `{x.CanonicalPath}` (expected id `{x.ExpectedLegacyId ?? "n/a"}`, extractor `{Step21SmallDriftPolicy.ExpectedExtractor(x.CanonicalPath)}`)");
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
