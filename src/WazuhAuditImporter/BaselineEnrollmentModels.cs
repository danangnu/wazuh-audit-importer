namespace WazuhAuditImporter;

public sealed record BaselineEnrollmentSnapshot(
    ulong EnrollmentId,
    string CandidateId,
    string Status,
    string BaselineSha256,
    int DiskFileCount,
    int EligibleFileCount,
    int SkippedFileCount,
    int SolrDocumentCount,
    int MatchCount,
    int MissingCount,
    int StaleCount,
    int OtherConflictCount,
    DateTime CapturedAtUtc,
    DateTime? ApprovedAtUtc,
    string? ApprovedBy,
    string? ApprovalNote);

public sealed record BaselineEnrollmentEvidence(
    string CandidateId,
    string AccessibleCandidateFolder,
    string CanonicalRoot,
    int DiskFileCount,
    int EligibleFileCount,
    int SkippedFileCount,
    int SolrDocumentCount,
    int MatchCount,
    int MissingCount,
    int StaleCount,
    int OtherConflictCount,
    IReadOnlyList<SolrPathComparison> Comparisons,
    IReadOnlyList<LegacyIdCollision> LocalLegacyIdCollisions);

public sealed record BaselineEnrollmentCapture(
    BaselineEnrollmentEvidence Evidence,
    string BaselineSha256,
    string BaselineJson,
    DateTime CapturedAtUtc);

public static class BaselineEnrollmentPolicy
{
    public const string Pending = "pending";
    public const string Approved = "approved";

    public static bool IsApproved(BaselineEnrollmentSnapshot? snapshot) =>
        snapshot is not null && snapshot.Status == Approved;

    public static void ValidateApprovalToken(string expected, string supplied)
    {
        if (string.IsNullOrWhiteSpace(supplied) || supplied.Length != 64 ||
            supplied.Any(c => !Uri.IsHexDigit(c)))
            throw new FormatException("--baseline-sha256 must be exactly 64 hexadecimal characters.");
        if (!string.Equals(expected, supplied, StringComparison.OrdinalIgnoreCase))
            throw new EventConflictException("Baseline approval token does not match the currently captured baseline. Refresh/review the baseline before approval.");
    }
}
