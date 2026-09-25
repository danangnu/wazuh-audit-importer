using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using Aspose.Words;

namespace WazuhAuditImporter;

public sealed record LegacyExtractionResult(
    string Status,
    string Extractor,
    string? Content,
    string? SourceFileSha256,
    string? ContentSha256,
    ulong? ContentCharCount,
    ulong? SourceFileLength,
    DateTime? SourceFileLastWriteUtc,
    string? BlockReason);

public static class LegacyContentExtractor
{
    private static readonly Regex LegacyNonContent = new("[^a-zA-Z0-9_.]+", RegexOptions.Compiled);
    private const string LegacyAsposeEvaluationCopyBanner = "Created with an evaluation copy of Aspose.Words. To remove all limitations, you can use Free Temporary License https://products.aspose.com/words/temporary-license/";
    private static readonly Regex LegacyAsposeEvaluationOnlyBanner = new(
        "Evaluation Only\\. Created with Aspose\\.Words.*?Aspose Pty Ltd\\.", RegexOptions.Singleline | RegexOptions.Compiled);

    public static LegacyExtractionResult ExtractForAction(SolrStoredAction action, string workerRoot)
    {
        if (action.ActionType != "index_document")
            throw new SolrPayloadException("Content extraction is only valid for index_document actions.");
        if (string.IsNullOrWhiteSpace(action.SourceFilePath))
            return Block("none", "source_file_path_missing", null, null);

        var source = Path.GetFullPath(action.SourceFilePath);
        var allowedRoot = Path.GetFullPath(Path.Combine(workerRoot, action.CandidateId));
        var prefix = allowedRoot.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar) + Path.DirectorySeparatorChar;
        if (!source.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
            throw new SolrPayloadException("Index source path is outside the approved FLOSVR01 candidate folder.");
        if (!File.Exists(source))
            return Block("none", "source_file_missing", null, null);

        var info = new FileInfo(source);
        var actualLength = checked((ulong)info.Length);
        var actualWrite = info.LastWriteTimeUtc;
        if (action.SourceFileLength is ulong expectedLength && expectedLength != actualLength)
            return Block("none", "source_changed_since_action_plan", actualLength, actualWrite);
        if (action.SourceFileLastWriteUtc is DateTime expectedWrite &&
            Math.Abs((actualWrite - expectedWrite).TotalMilliseconds) > 1.0)
            return Block("none", "source_changed_since_action_plan", actualLength, actualWrite);

        var bytes = File.ReadAllBytes(source);
        var sourceHash = HexSha256(bytes);
        var ext = Path.GetExtension(source).ToLowerInvariant();
        string? content;
        string extractor;

        switch (ext)
        {
            case ".txt":
            case ".html":
            case ".htm":
                // Legacy SolrIndexing.documentProcessing uses
                // My.Computer.FileSystem.ReadAllText(filePath) for these types.
                content = File.ReadAllText(source);
                extractor = "legacy_readalltext";
                break;
            case ".doc":
            case ".docx":
            case ".docm":
            case ".rtf":
                extractor = "legacy_aspose_words_24_9";
                try
                {
                    var document = new Document(source);
                    content = document.ToString(SaveFormat.Text);
                    content = RemoveLegacyAsposeEvaluationBanners(content);
                }
                catch (Exception)
                {
                    // The legacy function returns Nothing on extraction errors. Step 10B
                    // records a blocked payload so it can never be mistaken for valid text.
                    return Block(extractor, "legacy_aspose_extraction_failed", actualLength, actualWrite, sourceHash);
                }
                break;
            case ".pdf":
                // Supplied legacy app uses PDFBox 1.8.2 PDFTextStripper.
                return Block("legacy_pdfbox_1_8_2_not_ported", "legacy_extractor_not_ported", actualLength, actualWrite, sourceHash);
            default:
                return Block("none", "unsupported_extension", actualLength, actualWrite, sourceHash);
        }

        // Legacy doIndexing removes everything except ASCII letters/digits/underscore/dot
        // and refuses to index when nothing remains.
        if (LegacyNonContent.Replace(content, string.Empty).Length == 0)
            return Block(extractor, "empty_document_legacy_behavior", actualLength, actualWrite, sourceHash,
                HexSha256(Encoding.UTF8.GetBytes(content)), checked((ulong)content.Length));

        return new LegacyExtractionResult(
            "ready", extractor, content, sourceHash,
            HexSha256(Encoding.UTF8.GetBytes(content)), checked((ulong)content.Length),
            actualLength, actualWrite, null);
    }

    private static LegacyExtractionResult Block(string extractor, string reason, ulong? length, DateTime? write,
        string? sourceHash = null, string? contentHash = null, ulong? chars = null) =>
        new("blocked", extractor, null, sourceHash, contentHash, chars, length, write, reason);

    internal static string RemoveLegacyAsposeEvaluationBanners(string content)
    {
        var result = content.Replace(LegacyAsposeEvaluationCopyBanner, string.Empty, StringComparison.Ordinal);
        return LegacyAsposeEvaluationOnlyBanner.Replace(result, string.Empty);
    }

    public static string HexSha256(byte[] bytes) => Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();
}
