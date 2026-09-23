using System.Text.RegularExpressions;

namespace WazuhAuditImporter;

public static class SolrPathMapper
{
    public static string MapRelativeToCanonicalRoot(string canonicalRoot, string relativePath)
    {
        if (string.IsNullOrWhiteSpace(canonicalRoot))
            throw new ArgumentException("Canonical Solr root is required.", nameof(canonicalRoot));
        if (string.IsNullOrWhiteSpace(relativePath))
            throw new ArgumentException("Relative path is required.", nameof(relativePath));

        var root = NormalizeWindowsPath(canonicalRoot).TrimEnd('\\');
        var relative = NormalizeWindowsPath(relativePath).TrimStart('\\');
        if (relative.Split('\\').Any(p => p is "" or "." or ".."))
            throw new InvalidOperationException("Relative path contains an invalid or traversal segment.");
        return root + "\\" + relative;
    }

    public static string NormalizeWindowsPath(string path)
    {
        if (string.IsNullOrWhiteSpace(path)) return string.Empty;
        var normalized = path.Trim().Replace('/', '\\');
        while (normalized.Contains("\\\\", StringComparison.Ordinal) && !normalized.StartsWith("\\\\", StringComparison.Ordinal))
            normalized = normalized.Replace("\\\\", "\\", StringComparison.Ordinal);
        return normalized.TrimEnd('\\');
    }

    public static string NormalizeForComparison(string path) =>
        NormalizeWindowsPath(path).ToUpperInvariant();

    // Mirrors the active legacy VB implementation:
    // Regex.Replace(Path.GetFileName(filePath), "[^\\w\\s]", "")
    //   .Trim().Replace(" ", "-").Replace("_", "-").ToLower()
    public static string GenerateLegacySolrId(string path)
    {
        var windowsPath = NormalizeWindowsPath(path);
        var lastSlash = windowsPath.LastIndexOf('\\');
        var fileName = lastSlash >= 0 ? windowsPath[(lastSlash + 1)..] : windowsPath;
        var cleaned = Regex.Replace(fileName, @"[^\w\s]", string.Empty);
        return cleaned.Trim().Replace(" ", "-", StringComparison.Ordinal)
            .Replace("_", "-", StringComparison.Ordinal).ToLowerInvariant();
    }

    public static (bool Eligible, string? Reason) LegacyEligibility(string accessiblePath, FileAttributes attributes)
    {
        if ((attributes & FileAttributes.Hidden) == FileAttributes.Hidden)
            return (false, "hidden_attribute");

        var windowsPath = NormalizeWindowsPath(accessiblePath);
        var lastSlash = windowsPath.LastIndexOf('\\');
        var fileName = lastSlash >= 0 ? windowsPath[(lastSlash + 1)..] : windowsPath;
        var extension = Path.GetExtension(fileName);
        var tmp = windowsPath.ToLowerInvariant()
            .Replace("_", " ", StringComparison.Ordinal)
            .Replace("-", " ", StringComparison.Ordinal)
            .Replace("\\", " ", StringComparison.Ordinal);
        if (!string.IsNullOrEmpty(extension))
            tmp = tmp.Replace(extension.ToLowerInvariant(), string.Empty, StringComparison.Ordinal);
        var parts = tmp.Split(' ', StringSplitOptions.None);
        if (parts.Contains("dni", StringComparer.Ordinal)) return (false, "legacy_filename_filter_dni");
        if (parts.Contains("ocrerror", StringComparer.Ordinal)) return (false, "legacy_filename_filter_ocrerror");
        return (true, null);
    }
}
