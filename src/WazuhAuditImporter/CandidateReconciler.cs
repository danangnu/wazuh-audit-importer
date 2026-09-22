namespace WazuhAuditImporter;

public static class CandidateReconciler
{
    public static CandidateSnapshot Capture(string candidateId, string folder)
    {
        if (string.IsNullOrWhiteSpace(candidateId))
            throw new ArgumentException("Candidate ID is required.", nameof(candidateId));
        if (!Directory.Exists(folder))
            throw new DirectoryNotFoundException($"Candidate folder is not accessible: {folder}");

        var root = Path.GetFullPath(folder)
            .TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        var files = new Dictionary<string, SnapshotFileState>(StringComparer.OrdinalIgnoreCase);
        var options = new EnumerationOptions
        {
            RecurseSubdirectories = true,
            IgnoreInaccessible = false,
            ReturnSpecialDirectories = false,
            AttributesToSkip = FileAttributes.ReparsePoint
        };

        foreach (var file in Directory.EnumerateFiles(root, "*", options))
        {
            var full = Path.GetFullPath(file);
            if (!IsWithinRoot(root, full))
                throw new IOException($"Enumerated path escaped candidate root: {full}");

            var info = new FileInfo(full);
            info.Refresh();
            if (!info.Exists)
                throw new IOException($"File disappeared during reconciliation: {full}");

            var relative = Path.GetRelativePath(root, full)
                .Replace(Path.AltDirectorySeparatorChar, Path.DirectorySeparatorChar);
            if (Path.IsPathRooted(relative) || relative == ".." ||
                relative.StartsWith(".." + Path.DirectorySeparatorChar, StringComparison.Ordinal))
                throw new IOException($"Invalid relative path produced during reconciliation: {relative}");

            if (!files.TryAdd(relative, new SnapshotFileState(relative, info.Length,
                    DateTime.SpecifyKind(info.LastWriteTimeUtc, DateTimeKind.Utc))))
                throw new IOException($"Duplicate case-insensitive file path encountered: {relative}");
        }

        return new CandidateSnapshot(
            candidateId,
            DateTime.UtcNow,
            files);
    }

    public static ReconciliationResult Compare(CandidateSnapshot? previous, CandidateSnapshot current)
    {
        if (previous is null)
        {
            // A first worker run establishes a trustworthy baseline. It does not claim that
            // every pre-existing file is a newly-added file.
            return new ReconciliationResult(
                current.CandidateId,
                IsBaseline: true,
                Added: [],
                Removed: [],
                Changed: []);
        }

        if (!previous.CandidateId.Equals(current.CandidateId, StringComparison.Ordinal))
            throw new InvalidOperationException("Snapshot candidate ID does not match the claimed work item.");

        var added = current.Files.Keys
            .Except(previous.Files.Keys, StringComparer.OrdinalIgnoreCase)
            .OrderBy(x => x, StringComparer.OrdinalIgnoreCase)
            .ToList();

        var removed = previous.Files.Keys
            .Except(current.Files.Keys, StringComparer.OrdinalIgnoreCase)
            .OrderBy(x => x, StringComparer.OrdinalIgnoreCase)
            .ToList();

        var changed = current.Files.Keys
            .Intersect(previous.Files.Keys, StringComparer.OrdinalIgnoreCase)
            .Where(key =>
            {
                var before = previous.Files[key];
                var after = current.Files[key];
                return before.Length != after.Length || before.LastWriteUtc != after.LastWriteUtc;
            })
            .OrderBy(x => x, StringComparer.OrdinalIgnoreCase)
            .ToList();

        return new ReconciliationResult(
            current.CandidateId,
            IsBaseline: false,
            Added: added,
            Removed: removed,
            Changed: changed);
    }

    private static bool IsWithinRoot(string root, string full)
    {
        var prefix = root + Path.DirectorySeparatorChar;
        return full.Equals(root, StringComparison.OrdinalIgnoreCase) ||
               full.StartsWith(prefix, StringComparison.OrdinalIgnoreCase);
    }
}
