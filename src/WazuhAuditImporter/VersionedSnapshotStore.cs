using System.Text;
using System.Text.Json;

namespace WazuhAuditImporter;

public static class VersionedSnapshotStore
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true
    };

    public static CandidateSnapshot? Load(
        string stateDirectory,
        WorkerClaim claim,
        ulong completedVersion)
    {
        if (completedVersion == 0) return null;
        var path = SnapshotPath(stateDirectory, claim, completedVersion);
        if (!File.Exists(path))
            throw new FileNotFoundException(
                $"Snapshot for completed version {completedVersion} is missing. " +
                "Do not treat this as an empty candidate; restore/inspect worker state first.", path);

        var snapshot = JsonSerializer.Deserialize<CandidateSnapshot>(
            File.ReadAllText(path, new UTF8Encoding(false, true)), JsonOptions)
            ?? throw new InvalidDataException("Snapshot file is empty or invalid.");

        if (!snapshot.CandidateId.Equals(claim.CandidateId, StringComparison.Ordinal) ||
            snapshot.Files is null)
            throw new InvalidDataException("Snapshot identity does not match the claimed candidate.");

        foreach (var (key, state) in snapshot.Files)
        {
            if (!key.Equals(state.RelativePath, StringComparison.OrdinalIgnoreCase) ||
                Path.IsPathRooted(key) || key == ".." ||
                key.StartsWith(".." + Path.DirectorySeparatorChar, StringComparison.Ordinal))
                throw new InvalidDataException("Snapshot contains an invalid relative file path.");
        }

        return snapshot;
    }

    public static string Save(
        string stateDirectory,
        WorkerClaim claim,
        CandidateSnapshot snapshot)
    {
        if (!snapshot.CandidateId.Equals(claim.CandidateId, StringComparison.Ordinal))
            throw new InvalidOperationException("Refusing to save a snapshot for another candidate.");

        var path = SnapshotPath(stateDirectory, claim, claim.ClaimedVersion);
        var directory = Path.GetDirectoryName(path)!;
        Directory.CreateDirectory(directory);

        var temp = path + "." + claim.LeaseToken + ".tmp";
        var json = JsonSerializer.Serialize(snapshot, JsonOptions);
        try
        {
            using (var stream = new FileStream(temp, FileMode.CreateNew, FileAccess.Write,
                       FileShare.None, 4096, FileOptions.WriteThrough))
            using (var writer = new StreamWriter(stream, new UTF8Encoding(false)))
            {
                writer.Write(json);
                writer.Flush();
                stream.Flush(flushToDisk: true);
            }

            // This claimed version has not been completed yet. A previous orphan file can
            // exist after a DB failure; replacing it is safer than using stale candidate state.
            File.Move(temp, path, overwrite: true);
            return path;
        }
        finally
        {
            try { if (File.Exists(temp)) File.Delete(temp); } catch { }
        }
    }

    public static string SnapshotPath(string stateDirectory, WorkerClaim claim, ulong version)
    {
        ValidateComponent(claim.SourceInstance, nameof(claim.SourceInstance));
        ValidateComponent(claim.AgentId, nameof(claim.AgentId));
        ValidateComponent(claim.CandidateId, nameof(claim.CandidateId));
        if (version == 0) throw new ArgumentOutOfRangeException(nameof(version));

        var root = Path.GetFullPath(stateDirectory);
        return Path.Combine(root, claim.SourceInstance, claim.AgentId, claim.CandidateId,
            $"snapshot-v{version}.json");
    }

    private static void ValidateComponent(string value, string field)
    {
        if (string.IsNullOrWhiteSpace(value) || value is "." or ".." ||
            value.IndexOfAny(Path.GetInvalidFileNameChars()) >= 0 || value.Contains('/') || value.Contains('\\'))
            throw new InvalidOperationException($"Invalid snapshot path component: {field}.");
    }
}
