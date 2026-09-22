using MySqlConnector;

namespace WazuhAuditImporter;

public enum WorkerRunKind
{
    NoWork,
    Processed
}

public sealed record WorkerRunOutcome(
    WorkerRunKind Kind,
    string? CandidateId = null,
    ulong? ClaimedVersion = null,
    string? CompletionStatus = null,
    ulong? CompletedVersion = null);

public static class CandidateWorker
{
    public static int Preflight(ImportSettings settings, string workerRoot)
    {
        settings.ValidateWorker(workerRoot, Path.GetFullPath("worker-state"));
        Console.WriteLine("Worker preflight - metadata read only; no DB writes; no Solr writes.");
        Console.WriteLine($"Worker root: {Path.GetFullPath(workerRoot)}");

        foreach (var candidateId in settings.CandidateIds)
        {
            var folder = ResolveCandidateFolder(workerRoot, candidateId);
            Console.Write($"Candidate {candidateId}: {folder} ... ");
            var snapshot = CandidateReconciler.Capture(candidateId, folder);
            Console.WriteLine($"OK ({snapshot.Files.Count} files visible)");
        }
        return 0;
    }

    public static int RunOnce(
        ImportSettings settings,
        MySqlConnection connection,
        string workerRoot,
        string stateDirectory)
    {
        ProcessNext(settings, connection, workerRoot, stateDirectory, quietNoWork: false);
        return 0;
    }

    public static WorkerRunOutcome ProcessNext(
        ImportSettings settings,
        MySqlConnection connection,
        string workerRoot,
        string stateDirectory,
        bool quietNoWork)
    {
        settings.ValidateWorker(workerRoot, stateDirectory);
        var claim = WorkerRepository.ClaimNext(connection, settings);
        if (claim is null)
        {
            if (!quietNoWork)
            {
                Console.WriteLine("No due candidate work items for the configured pilot scope.");
                Console.WriteLine("No source folders were scanned. No Solr writes.");
            }
            return new WorkerRunOutcome(WorkerRunKind.NoWork);
        }

        Console.WriteLine($"CLAIM work_item_id={claim.WorkItemId} candidate={claim.CandidateId} " +
                          $"claimed_version={claim.ClaimedVersion} prior_completed={claim.PriorCompletedVersion} " +
                          $"attempt={claim.AttemptCount}");
        Console.WriteLine($"Lease expires UTC: {claim.LeaseExpiresUtc:yyyy-MM-dd'T'HH:mm:ss.ffffff'Z'}");

        try
        {
            var accessibleFolder = ResolveCandidateFolder(workerRoot, claim.CandidateId);
            Console.WriteLine($"Source queue folder : {claim.SourceCandidateFolder}");
            Console.WriteLine($"Accessible folder   : {accessibleFolder}");

            var previous = VersionedSnapshotStore.Load(
                stateDirectory, claim, claim.PriorCompletedVersion);
            var current = CandidateReconciler.Capture(claim.CandidateId, accessibleFolder);
            var result = CandidateReconciler.Compare(previous, current);

            Console.WriteLine($"Files observed       : {current.Files.Count}");
            if (result.IsBaseline)
            {
                Console.WriteLine("BASELINE: no previous completed worker snapshot exists.");
                Console.WriteLine("Current inventory will become the baseline; historical ADD/REMOVE/CHANGE is not inferred.");
            }
            else
            {
                foreach (var item in result.Added) Console.WriteLine($"  ADD    : {item}");
                foreach (var item in result.Removed) Console.WriteLine($"  REMOVE : {item}");
                foreach (var item in result.Changed) Console.WriteLine($"  CHANGE : {item}");
                if (result.Added.Count + result.Removed.Count + result.Changed.Count == 0)
                    Console.WriteLine("  Result : no inventory change detected");
            }

            // Write the immutable versioned snapshot before DB completion. If completion
            // fails, the file is only an orphan and is ignored because completed_version
            // did not move. No previous completed snapshot is overwritten.
            var snapshotPath = VersionedSnapshotStore.Save(stateDirectory, claim, current);
            Console.WriteLine($"Snapshot prepared    : {snapshotPath}");

            var completion = WorkerRepository.Complete(connection, claim);
            Console.WriteLine($"COMPLETE status={completion.Status} event_version={completion.EventVersion} " +
                              $"completed_version={completion.CompletedVersion}");
            if (completion.Status == "pending")
                Console.WriteLine("A newer event arrived while this claim was processing; the candidate remains pending for another pass.");

            Console.WriteLine("No file contents were read. No source files were changed. No Solr writes.");
            return new WorkerRunOutcome(
                WorkerRunKind.Processed,
                claim.CandidateId,
                claim.ClaimedVersion,
                completion.Status,
                completion.CompletedVersion);
        }
        catch (Exception ex)
        {
            try
            {
                var requeued = WorkerRepository.Fail(connection, claim, settings, ex.Message);
                Console.Error.WriteLine(requeued
                    ? $"Worker failed; queue row moved to retry for candidate {claim.CandidateId}."
                    : "Worker failed after its lease was lost; queue row was not overwritten.");
            }
            catch (Exception failEx)
            {
                Console.Error.WriteLine("WARNING: worker failure could not be recorded safely: " + failEx.Message);
            }
            throw;
        }
    }

    public static string ResolveCandidateFolder(string workerRoot, string candidateId)
    {
        var root = Path.GetFullPath(workerRoot)
            .TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        var candidate = Path.GetFullPath(Path.Combine(root, candidateId));
        var expectedPrefix = root + Path.DirectorySeparatorChar;
        if (!candidate.StartsWith(expectedPrefix, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("Candidate mapping escaped the configured worker root.");
        return candidate;
    }
}
