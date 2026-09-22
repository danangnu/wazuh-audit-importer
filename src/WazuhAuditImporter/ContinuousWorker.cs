using MySqlConnector;

namespace WazuhAuditImporter;

public static class ContinuousWorker
{
    public static int Run(
        ImportSettings settings,
        string databaseUser,
        string databasePassword,
        string workerRoot,
        string stateDirectory)
    {
        settings.Validate();
        settings.ValidateWorker(workerRoot, stateDirectory);

        using var cancellation = new CancellationTokenSource();
        ConsoleCancelEventHandler handler = (_, e) =>
        {
            e.Cancel = true;
            if (!cancellation.IsCancellationRequested)
            {
                Console.WriteLine("\nStop requested. The worker will exit after the current operation.");
                cancellation.Cancel();
            }
        };
        Console.CancelKeyPress += handler;

        MySqlConnection? connection = null;
        long cycle = 0;
        var consecutiveFailures = 0;

        try
        {
            Console.WriteLine(
                $"Continuous candidate worker started. poll={settings.WorkerPollSeconds}s; " +
                $"loop-retry={settings.WorkerLoopRetrySeconds}s; item-retry={settings.WorkerRetrySeconds}s");
            Console.WriteLine($"Worker root : {Path.GetFullPath(workerRoot)}");
            Console.WriteLine($"State dir   : {Path.GetFullPath(stateDirectory)}");
            Console.WriteLine("Press Ctrl+C to stop cleanly.");
            Console.WriteLine("File metadata only. No source-file changes. No Solr writes.\n");

            while (!cancellation.IsCancellationRequested)
            {
                cycle++;
                try
                {
                    connection ??= AuditRepository.Open(settings, databaseUser, databasePassword);

                    var outcome = CandidateWorker.ProcessNext(
                        settings,
                        connection,
                        workerRoot,
                        stateDirectory,
                        quietNoWork: true);

                    consecutiveFailures = 0;
                    if (outcome.Kind == WorkerRunKind.Processed)
                    {
                        Console.WriteLine(
                            $"[{DateTime.UtcNow:yyyy-MM-dd'T'HH:mm:ss'Z'}] cycle={cycle} " +
                            $"processed candidate={outcome.CandidateId} " +
                            $"claimed_version={outcome.ClaimedVersion} " +
                            $"status={outcome.CompletionStatus} " +
                            $"completed_version={outcome.CompletedVersion}");
                    }
                    else
                    {
                        Console.WriteLine(
                            $"[{DateTime.UtcNow:yyyy-MM-dd'T'HH:mm:ss'Z'}] cycle={cycle} " +
                            $"no due work; waiting {settings.WorkerPollSeconds}s");
                    }

                    if (WaitOrCancelled(cancellation.Token, settings.WorkerPollSeconds))
                        break;
                }
                catch (MySqlException ex) when (IsTransientDatabaseError(ex))
                {
                    consecutiveFailures++;
                    ResetConnection(ref connection);
                    Console.Error.WriteLine(
                        $"[{DateTime.UtcNow:yyyy-MM-dd'T'HH:mm:ss'Z'}] TRANSIENT DB ERROR {ex.Number}: {ex.Message}");
                    Console.Error.WriteLine(
                        $"No candidate folder is inferred empty on this failure. Retrying in " +
                        $"{settings.WorkerLoopRetrySeconds}s (failure {consecutiveFailures}).");
                    if (WaitOrCancelled(cancellation.Token, settings.WorkerLoopRetrySeconds))
                        break;
                }
                catch (DirectoryNotFoundException ex)
                {
                    consecutiveFailures++;
                    Console.Error.WriteLine(
                        $"[{DateTime.UtcNow:yyyy-MM-dd'T'HH:mm:ss'Z'}] SOURCE FOLDER UNAVAILABLE: {ex.Message}");
                    Console.Error.WriteLine(
                        $"The claimed item was moved to retry; an inaccessible folder was NOT treated as empty. " +
                        $"Loop retry in {settings.WorkerLoopRetrySeconds}s (failure {consecutiveFailures}).");
                    if (WaitOrCancelled(cancellation.Token, settings.WorkerLoopRetrySeconds))
                        break;
                }
                catch (UnauthorizedAccessException ex)
                {
                    consecutiveFailures++;
                    Console.Error.WriteLine(
                        $"[{DateTime.UtcNow:yyyy-MM-dd'T'HH:mm:ss'Z'}] SOURCE ACCESS ERROR: {ex.Message}");
                    Console.Error.WriteLine(
                        $"The claimed item was moved to retry when its lease was still owned. " +
                        $"Loop retry in {settings.WorkerLoopRetrySeconds}s (failure {consecutiveFailures}).");
                    if (WaitOrCancelled(cancellation.Token, settings.WorkerLoopRetrySeconds))
                        break;
                }
                catch (IOException ex)
                {
                    consecutiveFailures++;
                    Console.Error.WriteLine(
                        $"[{DateTime.UtcNow:yyyy-MM-dd'T'HH:mm:ss'Z'}] SOURCE I/O ERROR: {ex.Message}");
                    Console.Error.WriteLine(
                        $"The claimed item was moved to retry when its lease was still owned. " +
                        $"Loop retry in {settings.WorkerLoopRetrySeconds}s (failure {consecutiveFailures}).");
                    if (WaitOrCancelled(cancellation.Token, settings.WorkerLoopRetrySeconds))
                        break;
                }
                catch (EventConflictException ex)
                {
                    consecutiveFailures++;
                    Console.Error.WriteLine(
                        $"[{DateTime.UtcNow:yyyy-MM-dd'T'HH:mm:ss'Z'}] WORKER CONFLICT: {ex.Message}");
                    Console.Error.WriteLine(
                        $"No Solr write occurred. Retrying the queue in {settings.WorkerLoopRetrySeconds}s " +
                        $"(failure {consecutiveFailures}).");
                    if (WaitOrCancelled(cancellation.Token, settings.WorkerLoopRetrySeconds))
                        break;
                }
            }

            Console.WriteLine("Continuous candidate worker stopped cleanly. No Solr writes.");
            return 0;
        }
        finally
        {
            ResetConnection(ref connection);
            Console.CancelKeyPress -= handler;
        }
    }

    private static bool IsTransientDatabaseError(MySqlException ex) =>
        ex.Number is not (1044 or 1045 or 1049 or 1142);

    private static bool WaitOrCancelled(CancellationToken token, int seconds) =>
        token.WaitHandle.WaitOne(TimeSpan.FromSeconds(seconds));

    private static void ResetConnection(ref MySqlConnection? connection)
    {
        if (connection is null) return;
        try { connection.Dispose(); } catch { }
        connection = null;
    }
}
