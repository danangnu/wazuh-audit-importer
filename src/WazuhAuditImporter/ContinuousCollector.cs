using MySqlConnector;

namespace WazuhAuditImporter;

public static class ContinuousCollector
{
    public static int Run(
        ImportSettings settings,
        string databaseUser,
        string databasePassword,
        string indexerUser,
        string indexerPassword)
    {
        settings.Validate();

        using var cancellation = new CancellationTokenSource();
        ConsoleCancelEventHandler handler = (_, e) =>
        {
            e.Cancel = true;
            if (!cancellation.IsCancellationRequested)
            {
                Console.WriteLine("\nStop requested. The collector will exit after the current operation.");
                cancellation.Cancel();
            }
        };
        Console.CancelKeyPress += handler;

        MySqlConnection? connection = null;
        var cycle = 0L;
        var consecutiveFailures = 0;

        try
        {
            Console.WriteLine($"Continuous collector started. poll={settings.CollectorPollSeconds}s; retry={settings.CollectorRetrySeconds}s");
            Console.WriteLine("Press Ctrl+C to stop cleanly.");
            Console.WriteLine("No worker is run. No Solr writes.\n");

            while (!cancellation.IsCancellationRequested)
            {
                cycle++;
                try
                {
                    connection ??= AuditRepository.Open(settings, databaseUser, databasePassword);

                    var summary = IndexerCollector.CollectOnce(
                        settings,
                        connection,
                        indexerUser,
                        indexerPassword,
                        printDuplicateEvents: false);

                    consecutiveFailures = 0;
                    Console.WriteLine(
                        $"[{DateTime.UtcNow:yyyy-MM-dd'T'HH:mm:ss'Z'}] cycle={cycle} " +
                        $"seen={summary.Seen} accepted={summary.Accepted} inserted={summary.Inserted} " +
                        $"duplicates={summary.Duplicates} ignored={summary.Ignored} " +
                        $"checkpoint={summary.ThroughUtc:yyyy-MM-dd'T'HH:mm:ss.ffffff'Z'}");

                    if (WaitOrCancelled(cancellation.Token, settings.CollectorPollSeconds))
                        break;
                }
                catch (MySqlException ex) when (IsTransientDatabaseError(ex))
                {
                    consecutiveFailures++;
                    ResetConnection(ref connection);
                    Console.Error.WriteLine(
                        $"[{DateTime.UtcNow:yyyy-MM-dd'T'HH:mm:ss'Z'}] TRANSIENT DB ERROR {ex.Number}: {ex.Message}");
                    Console.Error.WriteLine(
                        $"Checkpoint was not advanced for the failed operation. Retrying in {settings.CollectorRetrySeconds}s (failure {consecutiveFailures}).");
                    if (WaitOrCancelled(cancellation.Token, settings.CollectorRetrySeconds))
                        break;
                }
                catch (HttpRequestException ex)
                {
                    consecutiveFailures++;
                    ResetConnection(ref connection);
                    Console.Error.WriteLine(
                        $"[{DateTime.UtcNow:yyyy-MM-dd'T'HH:mm:ss'Z'}] TRANSIENT INDEXER ERROR: {ex.Message}");
                    Console.Error.WriteLine(
                        $"Checkpoint was not advanced for the failed operation. Check the SSH tunnel; retrying in {settings.CollectorRetrySeconds}s (failure {consecutiveFailures}).");
                    if (WaitOrCancelled(cancellation.Token, settings.CollectorRetrySeconds))
                        break;
                }
                catch (TaskCanceledException ex) when (!cancellation.IsCancellationRequested)
                {
                    consecutiveFailures++;
                    ResetConnection(ref connection);
                    Console.Error.WriteLine(
                        $"[{DateTime.UtcNow:yyyy-MM-dd'T'HH:mm:ss'Z'}] TRANSIENT TIMEOUT: {ex.Message}");
                    Console.Error.WriteLine(
                        $"Checkpoint was not advanced for the failed operation. Retrying in {settings.CollectorRetrySeconds}s (failure {consecutiveFailures}).");
                    if (WaitOrCancelled(cancellation.Token, settings.CollectorRetrySeconds))
                        break;
                }
            }

            Console.WriteLine("Continuous collector stopped cleanly. No worker was run. No Solr writes.");
            return 0;
        }
        finally
        {
            ResetConnection(ref connection);
            Console.CancelKeyPress -= handler;
        }
    }

    private static bool IsTransientDatabaseError(MySqlException ex)
    {
        // Authentication, authorization and missing-schema errors need operator action;
        // do not retry those forever. Connection failures, deadlocks and timeouts may recover.
        return ex.Number is not (1044 or 1045 or 1049 or 1142);
    }

    private static bool WaitOrCancelled(CancellationToken token, int seconds) =>
        token.WaitHandle.WaitOne(TimeSpan.FromSeconds(seconds));

    private static void ResetConnection(ref MySqlConnection? connection)
    {
        if (connection is null) return;
        try { connection.Dispose(); } catch { }
        connection = null;
    }
}
