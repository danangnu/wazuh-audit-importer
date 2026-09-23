using MySqlConnector;

namespace WazuhAuditImporter;

public static class PipelineOrchestrator
{
    public static int RunOnce(
        ImportSettings settings,
        string databaseUser,
        string databasePassword,
        string indexerUser,
        string indexerPassword,
        string workerRoot,
        string stateDirectory,
        string? reportDirectory)
    {
        Validate(settings, workerRoot, stateDirectory);
        using var processLock = PipelineStateStore.AcquireProcessLock(stateDirectory);
        using var connection = AuditRepository.Open(settings, databaseUser, databasePassword);
        var summary = RunCycle(settings, connection, indexerUser, indexerPassword,
            workerRoot, stateDirectory, reportDirectory, cycle: 1);
        WriteState(settings, stateDirectory, summary);
        PrintCycleSummary(summary);
        Console.WriteLine("\nSTEP 12 PIPELINE-ONCE COMPLETE. No Solr update/delete/add/commit request was issued.");
        return 0;
    }

    public static int RunContinuous(
        ImportSettings settings,
        string databaseUser,
        string databasePassword,
        string indexerUser,
        string indexerPassword,
        string workerRoot,
        string stateDirectory,
        string? reportDirectory)
    {
        Validate(settings, workerRoot, stateDirectory);
        using var processLock = PipelineStateStore.AcquireProcessLock(stateDirectory);
        using var cancellation = new CancellationTokenSource();
        ConsoleCancelEventHandler handler = (_, e) =>
        {
            e.Cancel = true;
            if (!cancellation.IsCancellationRequested)
            {
                Console.WriteLine("\nStop requested. Step 12 will exit after the current safe operation.");
                cancellation.Cancel();
            }
        };
        Console.CancelKeyPress += handler;

        MySqlConnection? connection = null;
        long cycle = 0;
        try
        {
            Console.WriteLine($"Step 12 approval-gated pipeline started. poll={settings.OrchestratorPollSeconds}s; retry={settings.OrchestratorRetrySeconds}s");
            Console.WriteLine($"Worker root : {Path.GetFullPath(workerRoot)}");
            Console.WriteLine($"State dir   : {Path.GetFullPath(stateDirectory)}");
            if (!string.IsNullOrWhiteSpace(reportDirectory))
                Console.WriteLine($"Report dir  : {Path.GetFullPath(reportDirectory)}");
            Console.WriteLine($"Process lock: {processLock.Path}");
            Console.WriteLine("The pipeline may collect Wazuh events, write MariaDB audit/queue/plan/payload rows, read FLOSVR01 content, and query Solr.");
            Console.WriteLine("It NEVER calls the Solr update API. READY_FOR_APPROVAL requires a separate explicit Step 11 --apply command.\n");

            while (!cancellation.IsCancellationRequested)
            {
                cycle++;
                try
                {
                    connection ??= AuditRepository.Open(settings, databaseUser, databasePassword);
                    var summary = RunCycle(settings, connection, indexerUser, indexerPassword,
                        workerRoot, stateDirectory, reportDirectory, cycle);
                    WriteState(settings, stateDirectory, summary);
                    PrintCycleSummary(summary);
                    if (WaitOrCancelled(cancellation.Token, settings.OrchestratorPollSeconds))
                        break;
                }
                catch (MySqlException ex) when (IsTransientDatabaseError(ex))
                {
                    ResetConnection(ref connection);
                    WriteFailureState(settings, stateDirectory, cycle, "TRANSIENT_DB_ERROR", ex.Message);
                    Console.Error.WriteLine($"[{DateTime.UtcNow:yyyy-MM-dd'T'HH:mm:ss'Z'}] STEP12 TRANSIENT DB ERROR {ex.Number}: {ex.Message}");
                    Console.Error.WriteLine($"No Solr write was attempted. Retrying in {settings.OrchestratorRetrySeconds}s.");
                    if (WaitOrCancelled(cancellation.Token, settings.OrchestratorRetrySeconds)) break;
                }
                catch (HttpRequestException ex)
                {
                    WriteFailureState(settings, stateDirectory, cycle, "TRANSIENT_HTTP_ERROR", ex.Message);
                    Console.Error.WriteLine($"[{DateTime.UtcNow:yyyy-MM-dd'T'HH:mm:ss'Z'}] STEP12 TRANSIENT HTTP ERROR: {ex.Message}");
                    Console.Error.WriteLine($"No Solr write was attempted. Check the Indexer tunnel/Solr GET connectivity; retrying in {settings.OrchestratorRetrySeconds}s.");
                    if (WaitOrCancelled(cancellation.Token, settings.OrchestratorRetrySeconds)) break;
                }
                catch (TaskCanceledException ex) when (!cancellation.IsCancellationRequested)
                {
                    WriteFailureState(settings, stateDirectory, cycle, "TRANSIENT_TIMEOUT", ex.Message);
                    Console.Error.WriteLine($"[{DateTime.UtcNow:yyyy-MM-dd'T'HH:mm:ss'Z'}] STEP12 TIMEOUT: {ex.Message}");
                    Console.Error.WriteLine($"No Solr write was attempted. Retrying in {settings.OrchestratorRetrySeconds}s.");
                    if (WaitOrCancelled(cancellation.Token, settings.OrchestratorRetrySeconds)) break;
                }
                catch (EventConflictException ex)
                {
                    WriteFailureState(settings, stateDirectory, cycle, "DEFERRED_VERSION_RACE", ex.Message);
                    Console.Error.WriteLine($"[{DateTime.UtcNow:yyyy-MM-dd'T'HH:mm:ss'Z'}] STEP12 DEFERRED: {ex.Message}");
                    Console.Error.WriteLine($"A newer event/state won the race. No Solr write was attempted; retrying in {settings.OrchestratorRetrySeconds}s.");
                    if (WaitOrCancelled(cancellation.Token, settings.OrchestratorRetrySeconds)) break;
                }
                catch (Exception ex) when (ex is SolrConcreteActionException or SolrPayloadException or SolrExecutionException or SolrReadOnlyException)
                {
                    WriteFailureState(settings, stateDirectory, cycle, "OPERATOR_BLOCKED", ex.Message);
                    Console.Error.WriteLine($"[{DateTime.UtcNow:yyyy-MM-dd'T'HH:mm:ss'Z'}] STEP12 OPERATOR BLOCK: {ex.Message}");
                    Console.Error.WriteLine($"No Solr write was attempted. The pipeline will re-check in {settings.OrchestratorRetrySeconds}s; do not use --apply until resolved.");
                    if (WaitOrCancelled(cancellation.Token, settings.OrchestratorRetrySeconds)) break;
                }
                catch (Exception ex) when (ex is DirectoryNotFoundException or UnauthorizedAccessException or IOException)
                {
                    WriteFailureState(settings, stateDirectory, cycle, "SOURCE_OR_STATE_IO_ERROR", ex.Message);
                    Console.Error.WriteLine($"[{DateTime.UtcNow:yyyy-MM-dd'T'HH:mm:ss'Z'}] STEP12 I/O ERROR: {ex.Message}");
                    Console.Error.WriteLine($"An inaccessible candidate folder is never treated as empty. No Solr write was attempted; retrying in {settings.OrchestratorRetrySeconds}s.");
                    if (WaitOrCancelled(cancellation.Token, settings.OrchestratorRetrySeconds)) break;
                }
            }

            Console.WriteLine("Step 12 approval-gated pipeline stopped cleanly. No Solr writes were performed by Step 12.");
            return 0;
        }
        finally
        {
            ResetConnection(ref connection);
            Console.CancelKeyPress -= handler;
        }
    }

    public static PipelineCycleSummary RunCycle(
        ImportSettings settings,
        MySqlConnection connection,
        string indexerUser,
        string indexerPassword,
        string workerRoot,
        string stateDirectory,
        string? reportDirectory,
        long cycle)
    {
        var collector = IndexerCollector.CollectOnce(settings, connection, indexerUser, indexerPassword, printDuplicateEvents: false);

        var processed = 0;
        while (processed < settings.OrchestratorMaxWorkerItemsPerCycle)
        {
            var outcome = CandidateWorker.ProcessNext(settings, connection, workerRoot, stateDirectory, quietNoWork: true);
            if (outcome.Kind == WorkerRunKind.NoWork) break;
            processed++;
        }
        if (processed == settings.OrchestratorMaxWorkerItemsPerCycle)
            Console.WriteLine($"Step 12 worker drain reached configured per-cycle limit {settings.OrchestratorMaxWorkerItemsPerCycle}; remaining work will be handled next cycle.");

        var prep = PrepareLatestMutation(settings, connection, workerRoot, reportDirectory);
        return new PipelineCycleSummary(
            cycle,
            collector.Seen,
            collector.Accepted,
            collector.Inserted,
            collector.Duplicates,
            collector.Ignored,
            processed,
            prep.Decision.Disposition,
            prep.Snapshot?.MutationId,
            prep.Snapshot?.WorkerVersion,
            prep.Decision.Detail,
            DateTime.UtcNow);
    }

    private static (PipelineMutationSnapshot? Snapshot, PipelineDecisionResult Decision) PrepareLatestMutation(
        ImportSettings settings,
        MySqlConnection connection,
        string workerRoot,
        string? reportDirectory)
    {
        var candidateId = settings.CandidateIds.Single();
        for (var pass = 0; pass < 5; pass++)
        {
            var snapshot = PipelineRepository.ReadLatestSnapshot(connection, settings, candidateId);
            var decision = PipelineDecision.Decide(snapshot);
            if (snapshot is null) return (null, decision);

            switch (decision.Disposition)
            {
                case PipelineMutationDisposition.NeedsActions:
                    Console.WriteLine($"STEP12 PREPARE mutation_id={snapshot.MutationId}: running Step 10A idempotently.");
                    SolrConcreteActionPlanner.Run(settings, connection, workerRoot, reportDirectory);
                    var afterActions = PipelineRepository.ReadLatestSnapshot(connection, settings, candidateId)
                        ?? throw new EventConflictException("Latest mutation disappeared after Step 10A.");
                    if (afterActions.MutationId != snapshot.MutationId)
                        throw new EventConflictException("A newer mutation appeared during Step 10A; defer to the newer version.");
                    if (afterActions.ActionCount == 0)
                    {
                        PipelineRepository.MarkNoActionMutationSkipped(connection, settings, afterActions);
                        var skipped = PipelineRepository.ReadLatestSnapshot(connection, settings, candidateId);
                        return (skipped, new PipelineDecisionResult(PipelineMutationDisposition.Complete,
                            $"Mutation {snapshot.MutationId} produced zero concrete actions because live FLOSVR01/Solr were already reconciled; mutation marked skipped."));
                    }
                    continue;

                case PipelineMutationDisposition.NeedsPayloads:
                    Console.WriteLine($"STEP12 PREPARE mutation_id={snapshot.MutationId}: running Step 10B idempotently.");
                    _ = SolrPayloadPlanner.Run(settings, connection, workerRoot, reportDirectory);
                    continue;

                case PipelineMutationDisposition.ReadyForApproval:
                    Console.WriteLine($"STEP12 PREFLIGHT mutation_id={snapshot.MutationId}: invoking Step 11 in read-only preflight mode.");
                    _ = SolrExecutor.Run(settings, connection, workerRoot, snapshot.MutationId, apply: false);
                    return (snapshot, new PipelineDecisionResult(PipelineMutationDisposition.ReadyForApproval,
                        $"READY_FOR_APPROVAL mutation_id={snapshot.MutationId}. Step 12 will not apply it; use explicit 'solr-execute --mutation-id {snapshot.MutationId} --worker-root <root> --apply' after operator review."));

                default:
                    return (snapshot, decision);
            }
        }

        throw new InvalidOperationException("Step 12 preparation exceeded its bounded stage-transition count.");
    }

    private static void Validate(ImportSettings settings, string workerRoot, string stateDirectory)
    {
        settings.Validate();
        settings.ValidateWorker(workerRoot, stateDirectory);
        settings.ValidateCollector();
        settings.ValidateSolrReadOnly();
    }

    private static void PrintCycleSummary(PipelineCycleSummary summary)
    {
        Console.WriteLine(
            $"[{summary.CompletedAtUtc:yyyy-MM-dd'T'HH:mm:ss'Z'}] step12 cycle={summary.Cycle} " +
            $"collector(seen={summary.CollectorSeen},accepted={summary.CollectorAccepted},inserted={summary.CollectorInserted},duplicates={summary.CollectorDuplicates},ignored={summary.CollectorIgnored}) " +
            $"worker_processed={summary.WorkerItemsProcessed} stage={summary.Disposition} " +
            $"mutation={(summary.MutationId?.ToString() ?? "n/a")} version={(summary.WorkerVersion?.ToString() ?? "n/a")}");
        Console.WriteLine("  " + summary.Detail);
    }

    private static void WriteState(ImportSettings settings, string stateDirectory, PipelineCycleSummary summary)
    {
        _ = PipelineStateStore.Save(stateDirectory, new PipelineLocalState(
            1,
            settings.SourceInstance,
            settings.AgentId,
            settings.CandidateIds.Single(),
            summary.Cycle,
            summary.Disposition.ToString(),
            summary.MutationId,
            summary.WorkerVersion,
            summary.Detail,
            summary.CompletedAtUtc));
    }

    private static void WriteFailureState(ImportSettings settings, string stateDirectory, long cycle, string stage, string detail)
    {
        try
        {
            _ = PipelineStateStore.Save(stateDirectory, new PipelineLocalState(
                1,
                settings.SourceInstance,
                settings.AgentId,
                settings.CandidateIds.Single(),
                cycle,
                stage,
                null,
                null,
                detail.Length > 2000 ? detail[..2000] : detail,
                DateTime.UtcNow));
        }
        catch
        {
            // Console/database evidence remains authoritative; local status persistence is best-effort.
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
