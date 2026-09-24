using MySqlConnector;

namespace WazuhAuditImporter;

public static class SolrExecutor
{
    public static int Run(ImportSettings settings, MySqlConnection connection, string workerRoot,
        ulong mutationId, bool apply)
    {
        settings.ValidateWorker(workerRoot, Path.Combine(Path.GetTempPath(), "wazuh-step11-validation"));
        settings.ValidateSolrReadOnly();

        var target = SolrExecutionRepository.ReadTarget(connection, settings, mutationId);
        BaselineEnrollmentService.RequireApproved(connection, settings, target.CandidateId,
            apply ? "Step 11 Solr execution" : "Step 11 preflight");
        var items = SolrExecutionRepository.ReadItems(connection, target);
        var preflight = ValidateLiveState(settings, connection, workerRoot, target, items);

        Console.WriteLine("Step 11 controlled Solr execution preflight.");
        Console.WriteLine($"Target mutation: id={target.MutationId} candidate={target.CandidateId} worker_version={target.WorkerVersion}");
        Console.WriteLine($"Actions ready : {items.Count}");
        Console.WriteLine($"Disk files    : {preflight.DiskFilesObserved}");
        Console.WriteLine($"Solr docs now : {preflight.SolrDocumentsObserved}");
        foreach (var item in items)
        {
            Console.WriteLine($"  READY order={item.Action.ActionOrder} action_id={item.Action.ActionId} type={item.Action.ActionType} id={item.Action.SolrDocumentId}");
            Console.WriteLine($"        path={item.Action.CanonicalPath}");
        }
        Console.WriteLine("Source/payload drift : none");
        Console.WriteLine("Current Solr/disk plan: matches reviewed Step 10A actions");
        Console.WriteLine("PREFLIGHT PASS.");

        if (!apply)
        {
            Console.WriteLine("\nNO SOLR WRITES. No MariaDB status rows changed.");
            Console.WriteLine($"To execute this exact reviewed mutation, rerun with --mutation-id {mutationId} --apply.");
            return 0;
        }

        Console.WriteLine("\nAPPLY requested. MariaDB will first claim the exact mutation/actions as processing.");
        Console.WriteLine("Solr updates are ordered and followed by one explicit commit. Solr does not provide a MariaDB-style cross-request transaction.");
        Console.WriteLine("If a request fails after the first POST, the mutation is marked failed and Solr must be inspected before any retry.");

        var claimed = false;
        var writesStarted = false;
        try
        {
            SolrExecutionRepository.BeginExecution(connection, settings, target, items.Count);
            claimed = true;

            // Re-check the live filesystem and Solr after the DB claim and before the first POST.
            ValidateLiveState(settings, connection, workerRoot, target, items);
            Console.WriteLine("Post-claim live revalidation: PASS");

            using var writer = new SolrWriteClient(settings);
            foreach (var item in items.OrderBy(x => x.Action.ActionOrder))
            {
                // Re-read source content immediately before an index POST. This catches
                // last-moment source drift without modifying the reviewed payload.
                if (item.Action.ActionType == "index_document")
                {
                    var currentPayload = SolrPayloadBuilder.Build(item.Action, workerRoot, item.Payload.GeneratedAtUtc);
                    SolrExecutionSafety.ValidateCurrentPayload(item, currentPayload);
                }

                writesStarted = true; // A timeout after this point can have an uncertain server-side result.
                writer.PostReviewedPayload(item.Action.ActionId, item.Payload.PayloadJson!);
                Console.WriteLine($"  POST accepted: order={item.Action.ActionOrder} action_id={item.Action.ActionId} type={item.Action.ActionType}");
            }
            writer.Commit();
            Console.WriteLine("  COMMIT accepted");

            VerifyDesiredFinalState(settings, workerRoot, target, items);
            Console.WriteLine("Post-commit GET verification: PASS");

            try
            {
                SolrExecutionRepository.MarkApplied(connection, target.MutationId, items.Count);
            }
            catch (Exception ex) when (ex is MySqlException or EventConflictException or InvalidOperationException)
            {
                throw new SolrExecutionException(
                    "Solr verification passed but MariaDB finalization failed. The Solr mutation may already be fully applied; do NOT blindly rerun Step 11. Inspect Solr and DB status first.", ex);
            }

            Console.WriteLine($"\nSTEP 11 APPLIED. mutation_id={target.MutationId}; actions={items.Count}; verified=true");
            Console.WriteLine("MariaDB mutation/action rows are status=applied.");
            return 0;
        }
        catch (Exception ex) when (ex is SolrExecutionException or SolrConcreteActionException or SolrReadOnlyException or
                                   EventConflictException or IOException or UnauthorizedAccessException or InvalidOperationException)
        {
            if (claimed)
            {
                var prefix = writesStarted
                    ? "UNCERTAIN/PARTIAL SOLR STATE POSSIBLE after update POST. "
                    : "No Solr update POST was started. ";
                SolrExecutionRepository.MarkFailedBestEffort(connection, target.MutationId, prefix + ex.Message);
            }
            if (writesStarted && ex is not SolrExecutionException)
                throw new SolrExecutionException("A Step 11 failure occurred after Solr update POST began. Solr state may be partial/uncertain; inspect with read-only queries before any retry. " + ex.Message, ex);
            throw;
        }
    }

    public static SolrExecutionPreflight ValidateLiveState(ImportSettings settings, MySqlConnection connection, string workerRoot,
        SolrMutationTarget target, IReadOnlyList<SolrExecutionItem> items)
    {
        foreach (var item in items) SolrExecutionSafety.ValidateReadyItem(item);

        using var client = new SolrReadOnlyClient(settings);
        var schema = client.ReadSchema();
        if (!schema.UniqueKey.Equals(settings.SolrIdField, StringComparison.Ordinal))
            throw new SolrExecutionException($"Solr uniqueKey drift: expected '{settings.SolrIdField}', got '{schema.UniqueKey}'.");
        foreach (var required in new[] { settings.SolrIdField, settings.SolrCandidateField, settings.SolrPathField, settings.SolrLastUpdateField, settings.SolrContentField })
            if (!schema.Fields.ContainsKey(required))
                throw new SolrExecutionException($"Required Solr field '{required}' is missing from the live schema.");

        var candidateFolder = CandidateWorker.ResolveCandidateFolder(workerRoot, target.CandidateId);
        var disk = SolrReadOnlyDiscovery.CaptureDiskFiles(workerRoot, candidateFolder, settings.SolrCanonicalRoot);
        var solrDocs = client.QueryCandidate(target.CandidateId);
        var report = SolrReadOnlyDiscovery.Compare(settings, target.CandidateId, workerRoot, candidateFolder, schema, disk, solrDocs);
        var changedRelativePaths = SolrPlanRepository.ReadChangedRelativePaths(connection, target.MutationId);
        var currentActions = SolrConcreteActionBuilder.Build(target, report, disk, solrDocs, client.QueryById, changedRelativePaths);
        SolrExecutionSafety.ValidateCurrentActionPlan(items, currentActions);

        foreach (var item in items)
        {
            var currentPayload = SolrPayloadBuilder.Build(item.Action, workerRoot, item.Payload.GeneratedAtUtc);
            SolrExecutionSafety.ValidateCurrentPayload(item, currentPayload);
        }

        return new SolrExecutionPreflight(target, items, disk.Count, solrDocs.Count, DateTime.UtcNow);
    }

    public static void VerifyDesiredFinalState(ImportSettings settings, string workerRoot,
        SolrMutationTarget target, IReadOnlyList<SolrExecutionItem> items)
    {
        using var client = new SolrReadOnlyClient(settings);
        foreach (var item in items)
        {
            var found = client.QueryById(item.Action.SolrDocumentId);
            if (item.Action.ActionType == "delete_document")
            {
                // A same-ID move has a later index action with the same unique key. In that
                // case the final document is expected to exist at the new index path.
                var replacement = items.FirstOrDefault(x => x.Action.ActionType == "index_document" &&
                    x.Action.SolrDocumentId.Equals(item.Action.SolrDocumentId, StringComparison.Ordinal));
                if (replacement is null)
                {
                    if (found.Count != 0)
                        throw new SolrExecutionException($"Post-commit verification failed: deleted id '{item.Action.SolrDocumentId}' is still present.");
                }
                continue;
            }
            if (found.Count != 1)
                throw new SolrExecutionException($"Post-commit verification failed: indexed id '{item.Action.SolrDocumentId}' returned {found.Count} documents.");
            var doc = found[0];
            if (!doc.CandidateId.Equals(target.CandidateId, StringComparison.Ordinal) ||
                SolrPathMapper.NormalizeForComparison(doc.Path) != SolrPathMapper.NormalizeForComparison(item.Action.CanonicalPath))
                throw new SolrExecutionException($"Post-commit verification failed for indexed id '{item.Action.SolrDocumentId}': candidate/path mismatch.");
        }

        var schema = client.ReadSchema();
        var candidateFolder = CandidateWorker.ResolveCandidateFolder(workerRoot, target.CandidateId);
        var disk = SolrReadOnlyDiscovery.CaptureDiskFiles(workerRoot, candidateFolder, settings.SolrCanonicalRoot);
        var docs = client.QueryCandidate(target.CandidateId);
        var finalReport = SolrReadOnlyDiscovery.Compare(settings, target.CandidateId, workerRoot, candidateFolder, schema, disk, docs);
        if (finalReport.LocalLegacyIdCollisions.Count != 0 ||
            finalReport.Comparisons.Any(x => x.Status != "MATCH" && x.Status != "SKIPPED_BY_LEGACY_FILTER"))
            throw new SolrExecutionException("Post-commit candidate reconciliation is not clean; expected only MATCH or SKIPPED_BY_LEGACY_FILTER results.");
    }
}
