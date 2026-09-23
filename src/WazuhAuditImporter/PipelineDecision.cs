namespace WazuhAuditImporter;

public static class PipelineDecision
{
    public static PipelineDecisionResult Decide(PipelineMutationSnapshot? snapshot)
    {
        if (snapshot is null)
            return new(PipelineMutationDisposition.Idle, "No candidate mutation exists yet.");

        if (snapshot.MutationStatus is "processing" or "failed")
            return new(PipelineMutationDisposition.HaltedExecution,
                $"Latest mutation {snapshot.MutationId} is status={snapshot.MutationStatus}; operator inspection is required before orchestration can continue.");

        if (snapshot.MutationStatus is "applied" or "skipped" or "not_required" || snapshot.Operation == "none")
            return new(PipelineMutationDisposition.Complete,
                $"Latest mutation {snapshot.MutationId} is already terminal ({snapshot.MutationStatus}/{snapshot.Operation}).");

        if (snapshot.MutationStatus != "planned" || snapshot.Operation != "reindex_candidate")
            return new(PipelineMutationDisposition.HaltedExecution,
                $"Unexpected mutation state operation={snapshot.Operation}, status={snapshot.MutationStatus}.");

        if (snapshot.QueueStatus != "completed" ||
            snapshot.EventVersion != snapshot.WorkerVersion ||
            snapshot.CompletedVersion != snapshot.WorkerVersion)
        {
            return new(PipelineMutationDisposition.WaitingForWorker,
                $"Candidate queue is not quiescent at worker version {snapshot.WorkerVersion}: queue={snapshot.QueueStatus}, event={snapshot.EventVersion}, completed={snapshot.CompletedVersion}.");
        }

        if (snapshot.NonPlannedActionCount != 0)
            return new(PipelineMutationDisposition.HaltedExecution,
                $"Mutation {snapshot.MutationId} has {snapshot.NonPlannedActionCount} action(s) outside planned state while the mutation itself is planned.");

        if (snapshot.ActionCount == 0)
            return new(PipelineMutationDisposition.NeedsActions,
                $"Mutation {snapshot.MutationId} needs Step 10A concrete action planning.");

        if (snapshot.MissingPayloadCount > 0)
            return new(PipelineMutationDisposition.NeedsPayloads,
                $"Mutation {snapshot.MutationId} needs {snapshot.MissingPayloadCount} Step 10B payload(s).");

        if (snapshot.BlockedPayloadCount > 0)
            return new(PipelineMutationDisposition.BlockedPayload,
                $"Mutation {snapshot.MutationId} has {snapshot.BlockedPayloadCount} blocked payload(s); manual resolution is required and no Solr write is allowed.");

        if (snapshot.ReadyPayloadCount == snapshot.ActionCount)
            return new(PipelineMutationDisposition.ReadyForApproval,
                $"Mutation {snapshot.MutationId} has {snapshot.ActionCount} ready action(s) and is eligible for Step 11 preflight only.");

        return new(PipelineMutationDisposition.HaltedExecution,
            $"Mutation {snapshot.MutationId} has an inconsistent action/payload count.");
    }
}
