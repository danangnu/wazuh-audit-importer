using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace WazuhAuditImporter;

public static class SolrPlanBuilder
{
    public static SolrPlanSpec Build(WorkerClaim claim, ReconciliationResult result)
    {
        if (!claim.CandidateId.Equals(result.CandidateId, StringComparison.Ordinal))
            throw new InvalidOperationException("Reconciliation candidate does not match the claimed work item.");

        var hasChanges = result.Added.Count + result.Removed.Count + result.Changed.Count > 0;
        var operation = result.IsBaseline || !hasChanges ? "none" : "reindex_candidate";
        var status = operation == "none" ? "not_required" : "planned";
        var reason = result.IsBaseline
            ? "baseline_established"
            : hasChanges ? "candidate_inventory_changed" : "no_inventory_change";

        // We intentionally plan a candidate-level reindex only. The existing Solr schema
        // (one document per file vs. one document per candidate) has not yet been supplied,
        // so Step 8 must not invent file-level Solr mutations or field names.
        var payload = new
        {
            schema_version = 1,
            source_instance = claim.SourceInstance,
            agent_id = claim.AgentId,
            candidate_id = claim.CandidateId,
            worker_version = claim.ClaimedVersion,
            operation,
            status,
            reason,
            changes = new
            {
                added = result.Added,
                removed = result.Removed,
                changed = result.Changed
            },
            solr_target = new
            {
                collection = (string?)null,
                unique_key_field = (string?)null,
                candidate_field = (string?)null
            },
            execution_supported = false,
            note = "Dry-run planner only. No Solr endpoint, collection, schema field, or document identity is assumed."
        };

        var planJson = JsonSerializer.Serialize(payload, new JsonSerializerOptions
        {
            WriteIndented = false
        });

        var keyMaterial = string.Join("\n",
            claim.SourceInstance,
            claim.AgentId,
            claim.CandidateId,
            claim.ClaimedVersion.ToString(System.Globalization.CultureInfo.InvariantCulture),
            operation,
            planJson);
        var hash = SHA256.HashData(Encoding.UTF8.GetBytes(keyMaterial));
        var key = Convert.ToHexString(hash).ToLowerInvariant();

        return new SolrPlanSpec(
            claim.SourceInstance,
            claim.AgentId,
            claim.CandidateId,
            claim.ClaimedVersion,
            operation,
            status,
            result.Added.Count,
            result.Removed.Count,
            result.Changed.Count,
            planJson,
            key);
    }
}
