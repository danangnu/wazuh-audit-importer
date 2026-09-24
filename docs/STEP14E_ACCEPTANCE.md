# Step 14E acceptance — pilot metrics and delivery report

## Purpose

Produce a reproducible, read-only summary of the event-driven Wazuh-to-Solr pilot without overstating the evidence.

## A. Build gate

Stop Step 13 before replacing/building the Debug DLL and require:

```text
122/122 offline self-tests PASS
0 build warnings
0 build errors
```

No Step 14E database migration is required.

## B. Recovery/safety preflight

Run:

```powershell
.\Step14D-Preflight.cmd
```

Pass criteria:

- no unexplained `UncertainProcessing`, `UncertainFailed`, or `Inconsistent` latest mutation;
- pending baseline candidates remain pending;
- approved candidates remain readable;
- no Solr writes occur.

## C. Generate report

Run:

```powershell
.\Step14E-Report.cmd
```

Pass criteria:

- JSON metrics file is generated;
- CSV mutation-timing file is generated;
- Markdown delivery report is generated;
- current live FLOSVR01/Solr state is queried using metadata + GET only;
- no source content is read by the reporting command;
- no MariaDB application row is changed;
- no Solr update/delete/add/commit request occurs.

## D. Timing integrity

The report must distinguish these stages when timestamps are available:

```text
event → MariaDB ingest
ingest → worker mutation plan
event → worker mutation plan
worker mutation plan → payload ready
event → ready for approval
ready for approval → verified apply
event → verified apply
```

`ready → verified apply` must be labeled as including deliberate operator/human wait.

`applied_at_utc` may be treated as verified apply time because Step 11 writes the applied status only after Solr POST/commit and post-commit GET verification succeed.

## E. Version mapping

Mutation `worker_version=N` maps to the Nth unique audit event for the same source/agent/candidate ordered by `audit_event_id`.

This is valid for the pilot because:

- one accepted unique audit event increments the candidate queue version once;
- duplicate/replay events are deduplicated and do not increment the queue version;
- a worker may collapse several pending events by claiming the latest version, which is why metrics map to the event matching the mutation's exact worker version.

If a mutation cannot be mapped to its corresponding event version, timing fields remain unavailable rather than being invented.

## F. Legacy scan comparison

Default pass criteria:

```text
no legacy speedup claim
```

because the WazuhAuditImporter database contains no measured old-scanner timing.

If an operator supplies:

```powershell
.\Step14E-Report.cmd <measured_legacy_seconds>
```

then the report may show an approximate reference ratio against observed p50 `event → ready for approval`, but must state that the legacy timing is operator-supplied and not a controlled benchmark.

## G. Delivery report content

The Markdown report must include:

- five-candidate pilot scope;
- approval-gated safety boundary;
- current baseline status and current live disk/Solr reconciliation per candidate;
- persisted audit/mutation/action/payload counts;
- observed latency table with sample counts;
- explicit legacy-comparison limitation;
- Step 14D recovery/safety evidence;
- deferred candidate-source outage and production Solr GET-outage maintenance tests;
- recommendation to retain baseline gate, collision audit, explicit allowlist and manual Solr approval for broader rollout.

## H. Pass criteria

Step 14E passes when:

- 122/122 offline tests pass;
- Step 14D preflight remains clean;
- report generation succeeds;
- current candidate state is represented without hidden drift;
- latency metrics are derived only from stored timestamps;
- no unsupported speedup claim is made;
- all Step 14E operations are read/report only.
