# Step 12 acceptance — approval-gated continuous orchestration

Step 12 combines the already validated Wazuh collector, candidate worker, Step 10A concrete
planning, Step 10B payload generation and Step 11 **preflight** into one bounded pipeline.
It deliberately does not call the Solr update API. Actual Solr execution remains the separate,
explicit Step 11 `solr-execute --mutation-id <id> --worker-root <root> --apply` command.

## Safety invariants

1. `pipeline` / `pipeline-once` do not accept `--apply` and contain no call to
   `SolrExecutor.Run(..., apply: true)`.
2. A single-instance lock file is held with `FileShare.None` in the persistent state directory;
   a second Step 12 process must fail rather than run concurrently on the same state directory.
3. Collector checkpoint semantics remain unchanged: a failed collection operation does not
   advance the checkpoint.
4. Candidate folders that are inaccessible are never interpreted as empty.
5. Worker queue lease/version rules remain unchanged; Step 10A/10B preparation occurs only for
   a quiescent completed worker version.
6. Step 10A/10B are idempotent. Existing immutable concrete actions/payloads are reused only when
   they match; conflicts stop/defer orchestration.
7. Any blocked Step 10B payload leaves the mutation unexecuted and reports `BlockedPayload`.
8. A latest `processing` or `failed` Solr mutation is treated as an operator stop condition. The
   orchestrator does not automatically retry an uncertain Step 11 execution.
9. `READY_FOR_APPROVAL` means Step 11 read-only preflight passed. It is not approval and does not
   cause a Solr write.
10. The local `step12-pipeline-state.json` is operational status only. MariaDB remains the
    authoritative audit/queue/mutation state.

## Content-change correction

Earlier Step 10A path reconciliation correctly handled add/remove/rename, but a same-path content
change could still look like `MATCH` in Solr because the legacy `last_update` field represents
index time rather than source-file mtime. Step 12 carries the worker's immutable `changes.changed`
list from `solr_mutation_queue.plan_json` into Step 10A. A still-present, legacy-eligible changed
file therefore produces:

```text
INDEX_DOCUMENT
reason=source_changed
```

Step 11 preflight regenerates the same forced-reindex action from the immutable worker plan, so
this additional behavior remains covered by the existing drift gate.

## Build acceptance

Run:

```powershell
.\Restore-And-Preview.cmd
```

Expected:

```text
Build succeeded.
0 Warning(s)
0 Error(s)
Self-tests: 86/86 passed; 0 failed.
```

The offline tests include Step 12 timing bounds, orchestration-state decisions and the
same-path changed-file forced reindex behavior. They do not connect to MariaDB, Wazuh Indexer or
Solr.

## Runtime acceptance — current state

Because mutation 5 has already been successfully applied, a first `pipeline-once` with no new
file event may legitimately report the latest mutation as terminal/complete.

```powershell
.\Pipeline-Once.cmd
```

No Solr update request may occur.

## Runtime acceptance — new non-empty TXT

With `pipeline` running, create a new non-empty `.txt` file under candidate `1180097`, or modify
the existing non-empty `WAZUH_SOLR_CONTENT_TEST.txt`. The pipeline should automatically:

```text
Wazuh collect
  -> candidate worker
  -> Step 10A concrete actions
  -> Step 10B reviewed payloads
  -> Step 11 preflight
  -> READY_FOR_APPROVAL mutation_id=<new id>
```

For a modification of the existing test TXT, Step 10A should now show an `index_document` action
with `reason=source_changed` even though the Solr path itself is still a MATCH.

At `READY_FOR_APPROVAL`, stop and review. Step 12 must not execute Solr. If approved, use the
separate Step 11 command with the exact reported mutation id.

## Blocked/failed acceptance

- Unsupported legacy extractors or empty documents: `BlockedPayload`; no Step 11 apply.
- Queue version changes during planning: defer/retry the newer version; no Solr write.
- Latest mutation `failed` or `processing`: `HaltedExecution` / operator block; no automatic retry.
- Indexer/Solr GET transient connectivity failure: retry after the configured delay without
  treating the candidate folder as empty or calling Solr update APIs.
