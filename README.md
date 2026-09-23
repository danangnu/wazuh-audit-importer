# Step 12 — Approval-gated continuous orchestration

Step 12 turns the validated pilot components into one continuous operational pipeline while
keeping the Solr write boundary manual.

The fixed pilot scope remains:

```text
Filesystem source : \\FLOSVR01\FastTrack\Candidate\To 1189999
Candidate         : 1180097
Wazuh agent       : 001 / FLOSVR01
Wazuh Indexer     : https://127.0.0.1:19200 through the local SSH tunnel
Solr endpoint     : http://192.168.18.22:8983/solr/AlliedSolrCore
Canonical root    : G:\Candidate\To 1189999
MariaDB           : 127.0.0.1:3306 / wazuh_audit_poc on MGMTNB08
```

Mutation 5 from Step 11 has already been applied and verified. Step 12 is intended to handle the
**next** Wazuh event/version automatically through preparation and preflight.

## What Step 12 does

`pipeline` / `pipeline-once` run the following chain:

```text
Wazuh Indexer collection
        ↓
MariaDB audit_event + candidate queue
        ↓
Candidate metadata reconciliation
        ↓
Step 8 candidate mutation plan
        ↓
Step 10A concrete Solr actions
        ↓
Step 10B exact reviewed payloads
        ↓
Step 11 PRE-FLIGHT ONLY
        ↓
READY_FOR_APPROVAL mutation_id=N
```

Step 12 **never calls the Solr update API**. It does not delete, add, update or commit Solr. An
operator must still explicitly run Step 11 `solr-execute ... --apply` for the exact approved
mutation.

This keeps the current production-hardening step useful without turning a filesystem event into an
unattended Solr write.

## Important Step 12 correction: same-path content changes

The previous path-based Step 10A reconciliation handled add/remove/rename correctly, but a file
whose contents changed while its path and legacy Solr ID stayed the same could still appear as
`MATCH`. The legacy `last_update` field is index time, not source-file mtime, so it cannot safely be
used to infer source drift.

Step 12 now carries the immutable worker `changes.changed` list from the Step 8 plan into Step 10A.
A changed, still-present, legacy-eligible file therefore creates:

```text
INDEX_DOCUMENT
reason=source_changed
```

Step 11 preflight uses the same immutable changed-file list when regenerating the live action plan,
so source/action drift protection remains intact.

## Production-hardening behavior

- A `FileShare.None` lock file in the persistent state directory prevents two Step 12 processes
  from using the same state directory simultaneously.
- Collector checkpoint behavior is unchanged; failures do not advance a failed window.
- Worker lease/version rules are unchanged.
- Inaccessible FLOSVR01 folders are never interpreted as empty.
- Step 10A/10B storage remains idempotent and conflict-detecting.
- Blocked payloads remain blocked and are never passed to an apply operation.
- A latest `processing` or `failed` mutation is an operator stop condition, not an automatic retry.
- `step12-pipeline-state.json` records the latest operational stage for simple monitoring/restart
  visibility. MariaDB remains authoritative.
- Transient DB/Indexer/Solr-GET failures are retried; Step 12 still never performs a Solr write.

No database migration is required for Step 12.

## 1. Build and offline tests

Copy/merge this package into the existing repository, then run:

```powershell
cd "C:\Users\dnurdiansyah\Documents\NewAllied\WazuhAuditImporter"
.\Restore-And-Preview.cmd
```

Expected:

```text
Build succeeded.
0 Warning(s)
0 Error(s)
Self-tests: 86/86 passed; 0 failed.
```

The new tests cover Step 12 configuration bounds, state decisions, and forced reindex of a
same-path changed file. They do not connect to MariaDB, Wazuh Indexer or Solr.

## 2. One-cycle validation

The SSH tunnel to the Wazuh Indexer must still be open:

```powershell
ssh -L 19200:127.0.0.1:9200 danang@<CURRENT-WAZUH-LAB-IP>
```

Then run:

```powershell
.\Pipeline-Once.cmd
```

Equivalent explicit command:

```powershell
$root  = "\\FLOSVR01\FastTrack\Candidate\To 1189999"
$state = "C:\Users\dnurdiansyah\Documents\NewAllied\WazuhAuditImporter\worker-state"

 dotnet .\src\WazuhAuditImporter\bin\Debug\net9.0\WazuhAuditImporter.dll `
    pipeline-once `
    --worker-root "$root" `
    --state-dir "$state" `
    --report-dir ".\pipeline-reports"
```

Because mutation 5 is already applied, if no new Wazuh event exists this can legitimately finish
with a terminal/complete latest mutation and zero worker items.

## 3. Continuous Step 12 pipeline

```powershell
.\Pipeline.cmd
```

or:

```powershell
$root  = "\\FLOSVR01\FastTrack\Candidate\To 1189999"
$state = "C:\Users\dnurdiansyah\Documents\NewAllied\WazuhAuditImporter\worker-state"

 dotnet .\src\WazuhAuditImporter\bin\Debug\net9.0\WazuhAuditImporter.dll `
    pipeline `
    --worker-root "$root" `
    --state-dir "$state" `
    --report-dir ".\pipeline-reports"
```

Press `Ctrl+C` for a clean stop.

The pipeline asks for the MariaDB and Wazuh Indexer passwords once. For a non-interactive future
service account, the existing environment variables remain supported:

```text
WAZUH_DB_PASSWORD
WAZUH_INDEXER_PASSWORD
```

Do not commit those values to Git.

## 4. Runtime test

For the cleanest new-file test, while `Pipeline.cmd` is running create another non-empty TXT under:

```text
C:\Shares-DFS\FastTrack\Candidate\To 1189999\1180097
```

Alternatively, modify the existing non-empty:

```text
WAZUH_SOLR_CONTENT_TEST.txt
```

A content-only modification should now result in Step 10A output similar to:

```text
PLAN INDEX_DOCUMENT ...
reason=source_changed
```

The pipeline should continue through Step 10B and Step 11 preflight and finish the prepared state
with:

```text
READY_FOR_APPROVAL mutation_id=<new-id>
```

At this point **no Solr write has happened**.

## 5. Manual approval remains Step 11

After reviewing the exact new mutation and its preflight output, actual Solr execution remains:

```powershell
dotnet .\src\WazuhAuditImporter\bin\Debug\net9.0\WazuhAuditImporter.dll `
    solr-execute `
    --mutation-id <new-id> `
    --worker-root "\\FLOSVR01\FastTrack\Candidate\To 1189999" `
    --apply
```

Then verify with `solr-readonly` as in Step 11.

## Step 12 local status

The persistent worker state directory also receives:

```text
step12-pipeline-state.json
step12-pipeline.lock
```

The JSON status records the last cycle/stage/mutation/version/detail. The lock file may remain on
disk after a crash, but the operating-system file lock is released automatically; the next process
can reuse the file. Do not delete it merely because the file exists.

See `docs/STEP12_ACCEPTANCE.md` for the acceptance criteria.
