# Step 11 — Controlled Solr execution

Step 11 adds the first command that can actually update Solr. It executes only a
specific, already reviewed Step 10A/10B mutation and keeps the pilot scope fixed:

```text
Filesystem source : \\FLOSVR01\FastTrack\Candidate\To 1189999
Candidate         : 1180097
Wazuh agent       : 001 / FLOSVR01
Solr endpoint     : http://192.168.18.22:8983/solr/AlliedSolrCore
Canonical root    : G:\Candidate\To 1189999
MariaDB           : 127.0.0.1:3306 / wazuh_audit_poc on MGMTNB08
```

The current reviewed test mutation is `mutation_id=5`, worker version `24`:

```text
order 1  delete_document  old stale resume                 READY
order 2  index_document   WAZUH_SOLR_CONTENT_TEST.txt      READY
blocked payloads: 0
```

## Safety model

`solr-execute` requires an explicit mutation id. Without `--apply`, it is a
read-only preflight. The preflight checks all of the following again immediately
before execution:

- mutation identity/scope and candidate queue version;
- every concrete action is still `planned`;
- every Step 10B payload is `ready`, unblocked and has a valid payload SHA-256;
- current FLOSVR01 inventory and current Solr GET state regenerate exactly the
  same deterministic Step 10A action plan;
- source-backed payloads regenerate byte-for-byte with the same source hash,
  extracted-content hash, file metadata, JSON and payload hash;
- the live Solr schema still has the approved unique key and required fields.

With `--apply`, MariaDB first atomically claims the selected mutation/actions as
`processing`. The tool then runs the live safety checks again before the first
Solr POST.

Actions are POSTed in reviewed order and followed by one explicit commit. The
final state is then verified with Solr GET requests and a complete candidate
reconciliation. Only after verification are mutation/action rows marked
`applied`.

Important: Solr does not provide a MariaDB-style transaction spanning several
HTTP update requests. A failure after the first POST can leave an uncertain or
partial Solr state. In that case the tool records `failed` on a best-effort basis
and tells the operator to inspect with read-only queries before any retry. It
never sends a Solr rollback because this is a shared core and rollback could
interfere with unrelated writers.

## 1. Build and offline tests

```powershell
cd "C:\Users\dnurdiansyah\Documents\NewAllied\WazuhAuditImporter"
.\Restore-And-Preview.cmd
```

Step 11 adds offline tests for ready-payload integrity, blocked-payload rejection,
payload/source drift and deterministic action-plan drift. Offline tests do not
connect to MariaDB or Solr.

No new database migration is required for Step 11. Existing
`solr_mutation_queue` and `solr_mutation_action` status/attempt/error fields are
used for execution tracking.

## 2. Run Step 11 preflight — no writes

For the currently reviewed mutation:

```powershell
$root = "\\FLOSVR01\FastTrack\Candidate\To 1189999"

dotnet .\src\WazuhAuditImporter\bin\Debug\net9.0\WazuhAuditImporter.dll `
    solr-execute `
    --mutation-id 5 `
    --worker-root "$root"
```

Or:

```powershell
.\Solr-Execute-Preflight.cmd 5
```

Expected shape:

```text
PREFLIGHT PASS.
NO SOLR WRITES. No MariaDB status rows changed.
```

Do **not** run `--apply` if preflight reports source drift, Solr/disk plan drift,
a blocked/missing payload, queue-version drift, schema drift or any unexpected
Solr identity/path state.

## 3. Controlled apply

Only after the same mutation passes preflight:

```powershell
$root = "\\FLOSVR01\FastTrack\Candidate\To 1189999"

dotnet .\src\WazuhAuditImporter\bin\Debug\net9.0\WazuhAuditImporter.dll `
    solr-execute `
    --mutation-id 5 `
    --worker-root "$root" `
    --apply
```

The convenience script adds an additional typed confirmation:

```powershell
.\Solr-Execute-Apply.cmd 5
```

The expected reviewed writes for mutation 5 are:

```text
DELETE id=1180097-2025-08-22-choi-arthur-resume
ADD    id=wazuh-solr-content-testtxt
COMMIT
GET verification
```

The indexed document must resolve to:

```text
dbcandno = 1180097
path      = G:\Candidate\To 1189999\1180097\WAZUH_SOLR_CONTENT_TEST.txt
```

## 4. Verify MariaDB execution state

After a successful apply, run:

```text
sql\014_verify_solr_execution.sql
```

Expected for mutation 5:

```text
solr_mutation_queue.status = applied
attempt_count              = 1
applied_at_utc              = non-null

all solr_mutation_action.status = applied
all action attempt_count        = 1
all applied_at_utc               = non-null
all last_error                   = NULL
```

If the command reports an uncertain/partial state, do not manually change these
statuses and do not rerun `--apply` until current Solr state has been inspected
with the read-only command.

## Existing Step 10B payload contract

The actual write body is the exact payload stored in `solr_action_payload`.
Step 11 does not regenerate a different write body after approval. It only
regenerates the expected payload as a drift check and requires it to match the
stored reviewed payload byte-for-byte.

For `.txt`, `.html` and `.htm`, Step 10B mirrors the supplied legacy
`ReadAllText` path. Word/PDF extraction remains blocked until the corresponding
legacy-compatible extractor is ported and validated.
