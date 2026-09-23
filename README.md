# Step 14A — controlled cross-candidate legacy Solr ID collision audit

Steps 1–13 proved and operationalized the approval-gated FLOSVR01 → Wazuh → MariaDB → reconciliation
→ Solr pipeline for candidate `1180097`. Step 14A is the safety gate before broadening that scope.

The legacy indexer generates Solr `id` from the **file name only**. It does not include `dbcandno` or
the candidate path. Step 14A therefore audits a small candidate batch for filename-derived unique-key
collisions and checks the current Solr owner of every generated ID.

Step 14A is **read-only**:

```text
FLOSVR01 candidate folders
        ↓ metadata/name only
legacy filename → Solr ID algorithm
        ↓
cross-candidate grouping
        ↓
Solr unique-key GET ownership check
        ↓
JSON + CSV audit report
```

There is no MariaDB connection and no Solr update/delete/add/commit operation.

## 1. Merge and build

Merge this package into the current Step 13 repository, then:

```powershell
cd "C:\Users\dnurdiansyah\Documents\NewAllied\WazuhAuditImporter"
.\Restore-And-Preview.cmd
```

Expected build gate:

```text
Build succeeded.
0 Warning(s)
0 Error(s)
Self-tests: 95/95 passed; 0 failed.
```

## 2. Audit the first controlled batch

```powershell
.\Solr-Collision-Audit.cmd 10
```

This audits at most 10 candidate folders, including configured pilot candidate `1180097` when it is
accessible. Reports are written under:

```text
.\solr-collision-audit-reports
```

The command performs at most 1000 Solr unique-key GET lookups by default. If the batch has more than
1000 eligible unique IDs, it stops instead of silently producing a partial ownership audit.

## 3. Re-run a reproducible explicit batch

After the first run prints the selected candidate IDs, you can freeze the batch explicitly:

```powershell
$root = "\\FLOSVR01\FastTrack\Candidate\To 1189999"

dotnet .\src\WazuhAuditImporter\bin\Debug\net9.0\WazuhAuditImporter.dll `
  solr-collision-audit `
  --worker-root "$root" `
  --candidate-ids "1180097,1180100,1180112" `
  --max-id-lookups 1000 `
  --report-dir ".\solr-collision-audit-reports"
```

## 4. Interpret the result

Important finding types:

```text
cross_candidate_disk_collision
within_candidate_disk_collision
existing_solr_owner_different_candidate
existing_solr_same_candidate_different_path
existing_solr_same_document_root_alias   # non-blocking
```

For same-candidate ownership, Step 14A now compares the path *inside the candidate folder* rather than
treating repository-root spelling as document identity. Historical forms such as `G:\Candidate\...`,
`\\FLOSVR01\Candidate\...` and the current `\\FLOSVR01\FastTrack\Candidate\...` are reported
as a non-blocking root alias when they resolve to the same candidate-relative file name/subfolder.

The console and JSON report include:

```text
SafeToExpandScope : True|False
```

- `True`: no legacy-ID collision/ownership conflict was found for this audited batch. Continue with
  another controlled batch before Step 14B.
- `False`: hold scope expansion and review the JSON/CSV findings. Do not enable broader automatic
  candidate processing yet.

Even a `True` result applies only to the audited candidate batch; it is not a claim that all unscanned
candidate folders are collision-free.

See `docs/STEP14A_ACCEPTANCE.md` for the full acceptance procedure.

## Existing Step 13 operation

The Step 13 scheduled supervisor remains unchanged and approval-gated. Step 14A does not change the
Wazuh scope, worker scope, scheduled task, DPAPI secrets, SSH tunnel, MariaDB rows or Solr documents.
