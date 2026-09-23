# Step 14A acceptance — read-only cross-candidate legacy Solr ID collision audit

## Purpose

Before widening the pilot beyond candidate `1180097`, audit the known legacy Solr unique-key risk:
the active legacy ID algorithm derives `id` from the **file name only**, not from the candidate ID or
full path. Two different candidate files can therefore generate the same unique key and one can
replace the other in Solr.

Step 14A is deliberately read-only:

- FLOSVR01: directory/file metadata and names only; no document-content reads.
- Solr: schema and unique-key ownership queries using HTTP GET only.
- MariaDB: no connection.
- No Solr update/delete/add/commit request exists in this command.
- Candidate scope is bounded by `--candidate-limit` or an explicit `--candidate-ids` list.
- Solr per-ID GETs are bounded by `--max-id-lookups` (default 1000, hard cap 5000).

## Build gate

```powershell
.\Restore-And-Preview.cmd
```

Expected:

```text
Build succeeded.
0 Warning(s)
0 Error(s)
Self-tests: 95/95 passed; 0 failed.
```

The nine Step 14A self-tests cover controlled candidate selection, explicit selection, cross-candidate
collisions, within-candidate collisions, current Solr ownership conflicts, safe matching ownership,
legacy repository-root aliases, true same-candidate path conflicts and the lookup cap.

## First controlled run

Keep the Step 13 SSH tunnel/supervisor running so the normal operational environment stays healthy;
Step 14A itself talks directly to the approved Solr HTTP endpoint and does not use MariaDB.

```powershell
.\Solr-Collision-Audit.cmd 10
```

Equivalent explicit command:

```powershell
$root = "\\FLOSVR01\FastTrack\Candidate\To 1189999"

dotnet .\src\WazuhAuditImporter\bin\Debug\net9.0\WazuhAuditImporter.dll `
  solr-collision-audit `
  --worker-root "$root" `
  --candidate-limit 10 `
  --max-id-lookups 1000 `
  --report-dir ".\solr-collision-audit-reports"
```

Automatic selection seeds the configured pilot candidate (`1180097`) when accessible, then adds the
first numeric candidate folders encountered until the limit is reached. The selected IDs are printed
and recorded in the report. For a reproducible reviewed batch, rerun using exact IDs:

```powershell
dotnet .\src\WazuhAuditImporter\bin\Debug\net9.0\WazuhAuditImporter.dll `
  solr-collision-audit `
  --worker-root "$root" `
  --candidate-ids "1180097,1180100,1180112" `
  --max-id-lookups 1000 `
  --report-dir ".\solr-collision-audit-reports"
```

## Findings

The audit reports four blocking safety categories plus one non-blocking path-alias category:

1. `cross_candidate_disk_collision` — two or more audited candidates generate the same legacy Solr ID.
2. `within_candidate_disk_collision` — two files in one candidate generate the same legacy ID.
3. `existing_solr_owner_different_candidate` — an audited disk file's generated ID is already owned
   in current Solr by another candidate, including candidates outside the controlled disk subset.
4. `existing_solr_same_candidate_different_path` — the generated ID exists for the same candidate and
   points to a genuinely different file name/subfolder inside that candidate folder.
5. `existing_solr_same_document_root_alias` — non-blocking. Candidate ID, legacy ID and the path inside
   the candidate folder all match, but the repository root differs (for example `G:\Candidate`,
   `\\FLOSVR01\Candidate` or `\\FLOSVR01\FastTrack\Candidate`). This is retained in JSON/CSV for
   evidence but does not make `SafeToExpandScope` false.

The JSON report contains all selected candidates and all findings. The CSV contains one row per
collision/conflict file for review.

## Pass / review decision

A completed audit always exits normally even when findings exist; findings are an audit result, not a
runtime failure. Use the report field and console summary:

```text
SafeToExpandScope : True|False
```

`True` means no collision/ownership conflict was found **inside that controlled batch and against the
current Solr owner for every generated ID in that batch**. It does not prove unscanned FLOSVR01
folders are collision-free.

`False` means Step 14B scope expansion is blocked for review. Do not auto-apply or widen the worker
scope until the legacy-ID collision strategy is resolved.

## Lookup-cap behavior

If the selected candidate folders contain more unique eligible IDs than `--max-id-lookups`, Step 14A
stops before the per-ID Solr ownership pass and tells the operator to audit a smaller batch or
explicitly raise the cap (maximum 5000). It never silently truncates the ownership audit.

## No production mutation

Step 14A does not change Step 13 scheduled-task behavior, Wazuh configuration, MariaDB state, worker
scope, candidate snapshots or Solr state.
