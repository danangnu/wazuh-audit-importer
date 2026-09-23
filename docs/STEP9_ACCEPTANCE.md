# Step 9 acceptance — FLOSVR01 versus Solr read-only discovery

Step 9 is deliberately **read only**. It may enumerate file metadata beneath the
approved FLOSVR01 candidate root and issue HTTP GET requests to the approved Solr
core. It contains no Solr add/delete/update/commit/config operations and performs
no MariaDB writes.

## Fixed pilot scope

- Filesystem source of truth: `\\FLOSVR01\FastTrack\Candidate\To 1189999`
- Candidate: `1180097`
- Legacy local server path monitored by Wazuh:
  `C:\Shares-DFS\FastTrack\Candidate\To 1189999\1180097`
- Solr endpoint: `http://192.168.18.22:8983/solr/AlliedSolrCore`
- Solr canonical path root: `G:\Candidate\To 1189999`
- Expected unique key: `id`
- Candidate field: `dbcandno`
- Path field: `path`
- Timestamp field: `last_update`
- Content field is checked for schema presence but is never requested in candidate
  comparison results.

The endpoint and legacy field/path conventions are derived from the supplied
legacy indexing application/Paths.ini. The sensitive INI itself is not included
in this package.

## Run

From MGMTNB08 after building:

```powershell
$root = "\\FLOSVR01\FastTrack\Candidate\To 1189999"

dotnet .\src\WazuhAuditImporter\bin\Debug\net9.0\WazuhAuditImporter.dll `
    solr-readonly `
    --worker-root "$root" `
    --report-dir ".\solr-readonly-reports"
```

No MariaDB password or Wazuh Indexer password is required by this command.

## Expected checks

1. Solr schema API reports `uniqueKey=id`.
2. Required fields `id`, `dbcandno`, `path`, `last_update`, and `content` exist.
3. The command queries `dbcandno:1180097` using `GET /select` only.
4. FLOSVR01 paths are mapped relative to the explicit worker root onto
   `G:\Candidate\To 1189999` for comparison.
5. The active legacy filename-based ID algorithm is reproduced for diagnostics.
6. Results may include:
   - `MATCH`
   - `MISSING_IN_SOLR`
   - `STALE_IN_SOLR` (Solr path absent from current eligible FLOSVR01 files)
   - `ID_MISMATCH`
   - `DUPLICATE_SOLR_PATH`
   - `SKIPPED_BY_LEGACY_FILTER`
   - `POSSIBLE_ID_COLLISION` (within this candidate only)
7. `last_update` is displayed but is **not** compared against filesystem mtime to
   infer staleness because the legacy indexer sets it to indexing time.
8. Cross-candidate legacy-ID collision discovery is out of scope for Step 9.

## Safety acceptance

The Step 9 source must contain only `HttpClient.GetAsync` for Solr requests. It
must not contain calls to `/update`, delete commands, commit/optimize, POST/PUT/
DELETE/PATCH HTTP methods, SolrNet writes, or MariaDB changes in `solr-readonly`.

Before any future execution step, review the Step 9 report and the actual legacy
indexing behavior. Do not change existing Step 8 `planned` mutations to `applied`.
