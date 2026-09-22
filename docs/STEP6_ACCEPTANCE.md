# Step 6 acceptance — candidate reconciliation worker

Step 6 consumes `candidate_work_queue` but remains a dry-run with respect to Solr.
It reads **file metadata only** (relative path, length, last-write UTC) from one
explicitly mapped candidate root. It never opens file contents and never modifies
source files.

## Safety model

- Pilot remains restricted to source `wazuh-lab-pilot-01`, agent `001`, candidate `1180097`.
- `--worker-root` is mandatory. The worker does not assume that the FLOSVR01 local
  path is valid on MGMTNB08.
- Run `worker-preflight` before any queue claim.
- Missing/inaccessible folders cause failure/retry; they are never interpreted as
  an empty candidate.
- Queue work is claimed with a lease and a captured `claimed_version`.
- If new Wazuh events increment `event_version` while work is processing, completion
  advances only `completed_version` through the claimed version and leaves the row
  `pending` for another pass.
- Versioned snapshots are local worker state. The first successful worker run creates
  a baseline and deliberately does **not** label every pre-existing file as ADD.
- No Solr writes are implemented.

## 1. Discover the actual SMB mapping

On FLOSVR01, use a read-only share query:

```powershell
Get-SmbShare |
  Where-Object { $_.Path -like 'C:\Shares-DFS*' } |
  Select-Object Name, Path
```

Find the share whose local path contains the configured source root:

`C:\Shares-DFS\FastTrack\Candidate\To 1189999`

Construct the corresponding UNC worker root. Examples only:

- share path `C:\Shares-DFS\FastTrack`, share name `FastTrack` ->
  `\\FLOSVR01\FastTrack\Candidate\To 1189999`
- share path `C:\Shares-DFS`, share name `Shares-DFS` ->
  `\\FLOSVR01\Shares-DFS\FastTrack\Candidate\To 1189999`

Do not guess the share name.

## 2. Test Windows access from MGMTNB08

```powershell
$root = '\\FLOSVR01\<ACTUAL_SHARE_AND_SUBPATH>\To 1189999'
Test-Path -LiteralPath (Join-Path $root '1180097')
Get-ChildItem -LiteralPath (Join-Path $root '1180097') -File -ErrorAction Stop |
  Select-Object -First 5 Name, Length, LastWriteTime
```

Expected: `Test-Path` is `True` and metadata can be listed. If credentials or SMB
permissions fail, stop. Do not broaden permissions just for this test.

## 3. Worker preflight (no database write)

```powershell
dotnet .\src\WazuhAuditImporter\bin\Debug\net9.0\WazuhAuditImporter.dll `
  worker-preflight `
  --worker-root "$root"
```

Expected: candidate `1180097` reports `OK (<n> files visible)`. This command does
not claim or change the queue.

## 4. First work-once creates a baseline

Choose a persistent local state directory on MGMTNB08. Keep it out of Git:

```powershell
$state = 'C:\Users\dnurdiansyah\Documents\NewAllied\WazuhAuditImporter\worker-state'

dotnet .\src\WazuhAuditImporter\bin\Debug\net9.0\WazuhAuditImporter.dll `
  work-once `
  --worker-root "$root" `
  --state-dir "$state"
```

Expected first-run behavior:

- one due queue item is claimed;
- `BASELINE` is printed;
- one `snapshot-v<claimed_version>.json` is saved under the state directory;
- queue `completed_version` advances through the claimed version;
- status becomes `completed`, unless a newer event arrived while processing, in
  which case status remains `pending`;
- no ADD/REMOVE/CHANGE is inferred from history before the baseline;
- no Solr write occurs.

## 5. Validate real differences

Keep the continuous collector running. Make **one controlled test-file change** on
FLOSVR01 in candidate `1180097`, wait until the queue `event_version` increments,
then run `work-once` again with the same root and state directory.

Expected examples:

- create test file -> `ADD`
- modify test file -> `CHANGE`
- delete test file -> `REMOVE`
- rename -> normally `REMOVE old` + `ADD new`

The snapshot for the previous `completed_version` is the comparison baseline.

## 6. Verify queue state

```sql
SELECT work_item_id, candidate_id, status, event_version, claimed_version,
       completed_version, attempt_count, lease_token, lease_expires_at_utc,
       available_at_utc, last_error, updated_at_utc
FROM wazuh_audit_poc.candidate_work_queue
WHERE source_instance='wazuh-lab-pilot-01'
  AND agent_id='001'
  AND candidate_id='1180097';
```

After a successful pass with no newer event, expect:

- `status='completed'`
- `completed_version=event_version`
- claim/lease fields are NULL
- `last_error` is NULL

On source access failure, expect `status='retry'` and `last_error` populated; the
worker must not create a zero-file snapshot for that failure.


### Step 6.1 compatibility note
The worker must accept a MariaDB/MySqlConnector `lease_token` returned as either
`string` or `System.Guid` and normalize it before compare-and-set completion.
