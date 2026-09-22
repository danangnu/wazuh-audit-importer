# Step 7.2 hotfix

Fixes the continuous worker no-work path: the queue SELECT data reader is now disposed before committing the transaction. This prevents MySqlConnector from raising `This MySqlConnection is already in use` when the worker polls an empty/due-free queue. No schema changes are required.

# Step 6 — candidate reconciliation worker pilot

Step 6 adds `worker-preflight` and `work-once`. It consumes the existing
`candidate_work_queue` but still performs **no Solr writes**.

The worker deliberately requires an explicit `--worker-root` because queue paths
such as `C:\Shares-DFS\...` are local paths on FLOSVR01 and must not be assumed to
exist on MGMTNB08. Use the actual SMB/UNC mapping approved for the file server.
Do not use a local test mirror to complete the real FLOSVR01 queue row.

The first successful `work-once` establishes a versioned baseline snapshot and
does not claim that all pre-existing files are ADD operations. Later passes compare
file **metadata only** (relative path, byte length, last-write UTC) and report
ADD / REMOVE / CHANGE. Reparse points are skipped and inaccessible files/folders
cause retry rather than being treated as missing.

Queue claims use the existing lease/version columns. Completion is compare-and-set
against the lease token. If `event_version` increases while a claim is processing,
only the claimed version is marked completed and the row remains `pending` for a
follow-up pass. Failed source access moves the owned claim to `retry` with a delay
and records `last_error`.

Worker snapshots are stored outside MariaDB as immutable/versioned local state:

`<state-dir>\<source>\<agent>\<candidate>\snapshot-v<version>.json`

A snapshot is written before queue completion. If DB completion fails, that file
is an orphan and is ignored because `completed_version` did not advance. A missing
snapshot for a nonzero completed version is a hard error; it is never interpreted
as an empty candidate.

No database migration is required for Step 6. See `docs/STEP6_ACCEPTANCE.md` before
claiming the current pending row.


## Step 4.1 duplicate replay correction

The live collector may replay an event that was first inserted from a dashboard export.
Dashboard-export JSON and direct Indexer `_source` can differ in nonessential wrapper or
enrichment fields even when the normalized event used by this application is identical.
Step 4.1 therefore verifies duplicate Wazuh IDs against the normalized persisted/actionable
fields rather than requiring byte-equivalent full source JSON. The first `raw_json` remains
unchanged as evidence. Differences in agent, candidate, path, event type, timestamp, rule,
owner/actor fields, size or SHA-256 still produce a conflict.

The collector intentionally commits each accepted event separately and advances the
checkpoint only after the entire polling window succeeds. If a later event fails, earlier
new events from that run may already be committed; replay is safe through deduplication.

# Wazuh Audit Importer — first database-import pilot

A separate .NET 9 solution for importing **one saved Wazuh FIM JSON event** into
`wazuh_audit_poc` on the local MariaDB server. This package does not overwrite the
existing `SolrAuditPoc` Step 2 project.

## Scope and safety

- Default: FLOSVR01, agent ID **"001"**, candidate **"1180097"** only.
- DB connection: **127.0.0.1:3306**, expected server **MGMTNB08**.
- Database is fixed to **wazuh_audit_poc**; existing SEEK/candidate databases are untouched.
- Preview is the default and does **not connect to MariaDB**.
- `--apply` writes to `audit_event` and `candidate_work_queue`, atomically.
- No database creation/migration, source-file reading/deletion, live collection,
  worker execution, Wazuh configuration change, or Solr writes.
- `collector_checkpoint` is verified but not written by this manual importer.
- Database password is requested in the terminal; not stored in JSON or passed
  as a CLI argument. Never send the password back to anyone.
- Keep this package in a private repository: the supplied sample contains
  internal paths, host/agent metadata, ACLs, and account/group names.

## Build and run on MGMTNB08

Extract this folder alongside the existing solution, for example:

`C:\Users\dnurdiansyah\Documents\NewAllied\WazuhAuditImporter`

In PowerShell in that directory:

```powershell
dotnet restore .\WazuhAuditImporter.sln
dotnet build .\WazuhAuditImporter.sln --no-restore
```

Stop on any restore/build failure. The first restore needs NuGet access.
This solution targets **net9.0**, matching the SDK used successfully for Step 2.
MySqlConnector is pinned to **2.6.2**; do not downgrade silently if restore fails.

Run the offline parser/scope tests (no database connection):

```powershell
dotnet run --project .\tests\WazuhAuditImporter.SelfTests --no-build
```

Preview the real deletion event supplied in the conversation:

```powershell
dotnet run --project .\src\WazuhAuditImporter --no-build -- import .\samples\wazuh-delete-sample.json
```

The file is your supplied dashboard export, reformatted, not a newly generated
alert. It contains event ID **1790045703.1555358**, agent **001**, candidate
**1180097**, event type **deleted**, mode **realtime**, and event time
**2026-09-22T02:55:03.623000Z**. Manager spelling **wahzuh-lab** is preserved.
File owner is **Administrators**; actor and actor process must be **null**.

Check the database identity, required columns/indexes and row counts:

```powershell
dotnet run --project .\src\WazuhAuditImporter --no-build -- check-db
```

Enter an authorized local MariaDB username and password at the prompts. Use an
account scoped to this audit schema; no user/account is created by the tool.
For this pilot it needs SELECT/INSERT on audit_event and SELECT/INSERT/UPDATE
on candidate_work_queue, plus visibility/read access for the schema guard.
No grant or broad privileged account change is performed here.

After the preview and check-db succeed, explicitly apply:

```powershell
dotnet run --project .\src\WazuhAuditImporter --no-build -- import .\samples\wazuh-delete-sample.json --apply
```

Run exactly the same apply command again. Expected: `DUPLICATE`; the stored
row and candidate event_version remain unchanged. `IMPORTED` on the first run
means the audit insert and queue update committed; it does not mean the
candidate was processed or its Solr record updated.

Open `sql/002_verify_sample_import.sql` in your SQL client for read-only
verification. On a previously empty pilot schema: one audit row, one pending
queue row with version 1, zero checkpoints. Replay changes none of these.
Auto-increment ID gaps are normal and not a failure.

## Optional configuration

Default settings are compiled in and also shown in `importer.example.json`.
To keep a non-secret local username setting, copy it to `importer.local.json`
and set DatabaseUser. Run with `--config .\importer.local.json`.
Do not add a Password property: unknown configuration keys are rejected.
Alternatively supply `--db-user YOUR_USERNAME`; this is not a password.
A process environment variable `WAZUH_DB_PASSWORD` is supported for controlled
automation, but the interactive prompt is preferred for this manual pilot.

The source-instance key must stay **wazuh-lab-pilot-01** between replays.
It identifies this installation, not an IP address or manager display name.
Choose a new source-instance namespace for a rebuilt/replaced Wazuh source.
Do not broaden CandidateIds/root until pilot acceptance and approval.

## Import contract

1. Accept a single UTF-8 JSON object (max 4 MiB), wrapped in `_source` or raw.
2. Require structured FIM fields, the syscheck source/group, allowed agent/name,
   a recognized added/modified/deleted event and explicit candidate/path scope.
3. Reject ambiguous/traversal paths, malformed scalar values, missing timezone,
   duplicate JSON keys, overlength fields and invalid SHA256 values. Ignore
   out-of-scope/non-FIM events without a database connection.
4. Parse the event timestamp (not `mtime_after`) with its stated offset; convert
   to UTC and truncate to DATETIME(6) precision. Preserve string IDs and raw JSON.
5. Ownership is mapped only to file_owner_name. Only explicit
   syscheck.audit.user.name / syscheck.audit.process.name populate actor fields.
   Reported hashes and sizes remain event metadata even for deletions.
6. Apply a strict SQL mode and UTC timezone to the new connection's session,
   not globally. Validate required schema before any INSERT.
7. Insert audit_event using the unique (source_instance, wazuh_event_id) key.
8. If the key already exists, compare the full source objects. Whitespace,
   object-key ordering and the outer search envelope do not matter. Arrays,
   strings and scalar source values do. Changed content raises CONFLICT.
9. For a genuinely new event, atomically insert/update one queue row per
   source/agent/candidate and increment event_version. Preserve an existing
   processing lease or retry backoff. The future worker must compare versions
   on completion and recover expired leases. That worker is **not included**.
10. Roll back both writes if the queue update fails. A duplicate does not advance
    version or re-open completed work. Missing/conflicting queue state is an error.

A duplicate comparison is deliberately conservative; a numerically equivalent
number with a different representation may still conflict. Do not overwrite
conflicts automatically. The first accepted full input is retained in raw_json;
separate columns for indexer `_index`/`_id` are not added to your existing schema.

## Limitations and recovery

This is a manually invoked importer, not a continuous collector. It accepts no
JSON arrays, NDJSON, remote URLs, or watch/tail inputs. Source-folder paths in
queue rows belong to FLOSVR01; they are not accessible Windows paths on MGMTNB08
by assumption. A later worker needs an approved access mapping.

No automatic retry is implemented yet. On a transient DB error, stop, inspect,
and replay the same event. A lost connection during COMMIT may have an unknown
commit outcome; replay checks the persisted event identity and source content.

MariaDB 10.1 compatibility remains a pilot validation target. LONGTEXT is used
instead of JSON; all SQL avoids JSON functions and SKIP LOCKED. The old DB
server still needs a separately planned supported-version migration before
production use. Do not upgrade/drop it for this importer test.

## Validation status

See `docs/VALIDATION.md`. Source/JSON/schema consistency checks were performed
when packaging. The provided C# self-tests, compilation, and live MariaDB
transaction tests must still be run in an environment with .NET/NuGet access.
No claim of a successful database import or live pipeline is made by this ZIP.

## Files

- src/WazuhAuditImporter — parser, CLI, schema guard and transactional repository.
- tests/WazuhAuditImporter.SelfTests — 46 offline parser/scope/worker-diff test cases.
- samples/wazuh-delete-sample.json — supplied real event, reformatted only.
- sql/002_verify_sample_import.sql — read-only verification queries.
- docs/DATABASE_ACCEPTANCE.md — explicit database acceptance checks.
- docs/REFERENCES.md — primary documentation consulted.

# Step 4 — live Indexer collector pilot

This revision adds a deliberately bounded `collect-once` command. It reads Wazuh
FIM alerts through the already tested local SSH tunnel at
`https://127.0.0.1:19200`, imports/deduplicates scoped events, and advances one
`collector_checkpoint` only after every returned page has been processed.

It does **not** run the candidate worker and does **not** write to Solr.

Prerequisite: keep this tunnel open in a separate terminal (use the current VM IP):

```powershell
ssh -L 19200:127.0.0.1:9200 danang@<CURRENT_WAZUH_VM_IP>
```

Build using the previously successful isolated-NuGet recovery launcher if normal
restore still conflicts. Then run:

```powershell
dotnet .\src\WazuhAuditImporter\bin\Debug\net9.0\WazuhAuditImporter.dll collect-once
```

Passwords are prompted without echo. `WAZUH_DB_PASSWORD` and
`WAZUH_INDEXER_PASSWORD` are supported for controlled automation, but do not
commit secrets to configuration files.

The first run uses a 24-hour lookback when no checkpoint exists and a ten-minute
overlap on later runs. Replay is expected and safe because `audit_event` has the
unique `(source_instance,wazuh_event_id)` key. The collector uses bounded
`from/size` pagination for this narrow pilot; if it reaches the configured page
limit it fails **without advancing the checkpoint** rather than silently
truncating the source.

For the current test history there are five scoped FIM events in the Indexer.
One of those deletion events was already manually imported. Therefore the first
collector run against the current database should normally see five accepted
alerts, insert the four missing events, treat one as duplicate, and leave one
queue row for candidate 1180097 with event_version 5. Exact `seen` can be higher
only if additional scoped events were generated after the documented tests.

Run `sql/003_verify_collector.sql` afterward. A second `collect-once` with no new
file activity should add no new audit rows and should not increment
`candidate_work_queue.event_version`; its overlap window may legitimately replay
already stored events as duplicates.


# Step 5 — continuous collector pilot

This revision adds the `collect` command. It repeatedly executes the same bounded,
checkpointed Indexer collection used by `collect-once`.

It remains intentionally limited to the configured FLOSVR01 / agent 001 / candidate
1180097 scope. It does not run the candidate worker and does not write to Solr.

Prerequisites:

1. Wazuh Agent/Manager/Indexer are running.
2. Keep the local SSH tunnel open, using the current Wazuh VM address:

```powershell
ssh -L 19200:127.0.0.1:9200 danang@<CURRENT_WAZUH_VM_IP>
```

3. Build/test the solution. If ordinary NuGet restore conflicts on this laptop,
   use `Restore-And-Preview.cmd` as previously validated.

Start continuous collection in a second PowerShell window:

```powershell
dotnet .\src\WazuhAuditImporter\bin\Debug\net9.0\WazuhAuditImporter.dll collect
```

or:

```powershell
.\Collect.cmd
```

The default successful poll interval is 10 seconds. Transient Indexer/SSH or
MariaDB connection failures wait 15 seconds and retry. A failed collection does
not advance the checkpoint. The next successful overlapping query deliberately
replays recent events; the unique event identity and normalized duplicate checks
prevent queue-version inflation.

Press Ctrl+C once for clean shutdown. The process finishes the current bounded
operation and then exits. Authentication/authorization errors, schema conflicts,
malformed Indexer data, and normalized event conflicts remain fatal rather than
being retried indefinitely.

Passwords are prompted once at startup and retained only in process memory for
the running collector. Environment variables remain available for controlled
automation, but secrets must not be committed to Git or configuration files.

New optional non-secret settings in `importer.example.json`:

- `CollectorPollSeconds` (default 10; pilot range 5-300)
- `CollectorRetrySeconds` (default 15; pilot range 5-300)

## Step 5 acceptance test

With `collect` running, create, modify, then delete one new test file inside the
approved candidate 1180097 folder. Each genuine event should print a `NEW` line
and increment the single queue row's event_version. Duplicate overlap events are
processed but suppressed from per-event console output; the cycle summary reports
the duplicate count.

Then test restart recovery:

1. Stop the collector with Ctrl+C.
2. Make one test-file change while it is stopped.
3. Start `collect` again.
4. Confirm the offline-period event is imported through the overlap/checkpoint
   query and the checkpoint advances only after success.

Do not broaden CandidateIds, run a candidate worker, or enable Solr writes as part
of Step 5.

## Step 6.1 lease-token compatibility fix

MariaDB stores `candidate_work_queue.lease_token` as `CHAR(36)`. Depending on
MySqlConnector GUID handling, a UUID-shaped value can be materialized as a
`System.Guid` rather than a `System.String`. Step 6.1 accepts either form and
normalizes it to the canonical `D` GUID string before lease validation.

This fixes the observed completion failure:

```text
System.InvalidCastException: Unable to cast object of type 'System.Guid' to type 'System.String'.
```

A failed Step 6 claim that already moved the queue row to `retry` does not
need to be reset manually. After the configured retry delay, run `work-once`
again. Any snapshot written before the failed completion is an orphan because
`completed_version` did not advance; the retry safely replaces the snapshot
for its newly claimed version before database completion.

# Step 7 — continuous candidate worker

This revision adds the `work` command. It uses the same worker lease/version/snapshot
logic validated by `work-once`, but repeats automatically until Ctrl+C is pressed.

Example on MGMTNB08:

```powershell
$root = "\\FLOSVR01\FastTrack\Candidate\To 1189999"
$state = "C:\Users\dnurdiansyah\Documents\NewAllied\WazuhAuditImporter\worker-state"

dotnet .\src\WazuhAuditImporter\bin\Debug\net9.0\WazuhAuditImporter.dll `
    work `
    --worker-root "$root" `
    --state-dir "$state"
```

Or use:

```powershell
.\Work.cmd "\\FLOSVR01\FastTrack\Candidate\To 1189999" `
    "C:\Users\dnurdiansyah\Documents\NewAllied\WazuhAuditImporter\worker-state"
```

Default timing:

- Queue poll: 5 seconds.
- Failed source item retry: 30 seconds (existing queue behavior).
- Continuous-loop retry after transient DB/source failure: 15 seconds.
- Worker lease: 120 seconds.

The continuous worker does **not** read file contents, modify source files, or write to
Solr. An inaccessible candidate folder is treated as a retryable error and is never
interpreted as an empty folder.

Keep the existing `worker-state` directory when upgrading from Step 6; completed
versioned snapshots are the reconciliation baseline.

See `docs/STEP7_ACCEPTANCE.md` and `sql/007_verify_continuous_worker.sql`.


## Step 7.2 hotfix

Initializes ClaimNext local variables explicitly so the compiler can prove they are assigned after the no-row return path. This preserves the Step 7.1 reader-disposal fix.
