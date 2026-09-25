# Step 21 acceptance — remaining bounded SmallDrift

## Scope and expected evidence

| Candidate | Eligible files | Current Solr documents | Matches | Missing / index | Stale / delete | Other |
|---|---:|---:|---:|---:|---:|---:|
| 1180003 | 2 | 2 | 0 | 2 | 2 | 0 |
| 1180006 | 2 | 2 | 0 | 2 | 2 | 0 |
| 1180016 | 1 | 2 | 0 | 1 | 2 | 0 |
| 1180017 | 1 | 2 | 0 | 1 | 2 | 0 |

Begin with 1180003 and finish/verify it before moving to 1180006, 1180016, then
1180017. These counts are eligibility bounds, not an approval of any path or ID.
Both stale Solr documents require exact individual review. There is no inferred
rename pairing. Moderate/high drift and stale captures remain outside Step 21.

Approval requires an unchanged pending baseline fingerprint; exact comparison
counts; distinct candidate-scoped paths; exact generated IDs for missing files;
actual distinct delete IDs; no index/delete overlap, traversal, collision, or
other comparison conflicts. Each missing file must have a validated extractor:
`.txt`, `.html`, `.htm`, `.doc`, `.docx`, `.docm`, `.rtf`. PDF remains blocked.
Extension support does not prove content completeness: review every Step 10B
payload later. Unsupported or changed evidence stays gated; never substitute a
different approval command to bypass Step 21.

## 1. Deploy and build on MGMTNB08

Extract `WazuhAuditImporter_NET9_Step21.zip` into a separate staging directory.
Keep your current project as a backup. Stop the running importer before replacing
its source or rebuilding:

```powershell
# In the existing WazuhAuditImporter project folder, elevated PowerShell:
.\Step13-Stop.cmd
Start-Sleep -Seconds 3
Get-ScheduledTask -TaskName 'WazuhAuditImporter-Step13' | Select-Object TaskName, State
```

Require the stop script to report task/processes stopped and the task to be
`Ready`. Copy the files listed in `docs/STEP21_CHANGED_FILES.txt` from the extracted
project into the corresponding paths in the existing project. Copy only the
listed source/scripts/docs; preserve local configuration, secrets, reports,
worker state, scheduled-task registration and runtime directories. The full
source package also contains the unchanged reference files/configurations.
Do not overwrite locally customized configuration with packaged examples.

```powershell
.\Restore-And-Preview.cmd
```

Required gate: restore/build success, zero build errors, **166/166 self-tests
passed**, and successful sample preview. Self-tests make no database/Solr
connections. Do not start a failed build. The authoring workspace could parse
C# syntax and inspect the package but could not execute .NET; this Windows gate
is required before using the new commands.

After successful build:

```powershell
Start-ScheduledTask -TaskName 'WazuhAuditImporter-Step13'
Start-Sleep -Seconds 30
.\Step13-Status.cmd
.\Step16-Preflight.cmd
.\Step21-Review-SmallDrift.cmd 1180003
```

Step 16 approved rows must say `counts_source=stored_baseline live_checked=false`.
These are capture-time counts, not a new live Solr check. JSON uses `CountsSource`
and `LiveStateChecked`; CSV and Markdown label these too. Pending baselines still
receive live revalidation. No captures or approvals are rewritten by this change.

## 2. Review exact evidence before individual baseline approval

The Step 21 review and default approval preview read MariaDB plus FLOSVR01
metadata/Solr GET. Review writes local JSON, CSV and Markdown only. Inspect every
missing current path, expected ID/extractor, stale path and actual delete ID.
For 1180003 expect two indexes plus two deletes, and `step21_approval=YES`.
A `NO` report explains the reason; a completed read-only report is not approval.

Use the SHA-256 from the new review, not a copied historical hash. Replace the
placeholder below with that exact reviewed value:

```powershell
$reviewedSha = 'PASTE_SHA256_FROM_THE_NEW_REVIEW'
.\Step21-Approve-SmallDrift.cmd 1180003 $reviewedSha
```

After exact operator review of the preview, the separate enrollment action is:

```powershell
.\Step21-Approve-SmallDrift.cmd 1180003 $reviewedSha --ack-small-drift --apply
```

This records approval in MariaDB only. It neither creates a Solr repair nor
executes a mutation. No batch approval is available. A changed capture, conflicting
ID/path, wrong shape, unsupported extractor or missing acknowledgement blocks
approval. A matching previously approved baseline produces an idempotent no-op.

## 3. Obtain a fresh candidate mutation

First inspect Step 13 status and the candidate's live recovery state. Enrollment
can initially be `Idle` with no mutation. The first observed event may establish
worker state and produce `not_required/none`; that terminal state does not mean
historical Solr drift is repaired.

If a fresh event is needed, use the established unique, nonempty `DNI_` marker
workflow. Create one marker, wait for collection, and inspect the result before
creating another. Keep all markers in place: deleting them creates more events.
If events arrive in separate groups or a newer no-action mutation obscures a
planned one, inspect exact mutation IDs; never blindly apply the older plan.
The settled-trigger procedure used in Step 19 is available: stop Step 13, verify
it stopped, create one unique marker, wait 90 seconds, restart, then inspect.
Example marker creation, only after deciding a fresh event is needed:

```powershell
$candidate = '1180003'
$folder = Join-Path '\\FLOSVR01\FastTrack\Candidate\To 1189999' $candidate
$trigger = Join-Path $folder ("DNI_STEP21_{0}_RECON_{1}.txt" -f $candidate, [guid]::NewGuid().ToString('N'))
$bytes = [Text.Encoding]::ASCII.GetBytes("Step 21 reviewed reconciliation trigger for $candidate`r`n")
$stream = [IO.File]::Open($trigger, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
try { $stream.Write($bytes, 0, $bytes.Length) } finally { $stream.Dispose() }
Get-Item -LiteralPath $trigger | Select-Object FullName, Length, LastWriteTimeUtc
```

Continue only with the actual new mutation ID/version shown in the latest status.
Never assume an ID from sequence numbers. Step 13 can plan/build/preflight; it
never performs the Solr apply.

## 4. Review payloads, preflight, apply and verify

Use the new `solr-payloads-<candidate>-v<version>-*.json` report. Check its
`MutationId` matches the target; review all index content for completeness and
all delete IDs. For Word files, absence of evaluation notices alone is not proof
of complete text. Confirm status `ready` and expected extractors for every
payload. Do not use the old mutation 43 or any older unreviewed plan.

Run `solr-execute` for the actual mutation ID with worker root
`\\FLOSVR01\FastTrack\Candidate\To 1189999` and config
`.\importer.step15.pilot.json`, initially **without `--apply`**. Require the exact
reviewed action set, no source/payload drift and `PREFLIGHT PASS`. Then explicitly
apply that same mutation after operator review. Solr updates are ordered and are
not a cross-request database transaction; inspect failures before any retry.

Finally run `recovery-inspect --candidate-id <id>` with the same worker root and
config. Require `status=applied`, all expected actions applied, `HealthyTerminal`,
and missing=0, stale=0, other=0. Expected final matches/Solr count: 2 for
1180003/1180006 and 1 for 1180016/1180017. Check Step 13 shows Complete for the
actual applied mutation. Then move to the next candidate.

## Scope preservation and verification record

Step 17/18/19/20 services, the Step 20 non-greedy banner cleanup, database schema,
FIM allowlist, execution gates, scheduling and configurations are preserved.
No baseline approvals, source writes or Solr writes were performed to author
this package. Runtime/live Step 21 acceptance is pending MGMTNB08 deployment.

Previous Step 20 accepted on MGMTNB08: candidate 1180019, mutation 44/version 6,
one index action 38, payload 1,480 characters/205 words, post-commit verification
PASS, HealthyTerminal, eligible=2/solr=2/match=2/missing=0/stale=0. Mutation 43
remains unapplied.
