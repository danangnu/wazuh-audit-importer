# Step 19 acceptance — third controlled SmallDrift batch

## Source evidence and scope

The September 24, 2026 Step 16 read-only triage on MGMTNB08 reported these **pending** baselines:

| Candidate | Eligible | Match | Missing | Stale | Other | Stored fingerprint matches live |
| --- | ---: | ---: | ---: | ---: | ---: | --- |
| 1180015 | 1 | 0 | 1 | 1 | 0 | true |
| 1180021 | 3 | 2 | 1 | 1 | 0 | true |
| 1180022 | 4 | 3 | 1 | 1 | 0 | true |

These counts select the fixed batch, but do not authorize approval or a Solr mutation. The Step 19 review and approval preflight recapture FLOSVR01 metadata and Solr GET evidence. Only candidates 1180015, 1180021, and 1180022 can use these commands. Preserve the Step 17 and Step 18 scopes, 25-candidate importer allowlist, and manual Solr apply gate.

Candidates with wider drift (such as 1180016 and 1180017), missing-only drift (1180019), stale capture (1180005), and high drift (1180008) remain outside Step 19. Candidate 1180023 also has wider drift. No Step 19 command may approve them.

The Step 16 triage prints stored baseline evidence for rows already marked `APPROVED`. Thus historical `missing=1, stale=1` values on approved candidates do **not** establish current Solr regression. Read-only `recovery-inspect` is the live check; Step 18 inspections of 1180011, 1180012, and 1180014 each showed `match=1, missing=0, stale=0` after their applied mutations.

## Deployment gate on MGMTNB08

1. From the existing installation folder, run `Step13-Stop.cmd` as Administrator and verify the scheduled task is no longer Running. Keep the original `ops/step13.local.json`, DPAPI secrets, worker state, and reports. Do not overwrite them with package defaults.
2. Deploy the Step 19 source beside the existing solution, then run `Restore-And-Preview.cmd`. Require the .NET 9 build, **all** self-tests, and sample preview to pass before restarting Step 13. The authoring workspace has no `dotnet`; runtime verification takes place on MGMTNB08.
3. Resume the task with `Start-ScheduledTask -TaskName 'WazuhAuditImporter-Step13'` and confirm `Step13-Status.cmd` reports a running supervisor, tunnel, and pipeline.

No schema migration or automatic Solr write is added. The package itself does not approve baselines or run live operations.

## Fresh review and individual approval

Run `Step19-Review-SmallDrift.cmd` for the fixed batch, or `Step19-Review-SmallDrift.cmd 1180015` for the first candidate. The review is read/report only. For each candidate, require `fingerprint_match=true`, `missing=1`, `stale=1`, `other=0`, `step19_approval=YES`, and manually verify the exact current-file path/expected ID and stale path/current ID. Stop on changed evidence.

Use only the SHA-256 printed by the fresh review. Preview `Step19-Approve-SmallDrift.cmd <candidate-id> <fresh-baseline-sha256>`; compare its paths and IDs with the review. After exact operator review, run `Step19-Approve-SmallDrift.cmd <candidate-id> <fresh-baseline-sha256> --ack-small-drift --apply`. This records **only** MariaDB baseline approval; it does not repair or write Solr. Process one candidate at a time.

## Reconciliation gate

On the approved candidate, create a unique legacy-filtered `DNI_STEP19_...` file using `CreateNew`; leave it present until processing completes. The first event can establish a worker snapshot (`operation=none`, `not_required`). Run read-only `recovery-inspect` and check live missing/stale counts before deciding whether a **different** second `DNI_` trigger is required. Never modify a real candidate file to create an event.

For `ReadyForApproval`, run `solr-execute --mutation-id <id>` **without** `--apply`. Confirm `PREFLIGHT PASS`, no source/payload drift, and exact reviewed actions: delete the stale document and index the current document. No `DNI_` action should appear. Only then may the operator run the exact `solr-execute --mutation-id <id> --apply`. Require post-commit GET verification and read-only `recovery-inspect` with `HealthyTerminal`, no failed actions, and `missing=0, stale=0` before moving on.

Leave Step 17/18/19 trigger files in place pending a separately reviewed cleanup; deleting them produces new FIM events. Any processing/failed/uncertain mutation is operator-blocked and must never be retried blindly.
