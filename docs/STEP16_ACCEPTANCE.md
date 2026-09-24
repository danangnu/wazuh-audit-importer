# Step 16 acceptance — baseline triage and controlled clean enrollment

## Objective

Classify the 25-candidate Step 15 cohort before approving any additional baseline. Step 16 does **not** bulk-approve candidates and does **not** perform automatic Solr writes.

## Triage classes

- `Approved`: already enrolled by an operator.
- `CleanPending`: pending capture still matches the live fingerprint and all eligible disk files match Solr (`missing=0`, `stale=0`, `other=0`, `match=eligible`). Only this class can use the Step 16 clean-only approval command.
- `SmallDrift`: a small missing/stale set; remains gated for individual review.
- `ModerateDrift`: larger missing/stale set; remains gated for explicit action review.
- `HighDrift`: unusually large historical/live discrepancy. The current policy flags a pending baseline when stale or total delta reaches 20, or when Solr has at least 20 documents and at least 5x the eligible disk count.
- `BlockingConflict`: non-missing/stale comparison conflicts or local legacy-ID conflicts exist.
- `StaleCapture`: the stored pending fingerprint no longer equals the live capture. Recapture and review before any approval.
- `MissingBaseline`: baseline capture is absent.

The triage categories are operational routing labels, not authorization to mutate Solr.

## Clean-only approval gate

`baseline-approve-clean` requires all of the following:

1. candidate is in the explicit Step 15 25-candidate allowlist;
2. stored baseline status is `pending`;
3. operator supplies the exact stored SHA-256 fingerprint;
4. stored evidence is clean;
5. live FLOSVR01/Solr evidence is recaptured immediately before approval;
6. live fingerprint still equals the reviewed stored fingerprint;
7. live evidence is still clean;
8. `--apply` is supplied explicitly.

Approval changes only MariaDB baseline enrollment state. It does not call Solr update/delete/add/commit APIs.

## Acceptance sequence

1. `Restore-And-Preview.cmd` — build and self-tests.
2. `Step16-Preflight.cmd` — operational checks plus read-only triage.
3. Review `baseline-triage-reports` and identify only `CleanPending` candidates.
4. Run `Step16-Approve-Clean.cmd <candidate> <sha>` without `--apply` first.
5. If preview is clean, rerun the exact command with `--apply`.
6. Approve candidates individually; never bulk-approve drifted candidates.
7. `Step16-PostApproval-Check.cmd` — confirm approval state and recovery safety.
8. Optional live proof: on one newly approved clean candidate, create a temporary non-empty eligible `.txt` file. The pipeline may reach `ReadyForApproval`, but must not write Solr automatically. Delete the temporary file without applying the reviewed mutation; a later reconciliation should supersede the stale plan.

## Expected pilot candidates

Step 15 evidence immediately before this package showed two pending candidates with live `MATCH` state: `1180013` and `1180020`. Step 16 must **revalidate** them; the prior observation is not sufficient for approval by itself.

Candidate `1180008` previously showed a very large stale Solr population and is expected to remain high-drift/gated unless the live state has materially changed.

## PASS criteria

- Build/self-tests pass.
- Triage command is read-only.
- Only exact live `CleanPending` candidates are clean-approval eligible.
- Drifted/conflicted/stale captures are rejected by `baseline-approve-clean`.
- Each approval is explicit, SHA-bound and live-revalidated.
- No Step 16 command automatically applies a Solr mutation.
