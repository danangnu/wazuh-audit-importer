# Step 18 acceptance — controlled SmallDrift expansion

## Selection

The last Step 17 read-only recovery report showed these **pending** candidates with one eligible FLOSVR01 file, one Solr document, one missing current document, one stale document and no other conflicts:

| Candidate | Live missing | Live stale | Step 18 disposition |
| --- | ---: | ---: | --- |
| 1180011 | 1 | 1 | Review individually |
| 1180012 | 1 | 1 | Review individually |
| 1180014 | 1 | 1 | Review individually |

Those counts are historical observations, not approvals. The new Step 18 review performs fresh metadata and Solr GET checks, including the stored baseline SHA-256. If a fingerprint or comparison changes, that candidate stays gated. No other candidate can use the Step 18 approval command. The Step 17 three-candidate scope and the 25-candidate FIM/importer allowlist remain unchanged. In particular, 1180008 remains pending and is outside this batch.

## Safety gates

1. Require an existing pending baseline and a matching live fingerprint.
2. Require exactly one eligible current file missing in Solr, one stale Solr document, zero other conflicts, and Step 16 `SmallDrift` classification.
3. Print the exact missing current path/expected Solr ID and stale path/current ID.
4. Preview individual approval without a MariaDB status or Solr write.
5. Require both `--ack-small-drift` and `--apply` to record baseline approval. This writes **only** MariaDB baseline enrollment.
6. Reconcile through the normal Step 10A/10B/11 workflow: review the exact actions and payloads, require Step 11 read-only `PREFLIGHT PASS`, then run an explicit separate `solr-execute --mutation-id <id> --apply` only after operator review.
7. Treat any processing/failed/uncertain Solr mutation as operator-blocked. Never blindly retry; inaccessible candidate folders are never treated as empty.

No schema migration or automatic Solr apply is added.

## Deployment and static gate

On MGMTNB08, stop the Step 13 task/supervisor before copying and building the Step 18 source. Keep `ops/step13.local.json`, secrets, worker state, and local reports from the existing installation. Run the existing `Restore-And-Preview.cmd`; require a successful .NET 9 build and all self-tests passing before resuming Step 13. This package was inspected statically in the authoring workspace; that workspace did not have `dotnet`, so the MGMTNB08 build and self-tests are mandatory.

## Read-only review

```powershell
.\Step18-Review-SmallDrift.cmd
```

For every selected candidate, require `fingerprint_match=true`, `missing=1`, `stale=1`, `other=0`, `step18_approval=YES`, and exact expected/current document identities. A single candidate can be rechecked with `.\Step18-Review-SmallDrift.cmd 1180011` (or 1180012/1180014). Review only; no baseline approval or Solr write.

## One candidate at a time

Use only the SHA-256 printed in the *fresh* Step 18 review:

```powershell
.\Step18-Approve-SmallDrift.cmd 1180011 <fresh-baseline-sha256>
```

The preview must revalidate the same exact evidence. After operator review:

```powershell
.\Step18-Approve-SmallDrift.cmd 1180011 <fresh-baseline-sha256> --ack-small-drift --apply
```

This approval does not repair Solr. Check baseline status and recovery state. A first worker event can establish a worker snapshot with `operation=none`; a duplicate event can also be `not_required`. Do not mistake `Complete` for Solr reconciliation. If a controlled inventory change is needed, create one uniquely named legacy-filtered `DNI_...` file, keep it present until its worker version is complete, inspect the mutation and snapshot, then create a second distinct filtered trigger only if the first event merely established a baseline and the drift still remains. Do not modify a real candidate document to force a trigger.

For each resulting `ReadyForApproval` mutation, run Step 11 **without** `--apply` and confirm that its only actions are the reviewed stale deletion and current-file index, with no `DNI` actions. The Step 10A action list and Step 11 preflight are the authoritative write review; the Step 18 baseline report is not a Solr-write authorization. After explicit apply, require commit, post-commit GET verification and a read-only `recovery-inspect` showing `match=1, missing=0, stale=0` before moving to the next candidate.

Leave Step 17 and Step 18 trigger files in place until a separate controlled cleanup is reviewed. Removing them causes new file events.
