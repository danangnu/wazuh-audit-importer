# Step 14C — candidate baseline enrollment / review gate

Step 14C keeps the Step 14B five-candidate allowlist but adds an explicit **baseline enrollment gate** before any newly allowlisted candidate can reach Step 10A concrete Solr action planning.

This addresses the rollout behavior proven in Step 14B: an innocuous Wazuh event can correctly trigger a full candidate reconciliation and expose older Solr drift that predates the event. That is desirable for synchronization, but a newly enrolled candidate must not immediately generate destructive delete/index work from historical drift without an operator first reviewing its starting state.

## Safety model

For every allowlisted candidate, Step 14C captures a metadata-only baseline:

```text
FLOSVR01 metadata
      +
Solr GET-only candidate state
      ↓
candidate_baseline_enrollment
status = pending
baseline_sha256 = reviewed-state fingerprint
      ↓
BASELINE_REVIEW_REQUIRED
```

While a candidate baseline is `pending`:

- Wazuh collection continues.
- candidate worker reconciliation and version tracking may continue.
- no Step 10A concrete actions are planned.
- no Step 10B payloads are built.
- no Step 11 preflight or `--apply` is allowed.
- direct/manual Step 10A, Step 10B and Step 11 calls are also blocked by the baseline gate.

Only explicit operator approval of the exact SHA-256 baseline changes the candidate to `approved`.

Approval itself changes **MariaDB review state only**. It does not write Solr.

## New MariaDB tables

Run `sql/015_create_candidate_baseline_enrollment.sql` before starting the Step 14C binary.

The migration adds:

- `candidate_baseline_enrollment` — current candidate enrollment/review state.
- `candidate_baseline_enrollment_history` — append-only capture/approval audit trail.

The migration does not touch application candidate tables and does not call Solr.

## Build gate

Stop the Step 13 scheduled pipeline first so the running `dotnet.exe` does not lock the Debug DLL:

```powershell
Stop-ScheduledTask -TaskName "WazuhAuditImporter-Step13" -ErrorAction SilentlyContinue
powershell.exe -NoProfile -ExecutionPolicy Bypass -File ".\ops\Stop-Step13.ps1"
Start-Sleep -Seconds 3
```

Merge Step 14C, run the SQL migration, then:

```powershell
.\Restore-And-Preview.cmd
```

Expected offline gate:

```text
Build succeeded.
0 Warning(s)
0 Error(s)
Self-tests: 108/108 passed; 0 failed.
```

## Capture all five pilot baselines

With the Step 14B pilot config still active:

```powershell
.\Step14C-Baseline-Capture.cmd
```

This reads file metadata and Solr with GET only, then stores one `pending` review record for each candidate. It never reads document content and never writes Solr.

Expected status can be inspected with:

```powershell
.\Step14C-Baseline-Status.cmd
```

Based on the Step 14B acceptance evidence, candidates `1180001` and `1180097` should currently be clean/MATCH baselines, while `1180000`, `1180002` and `1180003` may show pre-existing MISSING/STALE drift. Do not approve the drifted candidates merely to clear the gate; review their baseline reports first.

## Approve an exact baseline

First run an approval preview using the SHA shown by `Step14C-Baseline-Status.cmd`:

```powershell
.\Step14C-Baseline-Approve.cmd 1180001 <baseline-sha256>
```

The command performs a fresh metadata/Solr GET recapture and refuses approval if the live fingerprint differs from the reviewed capture.

If the preview passes, record approval:

```powershell
.\Step14C-Baseline-Approve.cmd 1180001 <baseline-sha256> --apply
```

Approval stores the Windows reviewer identity in MariaDB and does not call Solr.

Repeat only for candidates whose starting baseline has actually been reviewed and accepted.

## Start the Step 13 supervisor again

```powershell
Start-ScheduledTask -TaskName "WazuhAuditImporter-Step13"
Start-Sleep -Seconds 8
.\Step13-Status.cmd
```

Pending candidates should show:

```text
BaselineReviewRequired
```

Approved candidates continue through the existing Step 14B per-candidate flow:

```text
Wazuh event
→ worker reconciliation
→ Step 10A
→ Step 10B
→ Step 11 preflight
→ ReadyForApproval
→ separate explicit Step 11 --apply
```

The supervisor never auto-applies Solr mutations.

## Direct command hardening

Step 14C also gates manual commands. For a baseline-pending candidate these commands must refuse to proceed:

```text
solr-plan-actions
solr-build-payloads
solr-execute (preflight or --apply)
```

This prevents bypassing the orchestration gate by running Step 10/11 manually.

## Acceptance target

Step 14C passes when:

1. migration is present and schema guard passes;
2. 108/108 offline tests pass;
3. all five baseline captures are stored as `pending` initially;
4. a pending candidate remains `BaselineReviewRequired` even when a Wazuh event creates/updates its worker mutation;
5. direct Step 10A/10B/11 calls for that candidate are blocked;
6. approval preview refuses a stale/wrong baseline SHA;
7. exact live SHA approval changes only MariaDB enrollment state;
8. an approved candidate can resume the normal approval-gated reconciliation flow;
9. no automatic Solr apply is introduced.

See `docs/STEP14C_ACCEPTANCE.md` for the detailed test sequence.
