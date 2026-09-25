# Step 20 — one missing document for 1180019

Step 20 selects only candidate `1180019` from the September 24 read-only Step 16 triage. A fresh review must show the unchanged pending fingerprint, exactly one missing current document, zero stale Solr documents, zero other conflicts, every other eligible file matched, and a file type supported by Step 10B. The September 25 review found the missing file is `.docx`. Its network hash matched the supplied file, but the saved Step 10B payload contained only 44 characters because the Aspose Evaluation Only banner cleanup matched greedily across repeated banners. The cleanup now uses non-greedy matching with a regression test that preserves document text between banners. Mutation 43 contains the truncated payload and must never be applied. Deploy the corrected source, pass MGMTNB08 restore/build/self-tests (148/148), then create and review a fresh payload before any Solr apply. See `docs/STEP20_ACCEPTANCE.md`. The 25-candidate allowlist and prior Step 17/18/19 scopes are unchanged.

## Earlier Step 19 expansion

Step 19 selects only 1180015, 1180021, and 1180022 from the latest read-only Step 16 triage. Start with `Step19-Review-SmallDrift.cmd`; each candidate requires a fresh matching fingerprint and exactly one missing and one stale document. Individual approval only records MariaDB enrollment. All later Solr changes still require reviewed Step 11 preflight and explicit manual apply. See `docs/STEP19_ACCEPTANCE.md`. Prior Step 17/18 policies and the 25-candidate FIM allowlist remain unchanged.

## Earlier Step 18 expansion

Step 18 adds a separate three-candidate review and individual baseline approval path for 1180011, 1180012 and 1180014. Start with `Step18-Review-SmallDrift.cmd`; approval previews are read-only, and approval `--apply` records only MariaDB enrollment. Every later Solr mutation still requires a reviewed Step 11 preflight and an explicit, separate `--apply`. See `docs/STEP18_ACCEPTANCE.md` for the rollout gates. The Step 17 batch and FIM allowlist remain unchanged.

## Step 17 reference

Step 17 keeps the existing 25-candidate Step 15 scope and introduces a deliberately narrow workflow for the first three `SmallDrift` baselines: `1180002`, `1180007`, and `1180009`.

It does **not** widen FIM, does **not** add a database migration, and does **not** enable automatic Solr apply. The initial Step 17 approval path accepts only an unchanged pending baseline with exactly one current document missing from Solr, exactly one stale Solr document, and zero other conflicts.

```powershell
.\Step17-Preflight.cmd
.\Step17-Review-SmallDrift.cmd
.\Step17-Approve-SmallDrift.cmd <candidate-id> <baseline-sha256>
.\Step17-Approve-SmallDrift.cmd <candidate-id> <baseline-sha256> --ack-small-drift --apply
.\Step17-PostApproval-Check.cmd
```

Expected build gate:

```text
Build succeeded.
0 Warning(s)
0 Error(s)
Self-tests: 136/136 passed; 0 failed.
```

Approval records enrollment in MariaDB only. **It does not repair historical Solr drift.** Any historical reconciliation still goes through Step 10A concrete actions, Step 10B payload review, Step 11 preflight, and a separate explicit `solr-execute --apply`.

See `docs/STEP17_ACCEPTANCE.md`.

---

# Step 16 — baseline triage and controlled clean enrollment

Step 16 keeps the Step 15 exact 25-candidate scope and adds a **read-only triage layer** plus a **clean-only baseline approval gate**. It does not widen FIM again, does not add a database migration, and does not enable automatic Solr apply.

The Step 15 pilot currently has two approved candidates and 23 pending baselines. Step 16 first revalidates each pending baseline live, classifies it, and permits individual approval only when the stored fingerprint is unchanged and the candidate is fully synchronized (`missing=0`, `stale=0`, `other=0`, `match=eligible`).

## Step 16 commands

```powershell
.\Step16-Preflight.cmd
.\Step16-Triage.cmd
.\Step16-Approve-Clean.cmd <candidate-id> <baseline-sha256>
.\Step16-Approve-Clean.cmd <candidate-id> <baseline-sha256> --apply
.\Step16-PostApproval-Check.cmd
```

The first approval command is a preview. `--apply` records baseline approval in MariaDB only after exact SHA and live clean-state revalidation. Drifted, conflicted or stale captures are rejected by the clean-only command.

Expected build gate after merging this package:

```text
Build succeeded.
0 Warning(s)
0 Error(s)
Self-tests: 130/130 passed; 0 failed.
```

See `docs/STEP16_ACCEPTANCE.md` for the acceptance sequence and live-test procedure.

---

# Step 15 — controlled 25-candidate rollout

Step 15 expands the validated five-candidate Step 14 pilot to an **explicit 25-candidate cohort** while retaining the Step 14C baseline enrollment gate, Step 14D failure/recovery safeguards, Step 13 supervisor recovery, and manual Step 11 Solr approval.

It does **not** enable root-wide processing and does **not** enable automatic Solr apply.

## Exact Step 15 cohort

```text
1180000-1180023
1180097
```

That is 25 explicit candidate folders. The cohort matches the earlier controlled Step 14A collision audit range.

## Safety boundary retained

```text
Wazuh event
  → explicit candidate allowlist
  → candidate worker reconciliation
  → baseline enrollment gate
  → Step 10A concrete action plan
  → Step 10B reviewed payload
  → Step 11 read-only preflight
  → READY_FOR_APPROVAL
  → separate explicit solr-execute --apply
```

Newly added candidates are captured as `PENDING` baselines and cannot progress to Step 10A until explicitly reviewed and approved. Existing `APPROVED` baseline rows are preserved by baseline capture.

## What Step 15 changes

- raises the hard active-candidate ceiling from 5 to **25**;
- adds `importer.step15.pilot.json` with the exact 25-candidate cohort;
- increases the bounded worker drain to 25 items/cycle for this cohort;
- adds a 25-candidate Wazuh FIM allowlist script for FLOSVR01;
- adds exact 25-candidate metadata + collision/ownership preflight;
- adds Step 15 baseline capture/status helpers;
- adds Step 15 activation and post-activation reporting helpers;
- keeps the baseline gate and manual Solr approval unchanged.

## Build gate

Stop the scheduled pipeline before replacing/building the Debug DLL:

```powershell
Stop-ScheduledTask -TaskName "WazuhAuditImporter-Step13" -ErrorAction SilentlyContinue
powershell.exe -NoProfile -ExecutionPolicy Bypass -File ".\ops\Stop-Step13.ps1"
Start-Sleep -Seconds 3
```

Then merge Step 15 and run:

```powershell
.\Restore-And-Preview.cmd
```

Expected:

```text
Build succeeded.
0 Warning(s)
0 Error(s)
Self-tests: 125/125 passed; 0 failed.
```

No MariaDB migration is required for Step 15.

## 1. Exact 25-candidate preflight

```powershell
.\Step15-Preflight.cmd
```

This performs:

- metadata-only access check for all 25 candidate folders;
- exact 25-candidate Step 14A legacy-ID collision/ownership audit;
- Solr GET only;
- no MariaDB writes;
- no source-content reads;
- no Solr writes.

Pass criteria include:

```text
Candidates audited : 25
Cross-candidate disk collision groups : 0
Within-candidate disk collision groups: 0
Solr owner-different-candidate conflicts: 0
Solr same-candidate/path conflicts     : 0
SafeToExpandScope                     : True
```

## 2. Capture enrollment baselines before activating the larger event scope

```powershell
.\Step15-Baseline-Capture.cmd
.\Step15-Baseline-Status.cmd
```

Existing approved baselines such as `1180001` and `1180097` are not replaced. Newly added candidates are captured as `PENDING` and remain review-gated.

For the current pilot evidence, the expected high-level state is:

```text
APPROVED: 1180001, 1180097
PENDING : all other Step 15 cohort candidates unless separately reviewed
```

Do not bulk-approve the new cohort merely because it passed collision audit. Collision safety and baseline reconciliation review are separate gates.

## 3. Expand FLOSVR01 Wazuh FIM to the exact 25 folders

Copy `ops\FLOSVR01-Step15-Allowlist.ps1` to FLOSVR01 and run from elevated PowerShell:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass `
  -File ".\FLOSVR01-Step15-Allowlist.ps1"
```

The script:

- requires exactly 25 explicit candidate IDs;
- verifies every folder exists;
- refuses a root-wide `To 1189999` monitor;
- refuses to proceed if the manager address has regressed from stable hostname `MGMTNB08` to a DHCP IPv4 address;
- backs up `ossec.conf`;
- writes exactly 25 managed realtime FIM entries;
- restarts `WazuhSvc` unless `-NoRestart` is supplied.

Verify `ossec.log` shows a monitoring line for each candidate and realtime FIM started.

## 4. Activate Step 15 on MGMTNB08

```powershell
.\Step15-Activate.cmd
```

This stops the current supervisor/task, points `ops\step13.local.json` at `importer.step15.pilot.json`, and intentionally leaves the scheduled task stopped.

Then run:

```powershell
.\Step13-Preflight.cmd
```

If PASS:

```powershell
Start-ScheduledTask -TaskName "WazuhAuditImporter-Step13"
Start-Sleep -Seconds 10
.\Step13-Status.cmd
```

The status should show 25 candidate states. Pending candidates should settle at `BaselineReviewRequired`; approved candidates may progress through the normal review pipeline.

## 5. Safe first live test

Use a newly added pending candidate, for example `1180004`, with a legacy-filtered filename so the test itself is never intended for Solr:

```powershell
# FLOSVR01
$testFile = "C:\Shares-DFS\FastTrack\Candidate\To 1189999\1180004\DNI_STEP15_GATE_TEST.txt"
Set-Content -LiteralPath $testFile -Value "Step 15 pending-baseline gate test $(Get-Date -Format o)"
```

After 20-30 seconds:

```powershell
# MGMTNB08
.\Step13-Status.cmd
```

Expected:

```text
candidate=1180004
worker version advances
stage=BaselineReviewRequired
```

and there must be no Step 10A/10B preparation, no `READY_FOR_APPROVAL`, and no Solr write for that candidate until its baseline is explicitly approved.

Remove the filtered test file afterward and let the delete event reconcile under the same baseline gate.

## 6. Post-activation report

```powershell
.\Step15-PostActivate-Check.cmd
```

This prints baseline status, read-only Step 14D recovery inspection, and Step 14E metrics for the 25-candidate config. It does not auto-apply any Solr mutation.

For a report only:

```powershell
.\Step15-Report.cmd
```

## Rollback

If the cohort must be rolled back operationally, stop Step 13 and reactivate the prior five-candidate config:

```powershell
.\Step14B-Activate.cmd
```

Then re-apply the five-candidate FLOSVR01 FIM allowlist using the prior Step 14B script and restart the scheduled task only after `Step13-Preflight.cmd` passes.

Baseline history and prior audit/mutation evidence remain intact.

See `docs\STEP15_ACCEPTANCE.md` for acceptance criteria.
