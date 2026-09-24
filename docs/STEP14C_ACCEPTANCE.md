# Step 14C acceptance — baseline enrollment/review gate

## Purpose

Prove that adding a candidate to the active five-candidate allowlist does not automatically turn pre-existing historical Solr drift into actionable delete/index payloads before an operator reviews that candidate's starting state.

## Migration

Execute `sql/015_create_candidate_baseline_enrollment.sql` against `wazuh_audit_poc`, then run:

```powershell
.\src\WazuhAuditImporter\bin\Debug\net9.0\WazuhAuditImporter.dll check-db --config .\importer.step14b.pilot.json
```

Expected schema guard PASS and counts for the two new baseline tables.

## Build

Stop Step 13 first, merge Step 14C, then run `Restore-And-Preview.cmd`.

Expected: 108/108 self-tests, 0 warnings, 0 errors.

## Capture

Run:

```powershell
.\Step14C-Baseline-Capture.cmd
.\Step14C-Baseline-Status.cmd
```

All five allowlisted candidates should have a `pending` baseline with SHA-256 and drift counts.

## Pending gate

Leave candidate `1180000` pending. Create a filtered DNI test event in its folder or use a normal Wazuh metadata event. The worker may advance versions, but Step 13 status must show `BaselineReviewRequired` and no Step 10A action report should be created for the new mutation.

A manual Step 10A attempt for candidate `1180000` must fail with the Step 14C baseline gate message.

## Clean candidate approval

Use candidate `1180001` or `1180097` after verifying its baseline report. Run baseline approval without `--apply`; it must re-capture live state and report matching SHA. Then rerun with `--apply`.

Expected:

- current enrollment status becomes `approved`;
- an `approved` history event is appended;
- no Solr request is made by the approval command.

## Stale approval protection

Capture a pending baseline, change disk/Solr state, then attempt approval using the old SHA. The approval must be refused until baseline capture is refreshed and reviewed again.

## Approved flow

After approval, a Wazuh event for the candidate may proceed to Step 10A/10B/Step 11 preflight and `ReadyForApproval`, preserving the existing separate explicit Solr `--apply` boundary.

## Pass criteria

- pending candidates cannot reach Step 10A/10B/11;
- manual commands cannot bypass the enrollment gate;
- approval is fingerprint-bound and revalidated live;
- approval is persisted with reviewer/audit history;
- approved candidates resume normal Step 14B behavior;
- pipeline never auto-applies Solr.
