# Step 14E — pilot metrics and delivery report

Step 14E keeps the Step 14D failure/recovery safeguards and adds a **read-only pilot measurement/reporting layer** for the current five-candidate rollout.

The goal is to give Campbell a concrete answer to the original problem: what the event-driven Wazuh → MariaDB → reconciliation → approval-gated Solr pipeline is doing, how quickly the observed pilot stages complete, what is currently synchronized, and which safety controls remain in force.

## What Step 14E adds

New command:

```text
pilot-report
```

It reads only:

- existing `wazuh_audit_poc` audit/mutation/action/payload/baseline rows;
- FLOSVR01 candidate **file metadata only**;
- Solr using HTTP GET only.

It writes local report files only. It never changes source documents, MariaDB application rows, or Solr.

Output under `pilot-reports`:

```text
step14e-pilot-metrics-YYYYMMDD-HHMMSS.json
step14e-mutation-timings-YYYYMMDD-HHMMSS.csv
step14e-pilot-delivery-report-YYYYMMDD-HHMMSS.md
```

## Observed latency stages

For each mutation, Step 14E maps `worker_version` back to the corresponding unique candidate audit-event version and reports available UTC timing stages:

```text
Wazuh event time
  → MariaDB ingest
  → worker/mutation plan
  → reviewed payload ready
  → explicit operator-approved / verified apply
```

The report deliberately separates:

```text
event → ready for approval
```

from:

```text
ready for approval → verified apply
```

because the second interval includes deliberate human/operator review and should not be presented as machine latency.

## Legacy scanner comparison

By default Step 14E does **not** claim an X-times speedup. The pilot database does not contain a measured timing for the old continuous full-folder scanner.

If Campbell or an old application log provides a measured legacy reference, add it explicitly:

```powershell
.\Step14E-Report.cmd 600
```

where `600` is the measured legacy scan interval/latency in seconds.

The resulting comparison is clearly labeled as an **operator-supplied reference**, not a controlled benchmark.

## Build gate

Stop the running Step 13 scheduled pipeline before replacing/building the Debug DLL:

```powershell
Stop-ScheduledTask -TaskName "WazuhAuditImporter-Step13" -ErrorAction SilentlyContinue
powershell.exe -NoProfile -ExecutionPolicy Bypass -File ".\ops\Stop-Step13.ps1"
Start-Sleep -Seconds 3
```

Then merge Step 14E and run:

```powershell
.\Restore-And-Preview.cmd
```

Expected:

```text
Build succeeded.
0 Warning(s)
0 Error(s)
Self-tests: 122/122 passed; 0 failed.
```

No database migration is required for Step 14E.

## Generate the pilot report

```powershell
.\Step14E-Report.cmd
```

Expected summary includes:

```text
Candidates in active allowlist
Unique audit events
Mutation/action/payload counts
Baseline approved/pending counts
Current live candidate reconciliation
Observed event → ingest latency
Observed event → ready-for-approval latency
Observed ready → verified-apply interval
Observed event → verified-apply latency
```

and a per-candidate live state table.

## Full Step 14E preflight

```powershell
.\Step14E-Preflight.cmd
```

This runs the Step 14D recovery/baseline preflight first and then creates the Step 14E report.

Pass criteria:

- no unexplained uncertain/failed processing state;
- report files are generated successfully;
- no Solr writes occur;
- the report does not claim a legacy speedup unless a measured legacy reference was explicitly supplied.

## Current pilot interpretation

The active five-candidate configuration remains intentionally small:

```text
1180000
1180001
1180002
1180003
1180097
```

`1180001` and `1180097` have been reconciled and approved in the pilot. Candidates with historical drift remain baseline-gated until separately reviewed.

Step 14E is reporting only. It does not broaden candidate scope and does not enable automatic Solr apply.

## Safety boundary

The operational pipeline remains:

```text
Wazuh event
→ candidate reconciliation
→ baseline gate
→ Step 10A action plan
→ Step 10B reviewed payload
→ Step 11 preflight
→ READY_FOR_APPROVAL
→ separate explicit solr-execute --apply
```

Step 14E does not alter this boundary.

See `docs/STEP14E_ACCEPTANCE.md` for acceptance criteria and `docs/STEP14E_PILOT_EVIDENCE.md` for the validated pilot evidence carried into this reporting stage.
