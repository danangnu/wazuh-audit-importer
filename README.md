# Step 14D — multi-candidate failure/recovery hardening

Step 14D keeps the Step 14C five-candidate baseline enrollment gate and adds failure/recovery hardening before broader rollout.

It targets five failure classes:

1. one candidate source folder is temporarily inaccessible;
2. WAZUH-LAB / Indexer tunnel is temporarily unavailable;
3. Solr GET is temporarily unavailable;
4. reviewed source/payload state changes before execution;
5. a Step 11 mutation is left `processing` or `failed`, where blind retry would be unsafe.

## What changes

### Per-candidate source failure isolation

The Step 14D orchestrator no longer lets a source-folder I/O failure for one claimed candidate abort the entire multi-candidate cycle.

A failed candidate work item is moved to the existing retry schedule and reported as:

```text
SourceUnavailable
```

Other due candidates may still reconcile during the same cycle.

The rule remains strict: an inaccessible folder is **never** interpreted as an empty candidate inventory.

Global failures such as MariaDB failure still stop/retry the whole cycle because their state cannot be safely isolated to one candidate.

### Read-only recovery inspection

New command:

```text
recovery-inspect
```

It reads:

- current/latest MariaDB mutation and action status;
- current FLOSVR01 metadata;
- current Solr state using GET only.

It does **not** modify MariaDB and does **not** call the Solr update API.

Recovery classifications include:

```text
NoMutation
HealthyTerminal
PlannedRequiresNormalPreflight
UncertainProcessing
UncertainFailed
Inconsistent
```

`processing`, `failed`, and inconsistent execution states are never authorized for blind retry.

## Build gate

Stop the running Step 13 scheduled pipeline before replacing/building the Debug DLL:

```powershell
Stop-ScheduledTask -TaskName "WazuhAuditImporter-Step13" -ErrorAction SilentlyContinue
powershell.exe -NoProfile -ExecutionPolicy Bypass -File ".\ops\Stop-Step13.ps1"
Start-Sleep -Seconds 3
```

Then merge Step 14D and run:

```powershell
.\Restore-And-Preview.cmd
```

Expected:

```text
Build succeeded.
0 Warning(s)
0 Error(s)
Self-tests: 114/114 passed; 0 failed.
```

No new database migration is required for Step 14D.

## Initial recovery inspection

Run:

```powershell
.\Step14D-Recovery-Inspect.cmd
```

or one candidate only:

```powershell
.\Step14D-Recovery-Inspect.cmd 1180001
```

Expected for the current pilot after Steps 14B/14C:

- `1180001` and `1180097` should normally be terminal/applied;
- pending baseline candidates may have terminal/not-required worker mutations or no mutation;
- there should be no unexpected `processing` or `failed` Solr mutation.

A JSON report is written under `recovery-reports`.

## Step 14D preflight

```powershell
.\Step14D-Preflight.cmd
```

This shows Step 14C enrollment status followed by Step 14D recovery inspection.

If an uncertain or inconsistent mutation is found, the command returns non-zero and the operator must inspect it before any `solr-execute --apply`.

## Failure/recovery acceptance sequence

See `docs/STEP14D_ACCEPTANCE.md` for the full sequence. The recommended order is:

1. build/self-test gate;
2. recovery inspection with no uncertain mutation;
3. WAZUH-LAB restart/IP-change recovery;
4. source-folder-unavailable behavior (never infer empty; item moves to retry);
5. source/payload drift rejection before Step 11 execution;
6. Solr GET outage behavior (operator block / retry, no Solr update request);
7. verify one candidate failure does not prevent healthy candidates from retaining independent state;
8. inspect any real `processing`/`failed` mutation with `recovery-inspect` rather than blind retry.

## Safety boundary

Step 14D does not add automatic Solr execution.

The pipeline remains:

```text
Wazuh event
→ candidate reconciliation
→ baseline gate
→ Step 10A
→ Step 10B
→ Step 11 preflight
→ READY_FOR_APPROVAL
→ separate explicit solr-execute --apply
```

The Step 13 supervisor and Step 14D pipeline never call `solr-execute --apply` automatically.
