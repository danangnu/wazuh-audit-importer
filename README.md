# Step 14B — controlled five-candidate pilot rollout

Step 14A audited 100 candidates and found no blocking legacy-ID collision/ownership conflict after
verified repository-root alias normalization. Step 14B now widens the **active** event-driven pilot
from candidate `1180097` to a deliberately small five-candidate allowlist:

```text
1180000
1180001
1180002
1180003
1180097
```

This is not a root-wide rollout. Active processing is hard-limited to at most five explicit
`CandidateIds` and Step 14B still preserves the manual Solr approval boundary.

```text
FLOSVR01 realtime FIM — five explicit folders only
        ↓
Wazuh / Indexer
        ↓
collector ignores every candidate outside importer.step14b.pilot.json
        ↓
worker claims/reconciles allowlisted candidates independently
        ↓
Step 10A / Step 10B per candidate
        ↓
Step 11 read-only preflight per mutation
        ↓
READY_FOR_APPROVAL candidate=<id> mutation=<id>
        ↓
NO automatic Solr apply
```

## Safety changes

Step 14B adds these controls:

- active `CandidateIds` maximum = **5**;
- duplicate candidate IDs are rejected;
- collector/parser remains explicit-allowlist only;
- worker already supports candidate-specific queue claims and snapshots;
- orchestration now evaluates each allowlisted candidate independently each cycle;
- a blocked candidate is visible separately and does not convert the scope into root-wide processing;
- local pipeline status stores per-candidate stage/mutation/version;
- `Step13-Status.cmd` displays the per-candidate state;
- `Step13-Approve.cmd <mutation-id>` accepts any mutation that is currently `ReadyForApproval` in the per-candidate state;
- direct Step 10A/10B commands require `--candidate-id` when the config has multiple candidates;
- Step 11 still requires an explicit mutation id and `--apply`;
- Step 14B never invokes `solr-execute --apply` itself.

## 1. Stop Step 13 before replacing/building the DLL

```powershell
Stop-ScheduledTask -TaskName "WazuhAuditImporter-Step13" -ErrorAction SilentlyContinue
powershell.exe -NoProfile -ExecutionPolicy Bypass -File ".\ops\Stop-Step13.ps1"
Start-Sleep -Seconds 3
```

Merge this package and run:

```powershell
.\Restore-And-Preview.cmd
```

Expected gate:

```text
Build succeeded.
0 Warning(s)
0 Error(s)
Self-tests: 100/100 passed; 0 failed.
```

## 2. Read-only Step 14B preflight on MGMTNB08

```powershell
.\Step14B-Preflight.cmd
```

This checks metadata access for all five folders and reruns the exact five-candidate Step 14A
collision/ownership audit. It must finish with `SafeToExpandScope : True`.

No MariaDB rows or Solr documents are changed by this preflight.

## 3. One-time Wazuh FIM allowlist migration on FLOSVR01

Copy `ops\FLOSVR01-Step14B-Allowlist.ps1` to FLOSVR01 and run it from **elevated PowerShell**:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\FLOSVR01-Step14B-Allowlist.ps1
```

The script:

- verifies it is running on FLOSVR01;
- verifies all five candidate folders exist;
- backs up `ossec.conf`;
- removes only candidate-specific FIM lines under the controlled `To 1189999` root;
- refuses to create a root-wide monitor;
- writes five explicit realtime `<directories>` entries;
- restarts `WazuhSvc` and requires it to return to `Running`.

Afterward, check `ossec.log` and confirm one monitored path for each allowlisted candidate.

## 4. Point the Step 13 supervisor at the Step 14B config

On MGMTNB08, elevated PowerShell:

```powershell
.\Step14B-Activate.cmd
```

This safely stops the Step 13 task/processes and changes only `ConfigPath` in
`ops\step13.local.json` to the absolute path of:

```text
importer.step14b.pilot.json
```

Then run the normal operational preflight:

```powershell
.\Step13-Preflight.cmd
```

Start the scheduled supervisor:

```powershell
Start-ScheduledTask -TaskName "WazuhAuditImporter-Step13"
Start-Sleep -Seconds 8
.\Step13-Status.cmd
```

The status should now include five candidate states. Candidates that have never produced a queue
mutation may show `Idle`; existing candidate `1180097` should show its prior terminal state.

## 5. Controlled new-candidate functional test

Do **not** edit a real resume just to test the pipeline. On FLOSVR01 create a temporary file whose
name is deliberately excluded by the legacy indexer filter:

```powershell
$test = "C:\Shares-DFS\FastTrack\Candidate\To 1189999\1180001\DNI_WAZUH_STEP14B_TEST.txt"
Set-Content -LiteralPath $test -Value "Step 14B multi-candidate FIM test $(Get-Date -Format o)"
```

`DNI` is excluded by the legacy filename filter, so the test file itself must never become a Solr
index document. Wait for Step 13/14B to process the event, then inspect:

```powershell
.\Step13-Status.cmd
```

Expected evidence includes candidate `1180001` being collected/claimed and independently reaching a
safe terminal/approval state. On its first observed version it may establish a baseline rather than
infer historical changes; that is expected.

After the candidate has a completed baseline, modify the same test file once to prove an independent
second version:

```powershell
Add-Content -LiteralPath $test -Value "second version $(Get-Date -Format o)"
```

Do not apply any unexpected mutation without review. Step 14B itself will never apply it.

## 6. Manual approval remains unchanged

If any candidate reaches `ReadyForApproval`, review its action/payload evidence, then use:

```powershell
.\Step13-Approve.cmd <mutation-id>
```

That script reruns Step 11 preflight before exposing the `APPLY-<id>` confirmation boundary.

## Direct multi-candidate Step 10 commands

When using `importer.step14b.pilot.json`, direct Step 10 commands require an explicit candidate:

```powershell
dotnet .\src\WazuhAuditImporter\bin\Debug\net9.0\WazuhAuditImporter.dll `
  solr-plan-actions --config .\importer.step14b.pilot.json `
  --worker-root "\\FLOSVR01\FastTrack\Candidate\To 1189999" `
  --candidate-id 1180001 --report-dir .\solr-action-reports
```

and similarly for `solr-build-payloads`.

See `docs\STEP14B_ACCEPTANCE.md` for the acceptance checklist.
