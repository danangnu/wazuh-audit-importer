# Step 14B acceptance — controlled five-candidate rollout

## Scope

Active candidate allowlist:

- 1180000
- 1180001
- 1180002
- 1180003
- 1180097

No other candidate may be imported, claimed, reconciled, planned or exposed for approval while the
Step 14B config is active.

## Build gate

```powershell
.\Restore-And-Preview.cmd
```

Expected: `100/100` offline self-tests pass with zero build warnings/errors.

The five new Step 14B tests cover:

1. an exact five-candidate active allowlist is accepted;
2. more than five active candidates are rejected;
3. duplicate IDs are rejected;
4. an event for a second explicitly allowed candidate is accepted;
5. candidate-specific planner guards reject IDs outside the active allowlist.

## Read-only preflight gate

```powershell
.\Step14B-Preflight.cmd
```

Required:

- all five accessible FLOSVR01 folders pass worker metadata capture;
- exact five-candidate collision/ownership audit completes;
- `SafeToExpandScope : True`;
- no MariaDB mutation and no Solr write.

## FLOSVR01 FIM gate

Run `ops\FLOSVR01-Step14B-Allowlist.ps1` on FLOSVR01 elevated.

Required:

- backup of `ossec.conf` created;
- no root-wide `To 1189999` monitor exists;
- exactly the five intended candidate paths are configured by the migration;
- WazuhSvc returns to Running;
- realtime monitoring starts for the allowlisted paths.

## Supervisor configuration gate

Run `Step14B-Activate.cmd`, then `Step13-Preflight.cmd`, then restart the scheduled Step 13 task.
`Step13-Status.cmd` must show the supervisor/tunnel/pipeline healthy and display per-candidate states.

## Multi-candidate functional gate

Use the `DNI_WAZUH_STEP14B_TEST.txt` temporary file in candidate `1180001` so the file itself is
excluded by the legacy Solr filename filter.

Required evidence:

- Wazuh event candidate is `1180001`;
- collector inserts/deduplicates it under the same source/agent identity;
- worker claims candidate `1180001`, not `1180097`;
- snapshot is stored under the candidate-specific state path;
- its worker/mutation state advances independently from candidate `1180097`;
- pipeline status lists both candidate states;
- no Solr write occurs automatically.

A first event may establish a baseline (`operation=none`, `not_required`). Modify the same DNI test
file after baseline if a second non-baseline version is needed. Any generated mutation must remain
approval-gated.

## Manual approval gate

If one or more candidates are `ReadyForApproval`, each mutation is reviewed/applied independently:

```powershell
.\Step13-Approve.cmd <mutation-id>
```

The approval script must accept a mutation only when that exact mutation appears as
`ReadyForApproval` in the per-candidate pipeline state. It reruns Step 11 preflight immediately before
manual confirmation.

## Pass decision

Step 14B passes when:

- build/self-tests pass;
- exact five-candidate Step 14A audit remains safe;
- Wazuh monitors only the five allowed candidate folders;
- a new candidate other than 1180097 is processed end-to-end through candidate-specific state;
- existing candidate 1180097 remains operational;
- per-candidate blockers/approvals are visible independently;
- no automatic Solr update/delete/add/commit occurs.

Step 14B does **not** authorize expanding to the entire `To 1189999` tree and does not authorize
automatic Solr apply.
