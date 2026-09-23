# Step 13 acceptance — operational background deployment and restart hardening

Step 13 does **not** expand the pilot candidate scope and does **not** introduce unattended Solr writes.
It operationalizes the already validated Step 12 approval-gated pipeline on MGMTNB08.

## Fixed pilot scope

- Source: `\\FLOSVR01\FastTrack\Candidate\To 1189999`
- Candidate: `1180097`
- Wazuh agent: `001 / FLOSVR01`
- Wazuh VM: Hyper-V `WAZUH-LAB`
- Local Indexer tunnel: `https://127.0.0.1:19200`
- MariaDB: `127.0.0.1:3306 / wazuh_audit_poc`
- Solr: `http://192.168.18.22:8983/solr/AlliedSolrCore`
- Solr write boundary: still manual Step 11 apply only

## Acceptance gates

1. Existing solution restores/builds cleanly and all Step 12 self-tests remain green.
2. Step 13 secrets are stored outside the repository as current-user Windows DPAPI ciphertext; no plaintext DB/Indexer password is placed in JSON, scripts, task arguments, logs, or Git.
3. A dedicated SSH key works in `BatchMode=yes`; WAZUH-LAB's Ed25519 host key is pinned under the stable alias `WAZUH-LAB`.
4. `Repair-WazuhLabNetwork.ps1` dynamically discovers the current Hyper-V VM IPv4 and recreates only the project-owned 8443/1514/1515 portproxy mappings.
5. Forwarding listens on `0.0.0.0` but the Windows Firewall allow rule is restricted to FLOSVR01 (`192.168.100.20`).
6. FLOSVR01 can use `MGMTNB08` as the Wazuh manager hostname after DNS/reachability validation, removing dependence on the laptop's DHCP address.
7. `Step13-Preflight` passes: admin, DLL, share, DB, Solr, DPAPI secrets, VM ports, IP Helper, pinned batch SSH.
8. `Step13-Run` starts/maintains the SSH tunnel and Step 12 pipeline without interactive password prompts.
9. The supervisor detects a WAZUH-LAB IP change/restart, repairs portproxy, restarts the tunnel, and lets the existing approval-gated pipeline recover.
10. Only one supervisor/task instance can run; Step 12's own process lock remains a second layer.
11. `Step13-Status` shows scheduled-task state, supervisor/tunnel/pipeline PIDs, restart counts, last error, and the Step 12 stage/mutation.
12. The scheduled task runs at the current operator's logon with highest privileges and does not require passwords in the task definition.
13. A new file change can reach `ReadyForApproval` while running under Step 13 background supervision.
14. No Step 13 supervisor/task command calls `solr-execute --apply`.
15. Actual Solr execution is performed only through explicit operator approval (`Step13-Approve.cmd <mutation-id>` or the Step 11 command), followed by read-only verification.

## Failure behavior

- VM stopped/no IP: supervisor waits and records `waiting_for_vm`.
- Tunnel failure: supervisor records degraded state and retries; pipeline is not auto-applied.
- Pipeline process exits: supervisor restarts it after the configured backoff; MariaDB/checkpoint/idempotency rules govern recovery.
- A Step 12 mutation becomes `failed`/`processing`: Step 12 remains halted for operator inspection; Step 13 does not bypass it.
- Source/payload/action drift: Step 11 preflight blocks apply as before.
- No automatic rollback is attempted against shared Solr.

## Not yet production-wide

Step 13 is still a controlled pilot. It deliberately does not:

- broaden `CandidateIds` beyond `1180097`;
- convert manual approval to auto-apply;
- replace MariaDB 10.1;
- deploy a dedicated always-on service account that runs before interactive logon;
- replace the Hyper-V lab with a server-grade Wazuh deployment.

Those are separate rollout decisions after Step 13 operational validation.
