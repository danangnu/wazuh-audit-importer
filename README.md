# Step 13 — Operational background deployment and restart hardening

Steps 1–12 proved the full FLOSVR01 → Wazuh → MariaDB → reconciliation → Solr flow, including
manual guarded Solr execution and same-path content reindexing. Step 13 makes that validated
**approval-gated** pipeline practical to leave running on MGMTNB08 without keeping an interactive
collector/pipeline console and without manually repairing the Hyper-V VM IP every morning.

Step 13 does **not** broaden the candidate scope and does **not** auto-write to Solr.

```text
FLOSVR01 Wazuh agent
        ↓
MGMTNB08 hostname + restricted portproxy
        ↓
dynamic Hyper-V WAZUH-LAB IPv4
        ↓
pinned, key-authenticated SSH tunnel :19200
        ↓
Step 12 approval-gated pipeline
        ↓
READY_FOR_APPROVAL
        ↓
manual Step13-Approve / Step 11 --apply only
```

## What is new

- Dynamic discovery of the current `WAZUH-LAB` Hyper-V IPv4.
- Automatic repair of project-owned `8443`, `1514`, `1515` portproxy mappings.
- Portproxy listens on all host IPv4 addresses so MGMTNB08 DHCP changes no longer require rewriting
  the forwarding rules; the firewall allow rule remains restricted to FLOSVR01 `192.168.100.20`.
- One-time FLOSVR01 helper to change the Wazuh manager from a DHCP IP to stable hostname `MGMTNB08`
  **only after DNS and TCP 1514 validation succeeds**.
- Dedicated Ed25519 SSH key for unattended Indexer tunneling.
- WAZUH-LAB SSH host-key pinning using a stable `HostKeyAlias=WAZUH-LAB`, so changing VM DHCP IPs do
  not require accepting a new host key every time.
- MariaDB and Indexer passwords stored outside the repository as current-user Windows DPAPI
  ciphertext.
- Supervisor that watches VM IP, portproxy, SSH tunnel and Step 12 pipeline; it restarts the tunnel
  and pipeline as needed and writes a small health JSON file.
- Current-user scheduled task at logon with highest privileges. This is appropriate for the current
  pilot because the same Windows user already has FLOSVR01 SMB access. It is not yet a dedicated
  server service account.
- `Step13-Status` operational view.
- `Step13-Approve` wrapper that requires current `ReadyForApproval`, reruns Step 11 preflight,
  requires typing `APPLY-<id>`, applies, then runs `solr-readonly` verification.

The supervisor itself **never invokes `solr-execute --apply`**.

## 0. Merge and build

Merge this package into the Step 12 repository and run:

```powershell
cd "C:\Users\dnurdiansyah\Documents\NewAllied\WazuhAuditImporter"
.\Restore-And-Preview.cmd
```

The .NET core is intentionally unchanged from the Step 12 code that passed `86/86` self-tests; Step
13 adds the operational PowerShell layer. Expected build gate remains:

```text
Build succeeded.
0 Warning(s)
0 Error(s)
Self-tests: 86/86 passed; 0 failed.
```

## 1. Close the old manual SSH tunnel

Before starting the Step 13 supervisor, close any manually opened command such as:

```powershell
ssh -L 19200:127.0.0.1:9200 danang@...
```

Step 13 owns local port `127.0.0.1:19200`. Two tunnel processes cannot bind the same port.

## 2. Initialize Step 13 on MGMTNB08

Run an **Administrator PowerShell** in the repository:

```powershell
.\Step13-Initialize.cmd
```

On first run it creates ignored local settings:

```text
ops\step13.local.json
```

The defaults already match the current pilot. The script then:

1. prompts for the MariaDB and Wazuh Indexer passwords and protects them with Windows DPAPI under
   `%LOCALAPPDATA%\WazuhAuditImporter\secrets-step13`;
2. creates a dedicated SSH key if needed;
3. scans the WAZUH-LAB Ed25519 host key and asks you to compare/paste the fingerprint shown by the
   VM command:

   ```bash
   ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub -E sha256
   ```

4. optionally installs the public key into `danang@WAZUH-LAB` (Ubuntu password may be requested once);
5. verifies SSH `BatchMode=yes`;
6. discovers the current VM IP and repairs portproxy/firewall.

No password is stored in Git, JSON or scheduled-task arguments.

## 3. Make FLOSVR01 independent of the laptop DHCP address

Copy/run this script **on FLOSVR01 in Administrator PowerShell**:

```text
ops\FLOSVR01-Use-MGMTNB08-Hostname.ps1
```

It first requires both of these to work from FLOSVR01:

```powershell
Resolve-DnsName MGMTNB08
Test-NetConnection MGMTNB08 -Port 1514
```

Only then does it back up `ossec.conf`, change the Wazuh manager/enrollment address to `MGMTNB08`,
restart `WazuhSvc`, and show the recent agent log.

If `MGMTNB08` does not resolve from FLOSVR01, **do not force the change**. Keep the current IP and ask
for an internal DNS record or DHCP reservation instead.

## 4. Step 13 preflight

Back on MGMTNB08, Administrator PowerShell:

```powershell
.\Step13-Preflight.cmd
```

Expected checks include:

```text
[PASS] Administrator
[PASS] Built importer
[PASS] Worker root
[PASS] MariaDB TCP
[PASS] Solr TCP
[PASS] DB DPAPI secret
[PASS] Indexer DPAPI secret
[PASS] SSH private key
[PASS] Pinned known_hosts
[PASS] WAZUH-LAB IPv4
[PASS] WAZUH-LAB TCP 22/443/1514/1515
[PASS] Batch SSH
[PASS] IP Helper

STEP 13 PREFLIGHT PASS.
```

## 5. Interactive supervisor validation

Before installing the task, run the supervisor once interactively:

```powershell
.\Step13-Run.cmd
```

In a second Administrator PowerShell:

```powershell
.\Step13-Status.cmd
```

You want:

```text
Supervisor      : running
SSH tunnel      : open=True
Pipeline        : running=True
```

The pipeline stage may be `Complete`, `ReadyForApproval`, etc. according to MariaDB state.

Stop the interactive validation with `Ctrl+C`. If needed:

```powershell
.\Step13-Stop.cmd
```

## 6. Install the background task

```powershell
.\Step13-Install-Task.cmd
```

This installs and starts:

```text
WazuhAuditImporter-Step13
```

Behavior:

- trigger: current Windows user's logon;
- run with highest privileges;
- one instance only;
- no DB/Indexer password in task arguments;
- automatically waits if WAZUH-LAB is off;
- repairs forwarding and restarts the SSH tunnel when the VM IP changes;
- restarts the Step 12 pipeline if the process exits;
- **never applies a Solr mutation automatically**.

Check at any time:

```powershell
.\Step13-Status.cmd
```

## 7. Operational approval

When status shows:

```text
Pipeline stage  : ReadyForApproval
Mutation        : 7
```

review the pipeline/action/payload reports, then run:

```powershell
.\Step13-Approve.cmd 7
```

The wrapper enforces that mutation `7` is the current `ReadyForApproval` mutation, reruns Step 11
preflight, and requires:

```text
APPLY-7
```

before any Solr POST. If apply succeeds, it immediately runs `solr-readonly` for post-apply
comparison.

## 8. Restart/IP-change acceptance test

After the task is running:

1. note `Step13-Status` VM IP;
2. restart `WAZUH-LAB` so Hyper-V may issue another `172.30.x.x` address;
3. wait about 30–60 seconds;
4. rerun `Step13-Status`;
5. verify the health view shows the new VM IP, tunnel open, pipeline running;
6. verify FLOSVR01 returns `Active` and a new test file modification can again reach
   `ReadyForApproval`.

This is the key Step 13 proof that the morning DHCP change no longer requires manual portproxy or
SSH-tunnel edits.

## Operational files

Outside Git:

```text
%LOCALAPPDATA%\WazuhAuditImporter\secrets-step13\     DPAPI secrets
%LOCALAPPDATA%\WazuhAuditImporter\ssh\known_hosts    pinned WAZUH-LAB host key
%LOCALAPPDATA%\WazuhAuditImporter\logs-step13\       supervisor/tunnel/pipeline logs
%LOCALAPPDATA%\WazuhAuditImporter\step13-health.json health snapshot
```

Inside the ignored repository runtime directories, Step 12 still owns:

```text
worker-state\step12-pipeline-state.json
worker-state\step12-pipeline.lock
pipeline-reports\
```

## Stop / uninstall

Stop task/processes but keep configuration:

```powershell
.\Step13-Stop.cmd
```

Uninstall task (secrets/keys/logs deliberately remain):

```powershell
PowerShell.exe -NoProfile -ExecutionPolicy Bypass -File .\ops\Uninstall-Step13Task.ps1
```

See `docs\STEP13_ACCEPTANCE.md` for the formal acceptance gates.

### Hyper-V KVP fallback

If `Get-VMIntegrationService` reports **Key-Value Pair Exchange: No Contact** and `Get-VMNetworkAdapter ... IPAddresses` is empty, Step 13 no longer treats that as fatal. IP discovery now falls back to an optional `VmIpv4Override`, a live existing portproxy target, and the Hyper-V host neighbour table. After SSH initialization, a pinned SSH host key is used to disambiguate candidates. `VmIpv4Override` should normally remain empty; it can be set temporarily to the current guest IP when bootstrapping.

### Step 13 preflight SSH timeout hardening

The Batch SSH preflight uses a bounded child process with `-n -T` and an 8-second timeout. This avoids Windows PowerShell 5.1/native-SSH hangs while preserving pinned-host-key and public-key-only verification.
