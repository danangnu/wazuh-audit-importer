# Step 14D acceptance — failure/recovery hardening

## Purpose

Prove that transient infrastructure/source failures do not turn into destructive reconciliation, do not cause blind Solr retries, and do not unnecessarily block unrelated candidates.

## A. Build and recovery baseline

Stop Step 13, build Step 14D, and require 114/114 offline self-tests.

Run:

```powershell
.\Step14D-Preflight.cmd
```

Pass criteria:

- Step 14C baseline status is readable;
- no unexpected latest mutation is `processing`, `failed`, or inconsistent;
- current live disk/Solr verification is available for healthy candidates;
- no writes occur.

## B. WAZUH-LAB / Indexer outage recovery

The Step 13 supervisor already supports VM/tunnel recovery. With the scheduled task running, restart WAZUH-LAB once.

Pass criteria:

- temporary collector HTTP/tunnel errors may appear;
- supervisor remains/reruns automatically;
- tunnel returns to `open=True`;
- pipeline returns to running;
- FLOSVR01 reconnects through MGMTNB08;
- no Solr update request occurs during the outage.

If WAZUH-LAB gets a different DHCP IP, portproxy/tunnel must repair automatically.

## C. Candidate source unavailable

The Step 14D worker now isolates candidate-local `DirectoryNotFoundException`, `UnauthorizedAccessException`, and `IOException` outcomes when running under the multi-candidate orchestrator.

Pass criteria for a controlled candidate-source failure:

- candidate queue item is moved to `retry` using the existing worker retry time;
- candidate status shows `SourceUnavailable` for that cycle;
- an inaccessible folder is never captured as an empty inventory;
- no Step 10A delete plan is produced from the inaccessible source;
- other healthy candidate state remains visible and independently evaluated.

Do not use broad root deletion/rename as a test. If a live candidate-specific access test is not operationally safe, rely on the offline Step 14D worker/recovery tests and test this during a planned maintenance window.

## D. Solr GET unavailable

Do not stop production Solr merely for the pilot. Test during a planned outage or by an approved network isolation on MGMTNB08.

Pass criteria:

- candidate preparation becomes an operator/dependency block;
- no Solr update API is called;
- no mutation is marked applied;
- after GET connectivity returns, the pipeline re-evaluates live state before becoming ReadyForApproval.

## E. Source/payload drift after review

Use an approved test candidate/document only. Allow Step 10B to create a ready payload, then modify the source before Step 11 apply.

Run Step 11 preflight without `--apply`.

Pass criteria:

```text
SOURCE/PAYLOAD DRIFT
```

or equivalent safety rejection, with zero Solr writes.

Afterward let the new Wazuh event reconcile and create a fresh reviewed payload rather than reusing the stale payload.

## F. Uncertain execution state

If a real Step 11 call ever ends with mutation status `processing` or `failed`, do not rerun `--apply` blindly.

Run:

```powershell
.\Step14D-Recovery-Inspect.cmd <candidate-id>
```

or:

```powershell
dotnet .\src\WazuhAuditImporter\bin\Debug\net9.0\WazuhAuditImporter.dll `
  recovery-inspect `
  --mutation-id <id> `
  --worker-root "\\FLOSVR01\FastTrack\Candidate\To 1189999" `
  --config ".\importer.step14b.pilot.json" `
  --report-dir ".\recovery-reports"
```

Pass criteria:

- `processing` => `UncertainProcessing`;
- `failed` => `UncertainFailed`;
- `Blind retry : False`;
- current disk/Solr reconciliation is shown read-only when available;
- no mutation/action row is changed by inspection.

## G. Pass criteria

Step 14D passes when:

- 114/114 offline tests pass;
- current recovery inspection has no unexplained uncertain/inconsistent state;
- WAZUH-LAB/tunnel recovery remains automatic;
- source unavailability never becomes an empty-folder delete plan;
- source/payload drift is rejected before write;
- failed/processing mutations cannot be blind-retried by the recovery workflow;
- a candidate-local source failure does not erase or overwrite another candidate's independent state;
- automatic Solr apply remains disabled.
