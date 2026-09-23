# Validation status for this delivery

## Performed in the preparation environment

- Read the actual `001_create_wazuh_audit_poc.sql` previously supplied to the user.
- Compared INSERT column lists with that schema (20 audit columns, 12 queue columns).
- Generated required-column/type/index checks against that schema.
- Parsed the supplied event JSON and checked the exact event ID, agent ID,
  candidate path, reported size/hash, manager spelling and UTC timestamp.
- Checked project XML, project references and net9.0 targets.
- Checked source delimiter balance (lexical check only, NOT a C# compiler).
- Reviewed transaction assignments, rollback, duplicate-source comparison,
  queue version increments and protection of active leases/retry state.
- Included 31 C# parser/scope self-tests and manual DB acceptance steps.

## NOT performed here

- NuGet restore, C# compilation and execution of the 31 C# tests.
- SQL execution or compatibility tests against MariaDB 10.1.48.
- Rollback, concurrency, permission-failure or commit-interruption DB tests.
- Any access or change to MGMTNB08, FLOSVR01, the VM or the user's GitHub repository.

This preparation environment has no .NET SDK or MariaDB service. A download
attempt for the SDK failed due to unavailable DNS/network resolution. These
limitations are not evidence of failure on the user's laptop; local validation
is still required before using `--apply`.

## Next local gate

On MGMTNB08, run `Build-And-Preview.cmd`. It stops on failed restore, build,
self-tests or parsing and never connects to the database. After it succeeds,
run `check-db`, then the explicit apply and duplicate-replay test documented
in the README. Keep real passwords out of console captures and Git.

## Step 7 additions

The package adds the continuous `work` loop on top of the Step 6 lease/versioned
snapshot worker. Offline self-tests include bounds for the continuous worker poll
and loop-retry settings. Runtime acceptance still must be performed on MGMTNB08
against the existing MariaDB queue and FLOSVR01 SMB root; this package has not
been compiled or executed in the artifact-generation environment.

## Step 9 static validation

Step 9 adds a Solr read-only discovery path only. Static review confirms the new
Solr client issues `HttpClient.GetAsync` requests and contains no POST/PUT/DELETE/
PATCH/update/commit/optimize call. The command is handled before MariaDB
credential prompting and does not open a database connection.

The supplied legacy indexing source and Paths.ini were reviewed to derive the
fixed pilot endpoint, field names, canonical `G:\Candidate\To 1189999` path,
filename-based legacy ID algorithm, and legacy hidden/DNI/OCRERROR filtering.
The sensitive Paths.ini itself is not packaged.

Runtime compilation/self-tests and live read-only Solr comparison remain to be
validated on MGMTNB08 because this packaging environment has no .NET SDK or
network access to AlliedSolrCore.

## Step 11 static validation

Step 11 adds the first Solr POST path. It is reachable only through
`solr-execute` with an explicit positive `--mutation-id`; omitting `--apply`
performs preflight only. Preflight re-reads the selected DB mutation/actions and
ready Step 10B payloads, validates stored payload SHA-256, regenerates the live
Step 10A action plan from FLOSVR01 metadata plus Solr GET state, and regenerates
each source-backed Step 10B payload for exact drift comparison.

With `--apply`, the selected mutation/actions are first claimed as `processing`
in MariaDB, live state is revalidated again, reviewed payload JSON is POSTed in
action order, one explicit commit is sent, and final state is verified with GET
and candidate reconciliation before rows are marked `applied`. No Solr rollback
is issued because the core may have unrelated concurrent writers.

Four additional offline tests cover Step 11 ready-payload integrity,
blocked-payload rejection, source/payload drift, and current action-plan drift,
bringing the expected self-test count to 74. This preparation environment still
has no .NET SDK and cannot compile or run those tests; MGMTNB08 remains the
runtime acceptance environment.


## Step 12 static validation

Step 12 adds `pipeline-once` and `pipeline` as approval-gated orchestration commands. Static
review confirms these commands call `SolrExecutor.Run(..., apply: false)` only; the Solr writer
remains reachable only through the separate Step 11 `solr-execute --apply` path. Step 12 may
write MariaDB audit/queue/plan/payload state, read source content during Step 10B, and issue
read-only Solr/Indexer queries.

The continuous pipeline holds a `FileShare.None` process lock under the persistent worker-state
directory, retries transient DB/HTTP/I/O failures, preserves existing collector checkpoint and
worker lease semantics, and writes a best-effort local `step12-pipeline-state.json` operational
status file. A latest mutation in `processing` or `failed` state is not auto-retried.

Step 12 also closes the same-path content-change gap: the immutable Step 8 `changes.changed`
list is read from `solr_mutation_queue.plan_json` and passed into Step 10A. A changed eligible
file that otherwise compares as `MATCH` produces an `index_document` with
`reason=source_changed`. Step 11 preflight regenerates the same forced action from the immutable
plan before any explicit apply.

Twelve additional offline tests (including one content-change action test and eleven
orchestration/configuration decision tests) bring the expected self-test count from 74 to 86.
This preparation environment still has no .NET SDK, MariaDB, Wazuh Indexer or AlliedSolrCore;
MGMTNB08 remains the required runtime compilation and integration-test environment.
