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
