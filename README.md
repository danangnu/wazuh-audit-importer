# Step 10A — Concrete Solr action planning (dry run)

Step 10A expands the latest **completed** candidate-level `reindex_candidate`
plan into concrete per-document actions, while keeping Solr strictly read-only.

Pilot scope remains fixed:

```text
Filesystem source : \\FLOSVR01\FastTrack\Candidate\To 1189999
Candidate         : 1180097
Solr endpoint     : http://192.168.18.22:8983/solr/AlliedSolrCore
Canonical root    : G:\Candidate\To 1189999
MariaDB           : 127.0.0.1:3306 / wazuh_audit_poc on MGMTNB08
```

## Safety boundary

`solr-plan-actions` may:

- read FLOSVR01 file **metadata**;
- call the approved Solr schema/select endpoints with HTTP GET;
- read the latest `solr_mutation_queue` and `candidate_work_queue` state;
- insert idempotent dry-run rows into `solr_mutation_action`.

It does **not**:

- read document contents;
- change files on FLOSVR01;
- call Solr add/delete/update/commit/optimize/config APIs;
- mark any action `applied`;
- execute OCR or content extraction.

## 1. Build

```powershell
cd "C:\Users\dnurdiansyah\Documents\NewAllied\WazuhAuditImporter"
.\Restore-And-Preview.cmd
```

The offline self-tests include Step 10A action ordering, collision blocking and
idempotency checks. They do not connect to MariaDB or Solr.

## 2. Apply the Step 10A database migration

Before running any Step 10A binary that performs a database schema check, execute
this file in the existing local MariaDB SQL client:

```text
sql\010_create_solr_mutation_action.sql
```

It creates only:

```text
wazuh_audit_poc.solr_mutation_action
```

Do not drop or recreate the existing audit/queue tables.

Then verify:

```powershell
dotnet .\src\WazuhAuditImporter\bin\Debug\net9.0\WazuhAuditImporter.dll check-db
```

`check-db` should now include `solr_mutation_action` in its row counts.

## 3. Generate concrete actions

```powershell
$root = "\\FLOSVR01\FastTrack\Candidate\To 1189999"

dotnet .\src\WazuhAuditImporter\bin\Debug\net9.0\WazuhAuditImporter.dll `
    solr-plan-actions `
    --worker-root "$root" `
    --report-dir ".\solr-action-reports"
```

Or use:

```powershell
.\Solr-Plan-Actions.cmd
```

For the Step 9 result previously observed for candidate 1180097, a normal plan
would be conceptually:

```text
PLAN DELETE_DOCUMENT
  stale Solr document:
  G:\Candidate\To 1189999\1180097\1180097 2025 08 22 Choi, Arthur Resume.pdf

PLAN INDEX_DOCUMENT
  current FLOSVR01 file:
  G:\Candidate\To 1189999\1180097\2026 09 16 001.txt
```

The exact IDs/paths are re-read at runtime. No action above is hard-coded.

## Guardrails

Step 10A refuses to persist concrete actions when:

- the candidate queue is not `completed` at the same version as the latest
  candidate Solr mutation;
- the latest mutation is not `planned/reindex_candidate`;
- Step 9 reports `ID_MISMATCH` or `DUPLICATE_SOLR_PATH`;
- multiple current FLOSVR01 files generate the same legacy Solr ID;
- an index action's legacy ID is already occupied by another candidate;
- an existing action row for the same mutation/order has different immutable
  plan data.

A same-candidate ID may be reused only when its currently occupying Solr document
is itself stale and is ordered for deletion before the index action. This supports
safe move/rename-style planning without assuming that two Wazuh events form a
rename.

## Action ordering and status

Concrete rows use:

```text
action_type = delete_document | index_document
status      = planned
```

Deletes are ordered before indexes. Rows also capture source metadata for index
plans (`source_file_length`, `source_file_last_write_utc`) and the observed
Solr `last_update` for delete plans. This gives a later executor enough evidence
to revalidate before any write.

Rerunning the same deterministic plan is idempotent. It reports existing rows
rather than adding duplicates.

## Verification

Run the read-only SQL:

```text
sql\011_verify_solr_actions.sql
```

Expected Step 10A rows remain:

```text
status         = planned
attempt_count  = 0
applied_at_utc = NULL
last_error     = NULL
```

## What comes next

Step 10B will reproduce/validate the legacy document construction and content
extraction required for `index_document`. It should still perform no Solr writes.
Actual controlled execution belongs to a later step after content generation and
pre-execution revalidation are accepted.
