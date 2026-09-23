# Step 10B — Legacy-compatible Solr payload generation (dry run)

Step 10B converts the Step 10A concrete actions into stored, reviewable Solr
update JSON **without sending anything to Solr**.

Pilot scope remains fixed:

```text
Filesystem source : \\FLOSVR01\FastTrack\Candidate\To 1189999
Candidate         : 1180097
Solr endpoint     : http://192.168.18.22:8983/solr/AlliedSolrCore
Canonical root    : G:\Candidate\To 1189999
MariaDB           : 127.0.0.1:3306 / wazuh_audit_poc on MGMTNB08
```

## Legacy extraction contract used

The supplied legacy indexing source shows:

- `.txt`, `.html`, `.htm` -> `My.Computer.FileSystem.ReadAllText(filePath)`;
- `.doc`, `.docx`, `.docm`, `.rtf` -> Aspose.Words 24.9.0 text export;
- `.pdf` -> PDFBox 1.8.2 `PDFTextStripper`;
- after extraction, the legacy code removes all characters except
  `[a-zA-Z0-9_.]` for its emptiness test and does **not** index the document
  when that result is empty;
- Solr fields are `id`, `dbcandno`, `content`, `path`, `last_update`.

Step 10B ports the `ReadAllText` path exactly. It deliberately **blocks** Word
and PDF payloads instead of silently substituting a different extractor. This is
safer than calling a modern extractor and claiming byte/text compatibility with
the legacy index.

For the current Step 10A candidate state, `2026 09 16 001.txt` was observed as a
0-byte source file. Therefore the expected first Step 10B result is:

```text
delete_document -> READY
index_document  -> BLOCKED (empty_document_legacy_behavior)
```

That blocked index is expected and reproduces the supplied legacy `doIndexing`
behavior.

## Safety boundary

`solr-build-payloads` may:

- read Step 10A concrete action rows from MariaDB;
- read **source file contents** for `index_document` actions;
- hash the source file and extracted content;
- store dry-run payload/evidence rows in `solr_action_payload`;
- write a local JSON report.

It does **not**:

- change source files;
- POST/PUT/DELETE to Solr;
- call Solr commit/optimize/config APIs;
- change `solr_mutation_action.status` from `planned`;
- mark anything `applied`.

## 1. Build

```powershell
cd "C:\Users\dnurdiansyah\Documents\NewAllied\WazuhAuditImporter"
.\Restore-And-Preview.cmd
```

The offline self-tests now cover Step 10B delete payloads, text extraction,
legacy empty-document behavior, extractor blocking, and source metadata drift.
They make no MariaDB or Solr connection.

## 2. Apply migration

Execute in the local MariaDB client:

```text
sql\012_create_solr_action_payload.sql
```

It creates only:

```text
wazuh_audit_poc.solr_action_payload
```

Then verify:

```powershell
dotnet .\src\WazuhAuditImporter\bin\Debug\net9.0\WazuhAuditImporter.dll check-db
```

`check-db` should include a `solr_action_payload` count.

## 3. Build/stash payloads

```powershell
$root = "\\FLOSVR01\FastTrack\Candidate\To 1189999"

dotnet .\src\WazuhAuditImporter\bin\Debug\net9.0\WazuhAuditImporter.dll `
    solr-build-payloads `
    --worker-root "$root" `
    --report-dir ".\solr-payload-reports"
```

Or:

```powershell
.\Solr-Build-Payloads.cmd
```

A ready delete payload is stored in the Solr JSON update form:

```json
{"delete":{"id":"..."}}
```

A ready index payload contains:

```text
id
dbcandno
content
path
last_update
```

and is wrapped in a JSON `add.doc` update object. `last_update` is frozen at the
first payload-generation time so the reviewed payload is stable on replay.

## Blocked payloads

A blocked row stores no executable `payload_json`. Examples:

```text
empty_document_legacy_behavior
legacy_extractor_not_ported
source_file_missing
source_changed_since_action_plan
unsupported_extension
```

If any payload is blocked, the command stores the evidence then exits non-zero.
This is a review gate, not a Solr failure. Do not bypass it by manually marking
the action applied.

Existing payload rows are reused on rerun instead of being regenerated with a
new timestamp. A later executor must still revalidate source hash/metadata before
using a stored index payload.

## 4. Verify

Run:

```text
sql\013_verify_solr_payloads.sql
```

Expected current pilot outcome is one `ready` delete row and one `blocked` index
row because the currently planned TXT file is empty.

## Next step

Step 10C/11 should first resolve/validate document extraction for non-empty
Word/PDF content and add pre-execution source revalidation. Only after that should
any controlled Solr write be considered.
