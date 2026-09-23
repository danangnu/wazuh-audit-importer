# Step 11 acceptance — controlled Solr execution

Step 11 is the first stage permitted to call the Solr update API. The pilot is
still restricted to FLOSVR01 / agent 001 / candidate 1180097 / the approved
AlliedSolrCore endpoint.

## Preflight acceptance

Run `solr-execute` with an explicit `--mutation-id` and **without** `--apply`.
It must perform no Solr POST and no MariaDB status update. It passes only when:

1. the selected mutation is `planned`, `reindex_candidate`, and exactly matches
   the completed candidate queue worker version;
2. every concrete action is still `planned`;
3. every action has exactly one Step 10B payload with `status=ready`, non-null
   JSON/SHA-256, and no block reason;
4. each stored payload SHA-256 validates;
5. current FLOSVR01 inventory + current Solr GET state regenerate the identical
   deterministic Step 10A action plan;
6. each source-backed payload regenerates byte-for-byte with the same source
   hash, extracted-content hash, metadata, JSON and payload hash;
7. the live Solr schema still reports the approved unique key and required
   fields.

Expected pilot target after Step 10B: mutation 5, two ready actions (delete old
stale resume; index WAZUH_SOLR_CONTENT_TEST.txt), zero blocked payloads.

## Apply acceptance

`--apply` first claims the mutation and every action as `processing` in one
MariaDB transaction and increments attempt counts. It then re-runs live safety
validation before the first Solr POST.

Reviewed action payloads are POSTed in deterministic action order, followed by
one explicit Solr commit. After commit, GET verification must prove:

- deleted unique keys are absent unless that key is intentionally reused by a
  later same-mutation index action;
- every indexed unique key exists exactly once with the expected candidate and
  canonical path;
- a full candidate reconciliation contains only `MATCH` and
  `SKIPPED_BY_LEGACY_FILTER` states.

Only after that verification are the mutation/actions marked `applied`.

## Failure semantics

Solr does not provide a MariaDB-style transaction spanning several HTTP update
requests. If any failure occurs after the first update POST begins, the tool
marks the processing rows `failed` on a best-effort basis and reports the Solr
state as potentially partial/uncertain. Do not blindly rerun that mutation.
Perform read-only inspection first.

The executor deliberately does **not** issue Solr rollback because this is a
shared core and a rollback could affect unrelated concurrent writers.
