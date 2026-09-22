# Step 8 acceptance — Solr dry-run planner

Step 8 records proposed Solr work in MariaDB but makes no network connection to
Solr and performs no Solr writes.

Because the real Solr document model has not yet been supplied, the planner is
intentionally candidate-level. Any non-baseline inventory delta produces one
`reindex_candidate` plan for the claimed worker version. It does not invent a
Solr collection, unique-key field, candidate field, or file-level document ID.

## Prerequisite migration

Execute `sql/008_create_solr_mutation_queue.sql` once on `wazuh_audit_poc`.
Do not drop/recreate existing audit or worker tables.

## Acceptance sequence

1. Build/self-test Step 8.
2. Start `collect` and `work` as in Step 7.
3. Create a new test file under candidate 1180097.
4. The collector must queue a new candidate version.
5. The worker must report the inventory delta and print a line similar to:

   `SOLR PLAN mutation_id=... operation=reindex_candidate status=planned ...`

6. `solr_mutation_queue` must contain exactly one row for that worker version.
7. Replaying/retrying the same worker version must not create another plan row.
8. `status` remains `planned`; `applied_at_utc` remains NULL.
9. No Solr endpoint is contacted and no Solr write occurs.

A baseline or a completed worker pass with no inventory delta is recorded as
`operation='none'`, `status='not_required'` when Step 8 processes such a version.
Historical worker versions completed before Step 8 are not backfilled.
