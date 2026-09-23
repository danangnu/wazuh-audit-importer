# Step 10A acceptance criteria

Step 10A passes only when all of the following are observed on MGMTNB08:

1. Solution restore/build succeeds and all offline self-tests pass.
2. `010_create_solr_mutation_action.sql` creates the InnoDB table without
   changing existing audit/queue tables.
3. `check-db` validates the new table and its two unique indexes.
4. Candidate 1180097 queue is completed and its latest mutation version matches
   the completed worker version.
5. `solr-plan-actions` performs only Solr HTTP GET requests.
6. Current FLOSVR01/Solr mismatch produces deterministic concrete action rows.
7. Re-running the command inserts no duplicates.
8. All action rows remain `planned`, `attempt_count=0`, `applied_at_utc=NULL`.
9. No source file is changed, no content is read, and no Solr write/commit occurs.
10. Any ambiguous ID/path/collision condition blocks the plan rather than guessing.
