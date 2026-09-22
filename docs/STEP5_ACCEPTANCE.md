# Step 5 acceptance — continuous collector

Pass only after all of the following are observed on MGMTNB08 with the SSH tunnel open:

1. `collect` starts and remains running without a new manual command per poll.
2. With no new scoped file activity, repeated overlap results do not add audit rows or increment queue `event_version`.
3. Create one approved test file under candidate `1180097`; one new Wazuh alert is imported and the existing candidate queue row increments exactly once.
4. Modify that same test file; one new alert is imported and the queue version increments exactly once.
5. Delete that test file; one new alert is imported and the queue version increments exactly once.
6. Stop with Ctrl+C; process exits cleanly after the current bounded operation.
7. While stopped, create/modify an approved test file. Restart `collect`; the missed alert is recovered by checkpoint/overlap and imported once.
8. Close the SSH tunnel temporarily while `collect` runs. It reports a transient Indexer error, does not advance the failed checkpoint, and resumes after the tunnel is restored.
9. No candidate worker runs and no Solr writes occur.

Use `sql/005_verify_continuous_collector.sql` for read-only state verification.
