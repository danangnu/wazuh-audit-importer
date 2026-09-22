# Step 4 acceptance — collect-once

Prerequisites:
- Wazuh Indexer SSH tunnel reachable at https://127.0.0.1:19200.
- Existing schema guard passes on MGMTNB08 / wazuh_audit_poc.
- Existing manual sample row and pending queue row may remain in place.

Run `collect-once` once. For the documented five-event history and one already
imported event, expected baseline is: accepted 5, inserted 4, duplicates 1,
ignored 0, one checkpoint row, one candidate queue row with event_version 5.
If newer scoped FIM alerts exist, counts can be higher.

Run `sql/003_verify_collector.sql`.

Run `collect-once` again without making another test file change. Expected:
- no additional audit rows,
- event_version unchanged,
- checkpoint timestamp advances,
- overlap replays can appear as DUP and are not a failure.

Failure contract:
- HTTP/JSON/page-limit failure => no checkpoint advance;
- per-event DB failure => command stops and no checkpoint advance;
- already committed earlier events can be replayed safely next time;
- no queue worker and no Solr write in Step 4.
