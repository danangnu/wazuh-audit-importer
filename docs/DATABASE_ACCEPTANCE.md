# Database acceptance — run on the pilot, not production

These checks are pending until executed against the intended MariaDB server.
Do not truncate existing tables or remove history to obtain expected counts.

## Minimum manual test

1. Restore/build with .NET 9 and run the offline self-test executable.
2. Preview samples/wazuh-delete-sample.json; confirm source, candidate, actor null,
   exact event ID and UTC timestamp. No DB password is requested for preview.
3. Run check-db. Confirm MGMTNB08 / wazuh_audit_poc, required schema and counts.
4. Apply the sample once. Expect IMPORTED on an empty pilot namespace.
5. Run sql/002_verify_sample_import.sql. The same source/event has exactly one
   audit row and the candidate has one pending work item, version 1.
6. Apply the identical sample again. Expect DUPLICATE. Compare SQL results:
   event count, queue count, version, timestamps and lease values unchanged.
7. Import the raw inner _source object of the same event. Expect DUPLICATE.

## Further tests before a continuous collector or worker

Use an isolated test namespace and synthetic inputs, clearly labeled as such,
not modified copies masquerading as real audit history.

- Same key with changed source payload: CONFLICT, no committed queue/event edits.
- Two distinct event IDs for the same candidate: two audit rows, one queue row,
  event_version increases by one for each new event.
- Concurrent identical imports: one insert, the rest duplicate; no version bump
  for replays. A lock timeout should be reported and retried, not ignored.
- Queue write permission denied after audit insert: transaction rollback leaves
  no committed audit row. Use a restricted test account, not production changes.
- New event while processing: active lease and claimed_version remain intact;
  event_version increases. A future worker must notice the newer version.
- New event during retry: backoff and retry status preserved.
- Connection loss around commit: replay checks persistent identity/content.
- Invalid input, mismatched host, missing columns or wrong engine: no import.

This package contains no automated DB test that modifies users, permissions,
worker leases, deletes history, or creates/drops schemas. Such tests need an
explicitly isolated DB/test scope and an agreed cleanup procedure.
