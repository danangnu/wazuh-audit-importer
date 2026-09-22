# Step 7 acceptance — continuous candidate worker

Step 7 adds the `work` command. It continuously polls `candidate_work_queue`, claims
one due candidate using the existing lease/version rules, reads only file metadata
under the explicitly supplied SMB/local candidate root, writes an immutable local
snapshot, and completes only the claimed queue version.

## Required pilot tests

1. Start the existing continuous Wazuh collector in one terminal.
2. Start the continuous worker in another terminal:

   ```powershell
   dotnet .\src\WazuhAuditImporter\bin\Debug\net9.0\WazuhAuditImporter.dll `
       work `
       --worker-root "\\FLOSVR01\FastTrack\Candidate\To 1189999" `
       --state-dir "C:\Users\dnurdiansyah\Documents\NewAllied\WazuhAuditImporter\worker-state"
   ```

3. Create a unique test file in candidate `1180097`. Confirm the collector increments
   `event_version` and the worker automatically reports `ADD` and returns the queue to
   `completed` without running `work-once`.
4. Modify the same test file. Confirm automatic `CHANGE` reconciliation.
5. Delete the test file. Confirm automatic `REMOVE` reconciliation.
6. Stop the worker with Ctrl+C. Confirm a clean shutdown message.
7. With the worker stopped, create another candidate event and let the collector queue
   it. Restart `work`; confirm it claims the already-pending version and completes it.
8. Temporarily make the worker root unavailable only in a controlled lab test. Confirm
   the item moves to `retry` and no missing folder is treated as an empty folder.

## PASS criteria

- No manual `work-once` is needed for new queue items.
- `event_version == completed_version` after the worker catches up.
- `claimed_version` and `lease_token` are cleared after successful completion.
- A newer event arriving during processing leaves the row pending for another pass.
- Temporary SMB/I/O failures enter retry and never generate mass REMOVE output.
- Ctrl+C stops the loop cleanly.
- No source files are changed and no Solr writes occur.
