# Step 10B acceptance

PASS requires:

1. Build and offline self-tests pass.
2. `solr_action_payload` exists and passes schema guard.
3. Latest Step 10A actions remain `planned`.
4. Delete action yields a stable `ready` delete-by-id JSON payload.
5. Index action reads only its exact approved FLOSVR01 source file.
6. Source metadata drift blocks payload generation rather than indexing stale data.
7. Legacy TXT/HTML/HTM extraction uses ReadAllText and applies the legacy empty-content test.
8. Word/PDF are blocked until their supplied legacy extractors are explicitly ported/validated.
9. Re-running Step 10B reuses stored reviewed payload rows.
10. No Solr update endpoint is called and no source file is modified.
