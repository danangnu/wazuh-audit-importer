# Step 10B acceptance

PASS requires:

1. Build and offline self-tests pass.
2. `solr_action_payload` exists and passes schema guard.
3. Latest Step 10A actions remain `planned`.
4. Delete action yields a stable `ready` delete-by-id JSON payload.
5. Index action reads only its exact approved FLOSVR01 source file.
6. Source metadata drift blocks payload generation rather than indexing stale data.
7. Legacy TXT/HTML/HTM extraction uses ReadAllText and applies the legacy empty-content test.
8. `.doc`, `.docx`, `.docm`, and `.rtf` use Aspose.Words 24.9.0 `Document.ToString(SaveFormat.Text)` and the exact legacy evaluation-banner cleanup; extraction failures are blocked.
9. PDF remains blocked until PDFBox 1.8.2 is ported and validated.
10. Re-running Step 10B reuses stored reviewed payload rows.
11. No Solr update endpoint is called and no source file is modified.
