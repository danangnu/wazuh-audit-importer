# Step 14E pilot evidence carried forward

This file summarizes the acceptance evidence already exercised before Step 14E reporting. It is intended as a concise operator record; the live Step 14E report independently reads current database and Solr/FLOSVR01 state.

## Proven in the pilot

- Wazuh realtime FIM on FLOSVR01 captures candidate file changes.
- Wazuh event ingestion is deduplicated and preserves audit history.
- Candidate reconciliation uses FLOSVR01 as the source of truth; raw delete events are triggers, not direct Solr deletes.
- Continuous collector and worker recover from normal restarts and duplicate polling windows.
- Step 10A generates concrete delete/index actions using Solr GET plus FLOSVR01 metadata.
- Step 10B generates legacy-compatible reviewed payloads and blocks unsupported/empty legacy content cases.
- Step 11 requires explicit `--apply`, performs post-claim live revalidation, ordered POSTs, explicit commit, and post-commit GET verification.
- Step 12/14B/14C/14D orchestration never invokes Solr apply automatically.
- Step 13 supervisor rebuilds the SSH Indexer tunnel and repairs WAZUH-LAB forwarding after VM restart; actual WAZUH-LAB DHCP IP change recovery was exercised.
- Step 14A audited 100 controlled candidates and found no true cross-candidate legacy-ID collision; two verified repository-root aliases were normalized as non-blocking.
- Step 14B reconciled a second candidate independently and exposed/cleaned pre-existing candidate-level Solr drift under explicit review.
- Step 14C baseline enrollment blocks newly allowlisted candidates with historical drift until exact reviewed baseline approval.
- Step 14D recovery inspection never authorizes blind retry; source/payload drift after review was rejected and replaced by a fresh mutation/version.

## Current rollout controls

- explicit five-candidate allowlist only;
- candidate baseline enrollment/review gate;
- cross-candidate collision audit before expansion;
- manual approval before Solr write;
- live source/payload/Solr revalidation before write;
- recovery inspection for uncertain execution states;
- no broad root-wide automatic candidate processing.

## Deferred to maintenance window

Two live disruption tests are intentionally deferred because intentionally breaking live dependencies is not necessary for the pilot:

1. candidate-specific FLOSVR01 source-folder unavailability;
2. production Solr GET outage/isolation.

The offline policy tests and Step 14D recovery logic cover these paths, but final live disruption evidence should be gathered during an approved maintenance window.
