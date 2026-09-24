# Step 15 acceptance — controlled 25-candidate rollout

## Goal

Expand the validated five-candidate pilot to exactly 25 candidates without weakening any existing safety control.

## Scope

The only active candidate IDs are:

```text
1180000 through 1180023, plus 1180097
```

Root-wide candidate processing is forbidden.

## Required acceptance evidence

1. Build succeeds with zero errors/warnings and all self-tests pass.
2. `Step15-Preflight.cmd` can read metadata for all 25 folders.
3. Exact 25-candidate collision audit returns `SafeToExpandScope=True`.
4. `Step15-Baseline-Capture.cmd` preserves existing approved baseline rows and creates pending rows for uncaptured candidates.
5. `Step15-Baseline-Status.cmd` shows no newly added candidate as approved without explicit operator approval.
6. FLOSVR01 `ossec.conf` contains exactly 25 managed candidate-specific realtime FIM entries and no root-wide candidate monitor.
7. FLOSVR01 manager remains `MGMTNB08`; Step 15 scope migration must not reintroduce a DHCP IPv4 manager address.
8. After activation, Step 13 supervisor/tunnel/pipeline are healthy.
9. Status exposes all 25 candidate states independently.
10. A Wazuh event for a newly added pending candidate advances its worker state but remains `BaselineReviewRequired`.
11. Pending candidate does not run Step 10A, Step 10B, Step 11 preflight, or any Solr update.
12. Approved candidates retain the existing manual `READY_FOR_APPROVAL` → explicit Step 11 `--apply` boundary.
13. One candidate source/recovery failure remains isolated by the Step 14D safeguards.
14. No automatic Solr apply is introduced.

## Rollout rule

Passing Step 15 does not authorize bulk baseline approval or a larger cohort. Expansion beyond 25 requires a separate reviewed step with fresh collision audit and operational evidence.
