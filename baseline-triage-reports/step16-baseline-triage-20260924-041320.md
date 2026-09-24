# Step 16 Baseline Triage

Read-only triage of the controlled 25-candidate cohort. Only `CLEANPENDING` rows are eligible for the Step 16 clean-only approval command; no drifted candidate is auto-approved.

| Candidate | Enrollment | Triage | Clean approval | Match | Missing | Stale | Other |
|---|---|---|---:|---:|---:|---:|---:|
| 1180000 | pending | ModerateDrift | NO | 0 | 4 | 4 | 0 |
| 1180001 | approved | Approved | NO | 1 | 0 | 0 | 0 |
| 1180002 | pending | SmallDrift | NO | 0 | 1 | 1 | 0 |
| 1180003 | pending | SmallDrift | NO | 0 | 2 | 2 | 0 |
| 1180004 | pending | ModerateDrift | NO | 0 | 1 | 5 | 0 |
| 1180005 | pending | SmallDrift | NO | 0 | 1 | 3 | 0 |
| 1180006 | pending | SmallDrift | NO | 0 | 2 | 2 | 0 |
| 1180007 | pending | SmallDrift | NO | 0 | 1 | 1 | 0 |
| 1180008 | pending | HighDrift | NO | 3 | 3 | 158 | 0 |
| 1180009 | pending | SmallDrift | NO | 0 | 1 | 1 | 0 |
| 1180010 | pending | ModerateDrift | NO | 2 | 1 | 4 | 0 |
| 1180011 | pending | SmallDrift | NO | 0 | 1 | 1 | 0 |
| 1180012 | pending | SmallDrift | NO | 0 | 1 | 1 | 0 |
| 1180013 | pending | CleanPending | YES | 6 | 0 | 0 | 0 |
| 1180014 | pending | SmallDrift | NO | 0 | 1 | 1 | 0 |
| 1180015 | pending | SmallDrift | NO | 0 | 1 | 1 | 0 |
| 1180016 | pending | SmallDrift | NO | 0 | 1 | 2 | 0 |
| 1180017 | pending | SmallDrift | NO | 0 | 1 | 2 | 0 |
| 1180018 | pending | ModerateDrift | NO | 0 | 2 | 3 | 0 |
| 1180019 | pending | SmallDrift | NO | 1 | 1 | 0 | 0 |
| 1180020 | approved | Approved | NO | 1 | 0 | 0 | 0 |
| 1180021 | pending | SmallDrift | NO | 2 | 1 | 1 | 0 |
| 1180022 | pending | SmallDrift | NO | 3 | 1 | 1 | 0 |
| 1180023 | pending | ModerateDrift | NO | 2 | 2 | 4 | 0 |
| 1180097 | approved | Approved | NO | 1 | 0 | 0 | 0 |

High-drift, conflict, stale-capture and other drifted baselines remain operator-gated. This report does not authorize Solr writes.
