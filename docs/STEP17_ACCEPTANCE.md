# Step 17 Acceptance — controlled SmallDrift enrollment

## Scope

Step 17 does not expand the 25-candidate FIM/importer allowlist and does not enable automatic Solr writes. It introduces a deliberately narrow approval path for the initial three `SmallDrift` candidates:

- `1180002`
- `1180007`
- `1180009`

The initial policy accepts only an unchanged pending baseline with exactly **one current file missing in Solr**, exactly **one stale Solr document**, and **zero other conflicts**.

## Safety model

1. Revalidate the exact stored baseline fingerprint against current FLOSVR01 metadata + Solr GET.
2. Require the candidate to be in the three-candidate Step 17 batch.
3. Require exactly `missing=1`, `stale=1`, `other=0` and Step 16 disposition `SmallDrift`.
4. Print the exact current missing path/expected ID and stale Solr path/current ID.
5. Preview approval without DB status change.
6. `--apply` requires explicit `--ack-small-drift` and records baseline enrollment in MariaDB only.
7. Approval does **not** repair Solr. Historical drift remains until a later candidate reconciliation mutation is reviewed through Step 10A/10B/11 and explicitly applied.
8. Pipeline orchestration never performs automatic Solr update/delete/add/commit requests.

## Build gate

Stop Step 13 before replacing/building the Debug DLL, then run:

```powershell
.\Restore-And-Preview.cmd
```

Expected:

```text
Build succeeded.
0 Warning(s)
0 Error(s)
Self-tests: 136/136 passed; 0 failed.
```

No database migration is required.

## Read-only preflight

```powershell
.\Step17-Preflight.cmd
```

Expected for each initial candidate:

```text
fingerprint_match=true
missing=1
stale=1
other=0
step17_approval=YES
```

The report must show the exact missing current canonical path and exact stale Solr path. No approval or Solr write occurs.

## Individual preview and approval

Preview one candidate first, beginning with `1180002`:

```powershell
.\Step17-Approve-SmallDrift.cmd 1180002 <baseline-sha256>
```

The preview must show the same exact one-missing/one-stale evidence and say that no baseline status or Solr write occurred.

After operator review:

```powershell
.\Step17-Approve-SmallDrift.cmd 1180002 <baseline-sha256> --ack-small-drift --apply
```

The apply step records baseline approval only. It must explicitly state that historical drift remains until a separately reviewed reconciliation mutation is applied.

## Post-approval check

```powershell
.\Step17-PostApproval-Check.cmd
```

Pass criteria:

- selected candidate is `APPROVED`;
- other initial-batch candidates remain pending until separately reviewed;
- no uncertain processing/failed mutation is introduced;
- no automatic Solr apply occurs.

## Controlled reconciliation after enrollment

Do not modify a real candidate document merely to force a mutation. Use a **legacy-filtered `DNI_...` trigger file** on FLOSVR01 if a controlled event is needed. A persistent filtered file can generate a candidate inventory event while remaining excluded from Solr indexing. Review the resulting candidate-level mutation/actions before any explicit Step 11 apply.

The Step 10A action list is the authoritative Solr mutation plan; Step 17 review output is baseline evidence, not an authorization to delete/index documents.
