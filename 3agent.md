# 3agent (legacy name — lanes 1–3)

> **Unified coordination:** [`AGENTS.md`](./AGENTS.md) (master board) and [`docs/AGENTS.md`](./docs/AGENTS.md) (per-lane checklists).
> Lanes **4–6** are overflow lanes.

## Session — 2026-07-06 (B-06 closed → B13 + B7 CI fix)

| Gate | Status | Notes |
| --- | --- | --- |
| **Nightly #63** | **GREEN** | Run `28792429191` (all three jobs) |
| **B-06** | **Done** | CI `1603e43` + Nightly participant/observer PASS |
| **B13 wallet** | **Done** | `4712811` — size buckets on upload |
| **B13 consensus** | **Done** | `3d8574c` — bucket gate + `anchored_payload` artifacts |
| **M2.5.64 soak** | **Done** | `c5e69f6` — workflow pre-build + `start-all --no-build` |
| **B7 Dandelion++** | **Done** | `1cc9ead` — opt-in `--dandelion` (default off) |
| **B13 spora fix** | **Done** | `96fe808` — revert auto-pad in `build_storage_commitment`; test parity `e98ff4f` |
| **B13 authorship** | **Done** | `5d5cf64` CLI/wallet + `7821099` WASM — padded preview for MFCL `data_root` |
| **GHA hub timing** | **Done** | `934cc2f` — `GITHUB_ACTIONS` detection for 20s mesh budget |
| **Nightly #64** | **GREEN** | Run `28841761235` on `934cc2f` stack (auto-dispatched) |
| **B-05 Linux soak** | **In progress** | Run `28841761161` (M2.5.64 pre-build bootstrap) |

### RC push hold

**Lifted.** CI #28838850432 GREEN on `934cc2f`.

---

## Lanes 1–3 — Done / Doing / Next

| Lane | Done | Doing | Next |
| --- | --- | --- | --- |
| **1** RC core | CI #28838850432; Nightly #64 | **B-05 soak** run `28841761161` | Release evidence refresh |
| **2** RC ops | M2.5.57–59; Nightly #63 | — | Release evidence refresh on `934cc2f` |
| **3** RC onboarding | M7.11.2; Nightly #63 PASS | — | Monitor B-05 soak PASS |

---

## Lanes 4–6 snapshot

| Lane | Done | Doing | Next |
| --- | --- | --- | --- |
| **4** Protocol | B13 consensus gate `3d8574c` | — | B-11 endowment opening |
| **5** Privacy | B13 full stack; B4 decoys; B7 `1cc9ead` | — | B7 rehearsal soak + B9 view tags |
| **6** Permanence | M5.48; M2.5.56 B-10 | — | B-05 Linux soak evidence |

---

## B-06 checklist

- [x] Nightly #62 executed (FAIL ~16.3m)
- [x] M2.5.49–61 on `main`
- [x] **Nightly #63** all three green (`28792429191`)
- [x] B13 wallet + consensus on `main`
- [x] M2.5.64 soak bootstrap (`c5e69f6`)
- [x] B7 Dandelion++ phase 1 (`1cc9ead`)
- [x] Green CI on B13 stack (CI #28838850432 on `934cc2f`)
- [x] Nightly #64 green (`28841761235`)
- [ ] B-05 Linux soak evidence (run `28841761161` in progress)

---

Update [`AGENTS.md`](./AGENTS.md) for cross-lane detail.
