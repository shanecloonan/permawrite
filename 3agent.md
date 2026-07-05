# 3agent (legacy name — lanes 1–3)

> **Unified coordination:** [`AGENTS.md`](./AGENTS.md) (master board) and [`docs/AGENTS.md`](./docs/AGENTS.md) (per-lane checklists).
> Lanes **4–6** are overflow lanes.

## Session — 2026-07-05 (B-06 → Nightly #63)

| Gate | Status | Notes |
| --- | --- | --- |
| **Nightly #62** | **FAIL** | ~16.3m on `3a1f213` (pre M2.5.50 early P2P) |
| **M2.5.49** | **Done** (`8650543`) | GHA health + hub_liveness soft gates at tip>=1 |
| **M2.5.50** | **Done** (`dbf6067`) | Early `mfnd_p2p_listening`; POST_START health 120s |
| **M2.5.51** | **Done** (`0d9646a`) | `hub_tip_wait` uses `MFN_POLL_HUB_MAX`; observer catchup soft gate |
| **M2.5.52** | **Done** (`2904ea3`) | B-07 dispatch params + method-meta split |
| **CI #652** | **In progress** | On `bcf0bf5` (RC `0d9646a` + M2.5.52 `2904ea3`) |
| **Nightly #63** | Waiting | After green CI #652 (do not push until green) |

### RC push embargo

**No pushes to `main` until CI #652 green** — doc-only sync only after green or on CI failure fixes.

---

## Lanes 1–3 — Done / Doing / Next

| Lane | Done | Doing | Next |
| --- | --- | --- | --- |
| **1** RC core | M2.5.49–51 (`0d9646a`) | Monitor **CI #652** | **Nightly #63** (B-06) |
| **2** RC ops | M2.5.39–42; M2.5.48 | — | Release evidence after green Nightly |
| **3** RC onboarding | M7.11.2 Phase B | — | Participant + observer PASS on #63 |

---

## Nightly failure pattern (~16.3m)

| Run | SHA | Stack | Result |
| --- | --- | --- | --- |
| #58–61 | partial fixes | pre-38 / wrong SHA | FAIL ~16.3m |
| #62 | `3a1f213` | M2.5.38 + 43–45 | **FAIL** ~16.3m |
| #63 | pending | M2.5.49–52 | pending |

**Fix stack for #63:** M2.5.50 early P2P · M2.5.49 soft gates · M2.5.51 hub_tip poll · POST_START health trim.

---

## B-06 checklist

- [x] M2.5.38 + M2.5.43–45 on `main`
- [x] Nightly #62 executed (FAIL ~16.3m on `3a1f213`)
- [x] M2.5.49–52 on `main` (RC stack through `2904ea3`)
- [ ] **Nightly #63** all three green on M2.5.49–52 stack
- [ ] Release evidence refresh
- [ ] B-05 Linux soak evidence

---

Update [`AGENTS.md`](./AGENTS.md) for cross-lane detail.
