# 3agent (legacy name — lanes 1–3)

> **Unified coordination:** [`AGENTS.md`](./AGENTS.md) (master board) and [`docs/AGENTS.md`](./docs/AGENTS.md) (per-lane checklists).
> Lanes **4–6** are overflow lanes.

## Session — 2026-07-05 (B-06 → Nightly #63)

| Gate | Status | Notes |
| --- | --- | --- |
| **Nightly #62** | **FAIL** | ~16.3m on `3a1f213` (pre M2.5.50 early P2P) |
| **M2.5.49–51** | **Done** | Soft gates + early P2P + hub_tip poll (`0d9646a`) |
| **M2.5.52–54** | **Done** | B-07 god-file splits (`2904ea3` / `bd76bde` / `770e7a9`) |
| **CI #657** | **FAIL** | On `4cf43b3` (clippy path; fixed in M2.5.54) |
| **CI #659** | **In progress** | On `770e7a9` (M2.5.54) |
| **Nightly #63** | Waiting | After green CI on M2.5.49–54 stack |

### RC push embargo

Hold **code** pushes until **CI #659** green. Board sync only after green (avoids cancel-in-progress).

---

## Lanes 1–3 — Done / Doing / Next

| Lane | Done | Doing | Next |
| --- | --- | --- | --- |
| **1** RC core | M2.5.49–51 (`0d9646a`) | Monitor **CI #659** | **Nightly #63** (B-06) |
| **2** RC ops | M2.5.39–42; M2.5.48 | — | Release evidence after green Nightly |
| **3** RC onboarding | M7.11.2 Phase B | — | Participant + observer PASS on #63 |
| **4** Protocol | M2.5.52–54 B-07 splits | Idle | B-10 lane 6 |

---

## Nightly failure pattern (~16.3m)

| Run | SHA | Stack | Result |
| --- | --- | --- | --- |
| #58–61 | partial / wrong SHA | pre-38 | FAIL ~16.3m |
| #62 | `3a1f213` | M2.5.38 + 43–45 | **FAIL** ~16.3m |
| #63 | pending | M2.5.49–54 | pending |

**Fix stack for #63:** M2.5.50 early P2P announce · M2.5.49 soft gates · M2.5.51 hub_tip poll · POST_START health trim · M2.5.52–54 B-07 (compile hygiene only).

---

## B-06 checklist

- [x] M2.5.38 + M2.5.43–45 on `main`
- [x] Nightly #62 executed (FAIL ~16.3m on `3a1f213`)
- [x] M2.5.49–54 on `main`
- [ ] **Nightly #63** all three green on M2.5.54 stack
- [ ] Release evidence refresh
- [ ] B-05 Linux soak evidence

---

Update [`AGENTS.md`](./AGENTS.md) for cross-lane detail.
