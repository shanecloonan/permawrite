# 3agent (legacy name — lanes 1–3)

> **Unified coordination:** [`AGENTS.md`](./AGENTS.md) (master board) and [`docs/AGENTS.md`](./docs/AGENTS.md) (per-lane checklists).
> Lanes **4–6** are overflow lanes.

## Session — 2026-07-05 (B-06 → Nightly #63)

| Gate | Status | Notes |
| --- | --- | --- |
| **Nightly #62** | **FAIL** | ~16.3m on `3a1f213` |
| **M2.5.49–51** | **Done** | RC smoke soft gates + early P2P + hub_tip poll parity |
| **M2.5.52** | **Done** (`2904ea3`) | B-07 dispatch params + method-meta split |
| **M2.5.53** | **Done** (`bd76bde`) | B-07 `cli/parse.rs` split; `4cf43b3` restores accidental delete |
| **CI #658** | **In progress** | On `5c246d5` board sync (code `bd76bde`) |
| **CI #657** | **FAIL** | clippy/tests on `4cf43b3` (pre-hoist) |
| **Nightly #63** | Waiting | After green CI on M2.5.49–53 stack |

### RC push embargo

Hold **code** pushes until **CI #658** green. Doc-only board sync OK.

---

## Lanes 1–3 — Done / Doing / Next

| Lane | Done | Doing | Next |
| --- | --- | --- | --- |
| **1** RC core | M2.5.49–53 (`bd76bde`) | Monitor **CI #658** | **Nightly #63** (B-06) |
| **2** RC ops | M2.5.39–42; M2.5.48 | — | Release evidence after green Nightly |
| **3** RC onboarding | M7.11.2 Phase B | — | Participant + observer PASS |

---

## Lanes 4–6 snapshot

| Lane | Done | Doing | Next |
| --- | --- | --- | --- |
| **4** Protocol | M2.5.52–53 B-07 splits (`bd76bde`) | — | Idle (B-07 complete) |
| **5** Privacy | Wallet README ring-16 | — | Monitor Nightly #63 |
| **6** Permanence | M5.48 emission tier | — | B-05 Linux soak |

---

## B-06 checklist

- [x] Nightly #62 executed (FAIL ~16.3m)
- [x] M2.5.49–53 on `main` (`bd76bde` code tip)
- [ ] **Nightly #63** all three green
- [ ] Release evidence refresh
- [ ] B-05 Linux soak evidence

---

Update [`AGENTS.md`](./AGENTS.md) for cross-lane detail.
