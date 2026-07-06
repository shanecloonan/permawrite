# 3agent (legacy name — lanes 1–3)

> **Unified coordination:** [`AGENTS.md`](./AGENTS.md) (master board) and [`docs/AGENTS.md`](./docs/AGENTS.md) (per-lane checklists).
> Lanes **4–6** are overflow lanes.

## Session — 2026-07-05 (B-06 → Nightly #63)

| Gate | Status | Notes |
| --- | --- | --- |
| **Nightly #62** | **FAIL** | ~16.3m on `3a1f213` |
| **M2.5.49–51** | **Done** | RC smoke soft gates + early P2P + hub_tip poll parity |
| **M2.5.52** | **Done** (`2904ea3`) | B-07 dispatch params + method-meta split |
| **M2.5.53** | **Done** (`4cf43b3`) | B-07 `cli/parse.rs` split; restore accidental delete |
| **CI #657** | **In progress** | On `4cf43b3` |
| **M2.5.54** | **Landing** | cli.rs mod order + test import fix |
| **Nightly #63** | Waiting | After green CI on RC stack |

### RC push embargo

Hold until **CI #657** result; M2.5.54 fix push only if #657 red on clippy/tests.

---

## Lanes 1–3 — Done / Doing / Next

| Lane | Done | Doing | Next |
| --- | --- | --- | --- |
| **1** RC core | M2.5.49–51 | Monitor CI #657 | **Nightly #63** (B-06) |
| **2** RC ops | M2.5.39–42; M2.5.48 | — | Release evidence after green Nightly |
| **3** RC onboarding | M7.11.2 Phase B | — | Participant + observer PASS |

---

## Lanes 4–6 snapshot

| Lane | Done | Doing | Next |
| --- | --- | --- | --- |
| **4** Protocol | M2.5.52–53 B-07 splits | M2.5.54 cli.rs hygiene | B-07 `cli.rs` remainder |
| **5** Privacy | Wallet README ring-16 | — | Monitor Nightly #63 |
| **6** Permanence | M5.48 emission tier | — | B-05 Linux soak |

---

## B-06 checklist

- [x] Nightly #62 executed (FAIL ~16.3m)
- [x] M2.5.49–53 on `main`
- [ ] **Nightly #63** all three green
- [ ] Release evidence refresh
- [ ] B-05 Linux soak evidence

---

Update [`AGENTS.md`](./AGENTS.md) for cross-lane detail.
