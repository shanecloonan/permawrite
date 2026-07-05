# 3agent (legacy name - lanes 1-3)

> **Unified coordination:** [`AGENTS.md`](./AGENTS.md) (master board) and [`docs/AGENTS.md`](./docs/AGENTS.md) (per-lane checklists).
> Lanes **4-6** are overflow lanes.

## Session - 2026-07-05 (B-06 -> Nightly #63)

| Gate | Status | Notes |
| --- | --- | --- |
| **Nightly #62** | **FAIL** | ~16.3m on `3a1f213` |
| **M2.5.49-50** | **Done** | `8650543`/`dbf6067` smoke soft gates + early P2P listen |
| **M2.5.51** | **Landing** | hub_tip_wait=MFN_POLL_HUB_MAX; observer catchup soft gate |
| **CI #645** | **In progress** | On `cc8bee0` (board handoff) |
| **Nightly #63** | Waiting | After green CI on M2.5.51 |

### RC push embargo

Lift after CI #645 green; M2.5.51 code push dispatches fresh CI.

---

## Lanes 1-3 - Done / Doing / Next

| Lane | Done | Doing | Next |
| --- | --- | --- | --- |
| **1** RC core | M2.5.49-50 | M2.5.51 hub tip + observer soft gates | **Nightly #63** (B-06) |
| **2** RC ops | M2.5.39-42; M2.5.48 | - | Release evidence after green Nightly |
| **3** RC onboarding | M7.11.2 Phase B | - | Participant + observer PASS |

Update [`AGENTS.md`](./AGENTS.md) for cross-lane detail.
