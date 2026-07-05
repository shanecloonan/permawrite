# 3agent (legacy name - lanes 1-3)

> **Unified coordination:** [`AGENTS.md`](./AGENTS.md) (master board) and [`docs/AGENTS.md`](./docs/AGENTS.md) (per-lane checklists).
> Lanes **4-6** are overflow lanes.

## Session — 2026-07-05 (B-06)

| Gate | Status | Notes |
| --- | --- | --- |
| **M2.5.31** | **Done** (`0e0de4e`) | GHA polls 900s; health 900s; nightly 90m; workflow_run Nightly backup |
| **CI #619** | In progress | `0e0de4e` — **do not push** until green (~70 min) |
| **Nightly #56** | FAIL | `4bd43f2` — ignored PASS; participant+observer FAIL ~11m (pre-M2.5.31) |
| **Nightly #57** | Waiting | Dispatches after green CI #619 |

### RC push embargo

No commits to `main` while CI #619 is in flight.

---

## Lanes 1-3 — Done / Doing / Next

| Lane | Done | Doing | Next |
| --- | --- | --- | --- |
| **1** RC core | M2.5.31 mesh hardening (`0e0de4e`) | Monitor CI #619 | Nightly #57 triage |
| **2** RC ops | M2.5.30 encoding (`6e99a9e`) | Wait CI green | Release evidence after Nightly #57 |
| **3** RC onboarding | M7.11 section 0 (`bb9600b`) | Monitor B-06 | Observer/participant smoke PASS |

---

## B-06 checklist

- [x] Nightly #56 ran (pre-M2.5.31 stack)
- [ ] Green CI #619 on `0e0de4e`
- [ ] Nightly #57 all-3-jobs green
- [ ] Release evidence refresh
- [ ] B-05 Linux soak evidence

---

Update [`AGENTS.md`](./AGENTS.md) for cross-lane detail.
