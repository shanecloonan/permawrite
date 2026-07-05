# 3agent (legacy name - lanes 1-3)

> **Unified coordination:** [`AGENTS.md`](./AGENTS.md) (master board) and [`docs/AGENTS.md`](./docs/AGENTS.md) (per-lane checklists).
> Lanes **4-6** are overflow lanes.

## Session — 2026-07-05 (B-06 / M2.5.32)

| Gate | Status | Notes |
| --- | --- | --- |
| **M2.5.31** | **Done** (`0e0de4e`) | GHA polls 900s; health 900s; nightly 90m; workflow_run Nightly backup |
| **M2.5.32** | **WIP** (this commit) | `.gitignore` debris; board mojibake guards; clean `docs/AGENTS.md` |
| **CI #622** | **In progress** | `f4b5e37` — hold push until green (~70 min) |
| **Nightly #57** | Waiting | Auto-dispatch after green CI #622 |

### RC push embargo

No commits to `main` while CI #622 is in flight.

---

## Lanes 1-3 — Done / Doing / Next

| Lane | Done | Doing | Next |
| --- | --- | --- | --- |
| **1** RC core | M2.5.31 (`0e0de4e`) | Idle — monitor CI #622 | Nightly #57 triage (B-06) |
| **2** RC ops | M2.5.30 encoding (`2eb8417`) | M2.5.32 hygiene + guards | Release evidence after Nightly #57 |
| **3** RC onboarding | M7.11 (`bb9600b`) | Monitor B-06 | Participant + observer PASS |

---

## B-06 checklist

- [x] Nightly #56 ran (pre-M2.5.31 stack)
- [ ] Green CI #622 on `f4b5e37`
- [ ] Nightly #57 all-3-jobs green
- [ ] Release evidence refresh
- [ ] B-05 Linux soak evidence

---

Update [`AGENTS.md`](./AGENTS.md) for cross-lane detail.
