# 3agent (legacy name - lanes 1-3)

> **Unified coordination:** [`AGENTS.md`](./AGENTS.md) (master board) and [`docs/AGENTS.md`](./docs/AGENTS.md) (per-lane checklists).
> Lanes **4-6** are overflow lanes.

## Session — 2026-07-05 (B-06 triage)

| Gate | Status | Notes |
| --- | --- | --- |
| **Nightly #56** | **PARTIAL** | `4bd43f2` — ignored **PASS**; participant+observer **FAIL** ~13m |
| **M2.5.31** | WIP (this commit) | GHA polls 900s; voter soft gate tip≥1; health 900s; nightly 90m |

### RC push embargo

No commits to `main` while CI is in progress on the release candidate SHA.

---

## Lanes 1-3 — Done / Doing / Next

| Lane | Done | Doing | Next |
| --- | --- | --- | --- |
| **1** RC core | M2.5.19 GHA gates | M2.5.31 mesh poll hardening | Monitor Nightly #57 after green CI |
| **2** RC ops | M2.5.30 encoding stack (`6e99a9e`) | M2.5.31 workflow_run + ci-check | Push after green CI |
| **3** RC onboarding | M7.11 section 0 (`bb9600b`) | B-06 triage | Release evidence after green Nightly |

---

## B-06 checklist

- [x] Nightly #56 ran on M2.5.29+ stack
- [ ] Nightly all-3-jobs green
- [ ] Green CI on M2.5.31 commit
- [ ] Agent 2 release-evidence refresh
- [ ] B-05 Linux soak evidence

---

Update [`AGENTS.md`](./AGENTS.md) for cross-lane detail.
