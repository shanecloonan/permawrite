# 3agent (legacy name — lanes 1–3)

> **Unified coordination:** [`AGENTS.md`](./AGENTS.md) (master board) and [`docs/AGENTS.md`](./docs/AGENTS.md) (per-lane checklists).
> Lanes **4–6** are overflow lanes.

## Session — 2026-07-05 (B-06 → Nightly #61)

| Gate | Status | Notes |
| --- | --- | --- |
| **M2.5.37** | **Done** (`12df02d`) | tip≥1 start-all; TCP RPC; hub_liveness 900s |
| **Nightly #60** | **FAIL** | ~16.3m on `54983c7` (M2.5.37) |
| **M2.5.38** | **Done** (`843e055`) | mfn-cli health probe; voter-dial both-listening soft gate |
| **CI #631** | **GREEN** | On `843e055` — Nightly #61 dispatched |
| **Nightly #61** | **In progress** | On `843e055` |
| **M2.5.39–42** | **Landing** | DOCS-QA-2 follow-up (lane 2) |

### RC push embargo

Lifted after CI #631 green; coordinate with lane 2 board sync before next push.

---

## Lanes 1–3 — Done / Doing / Next

| Lane | Done | Doing | Next |
| --- | --- | --- | --- |
| **1** RC core | M2.5.35–38 on `main` (`843e055`) | Monitor CI #631 | Nightly on `843e055` (B-06) |
| **2** RC ops | M2.5.39–42 (`4a1862b`) | M2.5.43–45 timeout dedup + deps | Nightly #61 evidence |
| **3** RC onboarding | M7.11.2 Phase B | — | Participant + observer PASS |

---

## Nightly #60 Post-Mortem (`54983c7`, ~16.3m)

| Job | Result | Notes |
| --- | --- | --- |
| ignored-integration | **PASS** | Stable |
| participant-rehearsal-smoke | **FAIL** | ~16.3m — still single 900s gate |
| observer-rehearsal-smoke | **FAIL** | Same class |

**M2.5.38 fix:** `query_get_status_compat_line` (mfn-cli tip first); unconditional GHA both-voters-listening soft gate; `MFN_REPO_ROOT` for health-check.

---

## B-06 checklist

- [x] M2.5.37 pushed; Nightly #60 ran (partial)
- [x] M2.5.38 pushed (`843e055`)
- [ ] Nightly on `843e055` — all three green
- [ ] Release evidence refresh
- [ ] B-05 Linux soak evidence

---

Update [`AGENTS.md`](./AGENTS.md) for cross-lane detail.
