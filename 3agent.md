# 3agent (legacy name — lanes 1–3)

> **Unified coordination:** [`AGENTS.md`](./AGENTS.md) (master board) and [`docs/AGENTS.md`](./docs/AGENTS.md) (per-lane checklists).
> Lanes **4–6** are overflow lanes.

## Session — 2026-07-05 (B-06 active)

| Gate | Status | Notes |
| --- | --- | --- |
| **CI #612** | In progress | `4bd43f2` (M2.5.29) — **do not push** until green (~70 min matrix) |
| **Nightly #56** | In progress | First Nightly on M2.5.19+ stack; monitor all 3 jobs |
| **B-05** Linux soak | Waiting | After B-06 green CI + soak dispatch |
| **M2.5.30** | **Done** (this commit) | UTF-8 board repair; `-text` gitattributes; validate-* path expansion |

### RC push embargo

No commits to `main` while CI #612 is in flight. Rapid pushes cancel the matrix and block `dispatch-nightly-rc`.

---

## Lanes 1–3 — Done / Doing / Next

| Lane | Done | Doing | Next |
| --- | --- | --- | --- |
| **1** RC core | M2.5.19 GHA rehearsal gates (`main`) | Monitor Nightly #56 participant + observer jobs | Triage `STAGE=` artifacts if ~11m fail |
| **2** RC ops | M2.5.24–M2.5.30 encoding stack (this commit) | - | B-05 soak evidence after green CI |
| **3** RC onboarding | M7.11 section 0 (`bb9600b`) | Monitor Nightly #56 ignored suite | Release evidence refresh after green Nightly |

---

## B-06 checklist (Nightly #56)

- [ ] CI #612 green on `4bd43f2`
- [ ] Nightly #56 — ignored suite PASS
- [ ] Nightly #56 — participant-rehearsal-smoke PASS
- [ ] Nightly #56 — observer-rehearsal-smoke PASS
- [ ] Agent 2 `release-evidence-refresh-for-head` on green SHA
- [ ] Update [`docs/TESTNET_CHECKLIST.md`](docs/TESTNET_CHECKLIST.md) + [`AGENTS.md`](AGENTS.md)

---

Update [`AGENTS.md`](AGENTS.md) for cross-lane detail; keep this file as the lanes 1–3 quick mirror.
