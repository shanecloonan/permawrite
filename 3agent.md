# 3agent (legacy name — lanes 1–3)

> **Unified coordination:** [`AGENTS.md`](./AGENTS.md) (master board) and [`docs/AGENTS.md`](./docs/AGENTS.md) (per-lane checklists).
> Lanes **4–6** are overflow lanes.

## Session — 2026-07-05 (B-06 → Nightly #58)

| Gate | Status | Notes |
| --- | --- | --- |
| **CI #625** | **GREEN** | `15fd4c7` — M2.5.34 macOS threads=2 |
| **Nightly #57** | **PARTIAL** | ignored **PASS**; smokes **FAIL** ~16m on `15fd4c7` |
| **M2.5.35** | **Done** (`f16bbb6`) | parallel voter poll; tip≥2 dial fallback; pushed |
| **CI #626** | **GREEN** | `f16bbb6` — all matrix jobs pass |
| **Nightly #58** | **FAIL** | ~16.3m on `f16bbb6` — same 900s class as #57 |
| **M2.5.36/37** | **Landing** | TCP RPC helper; start-all tip≥1 only; hub_liveness 900s |
| **Nightly #59** | Waiting | After green CI on M2.5.37 |

### RC push embargo

Board handoff `cfd5c8f` pushed. **Hold code pushes** until Nightly #58 completes (M2.5.36 queued locally).

---

## Lanes 1–3 — Done / Doing / Next

| Lane | Done | Doing | Next |
| --- | --- | --- | --- |
| **1** RC core | M2.5.35 on `main`; M2.5.36/37 local | **M2.5.37** start-all tip gate fix | Nightly #59 (B-06) |
| **2** RC ops | CI #625 green; M2.5.32 debris gitignore | — | Release evidence after green Nightly |
| **3** RC onboarding | M7.11.2 Phase B doc sync | — | Participant + observer PASS |

---

## Nightly #57 Post-Mortem (`15fd4c7`, ~16m)

| Job | Result | Notes |
| --- | --- | --- |
| ignored-integration | **PASS** | Stable |
| participant-rehearsal-smoke | **FAIL** | ~16m — mesh startup / health gate |
| observer-rehearsal-smoke | **FAIL** | Same class |

**M2.5.35 fix:** parallel GHA voter P2P poll; curl-first health-check on GHA; tip≥2 chain-live voter-dial fallback; `STAGE=start_mesh_fail` logging.

---

## B-06 checklist

- [x] CI green on M2.5.34 (`15fd4c7`)
- [x] Nightly #57 ran (partial)
- [x] Nightly #58 on `f16bbb6` — **PARTIAL** (ignored **PASS**; smokes **FAIL** ~16.3m).
- [ ] **M2.5.36/37** → Nightly #59 all three green
- [ ] Release evidence refresh
- [ ] B-05 Linux soak evidence

---

Update [`AGENTS.md`](./AGENTS.md) for cross-lane detail.
