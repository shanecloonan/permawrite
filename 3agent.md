# 3agent (legacy name — lanes 1–3)

> **Unified coordination:** [`AGENTS.md`](./AGENTS.md) (master board) and [`docs/AGENTS.md`](./docs/AGENTS.md) (per-lane checklists).
> Lanes **4–6** are overflow lanes.

## Session — 2026-07-05 (B-06 → Nightly #59)

| Gate | Status | Notes |
| --- | --- | --- |
| **CI #626** | **GREEN** | `f16bbb6` — M2.5.35 |
| **Nightly #58** | **PARTIAL** | smokes FAIL ~16.3m on `f16bbb6` (start-all tip≥2 gate) |
| **M2.5.37** | **Done** (`12df02d`) | tip≥1 start-all; TCP RPC; hub_liveness 900s |
| **CI #629** | **GREEN** | `54983c7` — stats refresh atop M2.5.37 |
| **Nightly #60** | **In progress** | On `54983c7` — first run with M2.5.37 fixes |

### RC push embargo

`12df02d` pushed. Hold further pushes until CI #628 green → **Nightly #59**.

---

## Lanes 1–3 — Done / Doing / Next

| Lane | Done | Doing | Next |
| --- | --- | --- | --- |
| **1** RC core | M2.5.35–37 on `main` (`12df02d`) | Monitor CI #628 → Nightly on `12df02d` | B-06 all three green |
| **2** RC ops | CI #626–627 green | — | Release evidence after green Nightly |
| **3** RC onboarding | M7.11.2 Phase B doc sync | — | Participant + observer PASS |

---

## Nightly #58 Post-Mortem (`f16bbb6`, ~16.3m)

| Job | Result | Notes |
| --- | --- | --- |
| ignored-integration | **PASS** | Stable |
| participant-rehearsal-smoke | **FAIL** | ~16.3m — `start-all` tip≥2 @ 900s duplicate gate |
| observer-rehearsal-smoke | **FAIL** | Same class |

**M2.5.37 fix:** start-all GHA tip≥1 (600s); tip≥2 in `hub_liveness` (900s); `query_rpc_json_line` TCP RPC.

---

## B-06 checklist

- [x] CI green on M2.5.34 (`15fd4c7`)
- [x] Nightly #57 ran (partial)
- [x] Nightly #58 on `f16bbb6` — **PARTIAL** (ignored **PASS**; smokes **FAIL** ~16.3m).
- [x] **M2.5.37** (`12df02d`) pushed — awaiting Nightly on `12df02d` (CI #628 dispatch)
- [ ] Release evidence refresh
- [ ] B-05 Linux soak evidence

---

Update [`AGENTS.md`](./AGENTS.md) for cross-lane detail.
