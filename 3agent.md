# 3agent (legacy name - lanes 1-3)

> **Unified coordination:** [`AGENTS.md`](./AGENTS.md) (master board) and [`docs/AGENTS.md`](./docs/AGENTS.md) (per-lane checklists).  
> Lanes **4-6** are overflow lanes for work the RC track does not own (M5 hardening, privacy surface, permanence depth).

## Done / Doing / Next (mandatory)

Every lane agent **must announce** what they finished, what they are doing, and what they will do next - in chat and on the boards. Full protocol: [`AGENTS.md` Agent announcement protocol](./AGENTS.md#agent-announcement-protocol-mandatory).

| When | Announce |
| --- | --- |
| Session start | Done + Doing + Next **before** coding |
| Claim unit | Update quick mirror **Doing** column + master board |
| Unit complete | Refresh **Done**; set **Next** handoff |
| Before push | Board matches the commit about to land |

## Lanes 1-3 quick mirror

| Lane | Done | Doing | Next |
| --- | --- | --- | --- |
| **1** RC core | M2.5.19 GHA rehearsal gates (`main`) | - | Nightly #56 after green CI (B-06) |
| **2** RC ops | M2.5.29 board sync (__COMMIT__); M2.5.28 (`99f5da2`); M2.5.27 (`aaf2246`) | - | B-05 soak evidence |
| **3** RC onboarding | M7.11 STORAGE_ACCESSIBILITY section 0 (`bb9600b`) | - | Monitor Nightly #56 smokes (B-06) |

**RC gate:** green CI on `main` -> auto-dispatch **Nightly #56** + **Linux Soak Audit** when evidence missing (`ci.yml`).

**Do not duplicate:** lanes 4-6 - see master board before starting M5/protocol/privacy-surface work. Lane 6 emission sim promotions are **closed** at M5.48.

Update [`AGENTS.md`](./AGENTS.md) instead of growing this file.