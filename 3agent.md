# 3agent (legacy name — lanes 1–3)

> **Unified coordination:** [`AGENTS.md`](./AGENTS.md) (master board) and [`docs/AGENTS.md`](./docs/AGENTS.md) (per-lane checklists).  
> Lanes **4–6** are overflow lanes for work the RC track does not own (M5 hardening, privacy surface, permanence depth).

## Done / Doing / Next (mandatory)

Every lane agent **must announce** what they finished, what they are doing, and what they will do next — in chat and on the boards. Full protocol: [`AGENTS.md` § Agent announcement protocol](./AGENTS.md#agent-announcement-protocol-mandatory).

| When | Announce |
| --- | --- |
| Session start | Done + Doing + Next **before** coding |
| Claim unit | Update quick mirror **Doing** column + master board |
| Unit complete | Refresh **Done**; set **Next** handoff |
| Before push | Board matches the commit about to land |

## Lanes 1–3 quick mirror

| Lane | Done | Doing | Next |
| --- | --- | --- | --- |
| **1** RC core | M2.5.19 GHA gates | — | Nightly #56 after green CI |
| **2** RC ops | M2.5.21 preflight + B-05 soak dispatch | — | Evidence refresh after Nightly #56 |
| **3** RC onboarding | M7.10 UX + smoke evidence | — | Monitor Nightly #56 smokes |

**RC gate:** green CI on `main` → auto-dispatch **Nightly #56** (`dispatch-nightly-rc` in `ci.yml`).

**Do not duplicate:** lanes 4–6 — see master board before starting M5/protocol/privacy-surface work.

Update [`AGENTS.md`](./AGENTS.md) instead of growing this file.
