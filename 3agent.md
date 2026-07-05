# 3agent (legacy name ╬ô├ç├╢ lanes 1╬ô├ç├┤3)

> **Unified coordination:** [`AGENTS.md`](./AGENTS.md) (master board) and [`docs/AGENTS.md`](./docs/AGENTS.md) (per-lane checklists).  
> Lanes **4╬ô├ç├┤6** are overflow lanes for work the RC track does not own (M5 hardening, privacy surface, permanence depth).

## Done / Doing / Next (mandatory)

Every lane agent **must announce** what they finished, what they are doing, and what they will do next ╬ô├ç├╢ in chat and on the boards. Full protocol: [`AGENTS.md` Γö¼┬║ Agent announcement protocol](./AGENTS.md#agent-announcement-protocol-mandatory).

| When | Announce |
| --- | --- |
| Session start | Done + Doing + Next **before** coding |
| Claim unit | Update quick mirror **Doing** column + master board |
| Unit complete | Refresh **Done**; set **Next** handoff |
| Before push | Board matches the commit about to land |

## Lanes 1╬ô├ç├┤3 quick mirror

| Lane | Done | Doing | Next |
| --- | --- | --- | --- |
| **1** RC core | M2.5.19 GHA rehearsal gates (`main`) | ╬ô├ç├╢ | Nightly #56 after green CI (B-06) |
| **2** RC ops | M2.5.28 consolidated RC encoding guard (this commit) + M2.5.27 docs mirror | - | B-05 soak evidence |
| **3** RC onboarding | M7.11 STORAGE_ACCESSIBILITY section 0 (this commit) | - | Monitor Nightly #56 smokes (B-06) |

**RC gate:** green CI on `main` ╬ô├Ñ├å auto-dispatch **Nightly #56** + **Linux Soak Audit** when evidence missing (`ci.yml`).

**Do not duplicate:** lanes 4╬ô├ç├┤6 ╬ô├ç├╢ see master board before starting M5/protocol/privacy-surface work.

Update [`AGENTS.md`](./AGENTS.md) instead of growing this file.
