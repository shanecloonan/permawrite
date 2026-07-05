# 3agent (legacy name — lanes 1–3)

> **Unified coordination:** [`AGENTS.md`](./AGENTS.md) (master board) and [`docs/AGENTS.md`](./docs/AGENTS.md) (per-lane checklists).
> Lanes **4–6** are overflow lanes.

## Session — 2026-07-05 (B-06 → Nightly #63)

| Gate | Status | Notes |
| --- | --- | --- |
| **M2.5.38** | **Done** (`843e055`) | mfn-cli health probe; voter-dial both-listening soft gate |
| **Nightly #60–62** | **FAIL** | ~16.3m — #62 on `3a1f213` (M2.5.38 + M2.5.43–45 stack) |
| **M2.5.39–42** | **Done** (`4a1862b`) | DOCS-QA-2; ci-check fast paths; P2P decode hardening |
| **M2.5.43–45** | **Done** (`b945f73`) | `rehearsal-poll-timeouts`; mfnd P2P dial/listen hardening |
| **M2.5.46–47** | **Done** (`2b33ced`) | B-07 `p2p_fanout` split + B-08 runner/mfnd_cli; `mfnd_serve` import fix |
| **M2.5.48** | **Done** (`040d31d`) | Debris purge; light-follow quorum expect removal |
| **M2.5.49** | **Done** (`8650543`) | GHA health + hub_liveness soft gates at tip>=1 |
| **M2.5.50** | **Done** (`dbf6067`) | Early P2P listen + POST_START ps1 parity |
| **CI #636** | **GREEN** | On `3a1f213` — Nightly #62 dispatched |
| **CI #643** | **In progress** | On `dbf6067` (M2.5.50) |
| **Nightly #63** | Waiting | After green CI on `dbf6067` |

### RC push embargo

Hold **code** pushes until CI #643 green; doc-only board sync OK.

---

## Lanes 1–3 — Done / Doing / Next

| Lane | Done | Doing | Next |
| --- | --- | --- | --- |
| **1** RC core | M2.5.35–38, M2.5.43–45, M2.5.49–50 (`dbf6067`) | Monitor CI #643 | **Nightly #63** (B-06) |
| **2** RC ops | M2.5.39–42; M2.5.48 | — | Release evidence after green Nightly |
| **3** RC onboarding | M7.11.2 Phase B | — | Participant + observer PASS |

---

## Nightly failure pattern (~16.3m)

| Run | SHA | Stack | Result |
| --- | --- | --- | --- |
| #58–61 | pre-38 / board-only | partial fixes | FAIL ~16.3m |
| #62 | `3a1f213` | M2.5.38 + 43–45 | **FAIL** ~16.3m |
| #63 | pending | + M2.5.49–50 | pending |

**M2.5.50 fix:** mfnd prints `mfnd_p2p_listening` before committee engine init; POST_START mesh health timeout exported.

---

## B-06 checklist

- [x] M2.5.38 + M2.5.43–45 on `main`
- [x] Nightly #62 ran (FAIL ~16.3m on `3a1f213`)
- [ ] **Nightly #63** all three green after M2.5.50
- [ ] Release evidence refresh
- [ ] B-05 Linux soak evidence

---

Update [`AGENTS.md`](./AGENTS.md) for cross-lane detail.
