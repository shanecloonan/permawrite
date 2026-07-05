# 3agent (legacy name — lanes 1–3)

> **Unified coordination:** [`AGENTS.md`](./AGENTS.md) (master board) and [`docs/AGENTS.md`](./docs/AGENTS.md) (per-lane checklists).
> Lanes **4–6** are overflow lanes.

## Session — 2026-07-05 (B-06 → Nightly #62)

| Gate | Status | Notes |
| --- | --- | --- |
| **M2.5.38** | **Done** (`843e055`) | mfn-cli health probe; voter-dial both-listening soft gate |
| **Nightly #60–61** | **FAIL** | ~16.3m — #60 on M2.5.37; #61 on pre-fix board SHA `4de1585` |
| **M2.5.39–42** | **Done** (`4a1862b`) | DOCS-QA-2; ci-check fast paths; P2P decode hardening |
| **M2.5.43–45** | **Done** (`b945f73`) | `rehearsal-poll-timeouts`; mfnd P2P dial/listen hardening |
| **CI #634** | **In progress** | On `df8d985` — dispatches **Nightly #62** when green |
| **Nightly #62** | Waiting | First full stack: M2.5.38 + M2.5.43–45 on `df8d985` |

### RC push embargo

Hold **code** pushes until CI #634 green. Doc-only board sync OK after green.

---

## Lanes 1–3 — Done / Doing / Next

| Lane | Done | Doing | Next |
| --- | --- | --- | --- |
| **1** RC core | M2.5.35–38, M2.5.43–45 (`df8d985`) | Monitor CI #634 | **Nightly #62** (B-06) |
| **2** RC ops | M2.5.39–42; CI fast paths | — | Release evidence after green Nightly |
| **3** RC onboarding | M7.11.2 Phase B | — | Participant + observer PASS |

---

## Nightly failure pattern (~16.3m)

| Run | SHA | M2.5.38? | Result |
| --- | --- | --- | --- |
| #58–60 | pre-38 / 37 | partial / yes | FAIL ~16.3m |
| #61 | `4de1585` | board only | FAIL ~16.3m |
| #62 | `df8d985` | **yes + 43–45** | pending |

**Fix stack on `df8d985`:** M2.5.37 tip≥1 gate · M2.5.38 mfn-cli health · M2.5.43 shared poll timeouts · mfnd P2P no-panic dial.

---

## B-06 checklist

- [x] M2.5.38 + M2.5.43–45 on `main`
- [ ] **Nightly #62** all three green on `df8d985`
- [ ] Release evidence refresh
- [ ] B-05 Linux soak evidence

---

Update [`AGENTS.md`](./AGENTS.md) for cross-lane detail.
