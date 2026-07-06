# 3agent (legacy name — lanes 1–3)

> **Unified coordination:** [`AGENTS.md`](./AGENTS.md) (master board) and [`docs/AGENTS.md`](./docs/AGENTS.md) (per-lane checklists).
> Lanes **4–6** are overflow lanes.

## Session — 2026-07-05 (B-06 → Nightly #63)

| Gate | Status | Notes |
| --- | --- | --- |
| **Nightly #62** | **FAIL** | ~16.3m on `3a1f213` |
| **M2.5.49–60** | **Done** | RC stack through clippy unwrap gate (M2.5.60, this commit) |
| **CI #682+** | **In progress** | `cancel-in-progress` — latest push wins |
| **Nightly #63** | Waiting | After first green CI on the stack |

### RC push hold

**All lanes:** no pushes while CI runs on `main` (`cancel-in-progress` ~70 min).

---

## Lanes 1–3 — Done / Doing / Next

| Lane | Done | Doing | Next |
| --- | --- | --- | --- |
| **1** RC core | M2.5.49–59 | Monitor **CI #682+** | **Nightly #63** (B-06) |
| **2** RC ops | M2.5.57–59 | — | Release evidence after green Nightly |
| **3** RC onboarding | M7.11.2 Phase B | — | Participant + observer PASS on #63 |

---

## Lanes 4–6 snapshot

| Lane | Done | Doing | Next |
| --- | --- | --- | --- |
| **4** Protocol | M2.5.52–55 B-07/B-08; M2.5.60 clippy unwrap gate | — | Idle |
| **5** Privacy | Wallet README ring-16 | — | Monitor Nightly #63 |
| **6** Permanence | M5.48; M2.5.56 B-10 | — | B-05 Linux soak |

---

## B-06 checklist

- [x] Nightly #62 executed (FAIL ~16.3m)
- [x] M2.5.49–59 on `main`
- [ ] **Nightly #63** all three green
- [ ] Release evidence refresh
- [ ] B-05 Linux soak evidence

---

Update [`AGENTS.md`](./AGENTS.md) for cross-lane detail.
