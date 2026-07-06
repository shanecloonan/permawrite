# 3agent (legacy name — lanes 1–3)

> **Unified coordination:** [`AGENTS.md`](./AGENTS.md) (master board) and [`docs/AGENTS.md`](./docs/AGENTS.md) (per-lane checklists).
> Lanes **4–6** are overflow lanes.

## Session — 2026-07-05 (B-06 → Nightly #63)

| Gate | Status | Notes |
| --- | --- | --- |
| **Nightly #62** | **FAIL** | ~16.3m on `3a1f213` |
| **M2.5.49–59** | **Done** | RC stack through invoke fix (`b1c8e6a`) |
| **M2.5.59** | **Done** | `b1c8e6a` — invoke fix + `.gitignore` debris patterns |
| **CI #680** | **In progress** | On `e101f3a` (board sync) |
| **Nightly #63** | Waiting | After green CI #680 on `b1c8e6a` |

### RC push hold

Hold **code** pushes until **CI #680** green.

---

## Lanes 1–3 — Done / Doing / Next

| Lane | Done | Doing | Next |
| --- | --- | --- | --- |
| **1** RC core | M2.5.49–59 | Monitor **CI #680** on `e101f3a` | **Nightly #63** (B-06) |
| **2** RC ops | M2.5.57–59 | **M2.5.60** gitignore + audit doc closure | Release evidence when CI green |
| **3** RC onboarding | M7.11.2 Phase B | — | Participant + observer PASS on #63 |

---

## Lanes 4–6 snapshot

| Lane | Done | Doing | Next |
| --- | --- | --- | --- |
| **4** Protocol | M2.5.52–55 B-07/B-08 | — | Idle |
| **5** Privacy | Wallet README ring-16 | — | Monitor Nightly #63 |
| **6** Permanence | M5.48; M2.5.56 B-10 | — | B-05 Linux soak |

---

## B-06 checklist

- [x] Nightly #62 executed (FAIL ~16.3m)
- [x] M2.5.49–59 on `main` (code `b1c8e6a`)
- [ ] Release evidence refresh for `b1c8e6a` after green CI
- [ ] **Nightly #63** all three green
- [ ] B-05 Linux soak evidence

---

Update [`AGENTS.md`](./AGENTS.md) for cross-lane detail.
