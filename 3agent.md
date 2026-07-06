# 3agent (legacy name — lanes 1–3)

> **Unified coordination:** [`AGENTS.md`](./AGENTS.md) (master board) and [`docs/AGENTS.md`](./docs/AGENTS.md) (per-lane checklists).
> Lanes **4–6** are overflow lanes.

## Session — 2026-07-05 (B-06 → Nightly #63)

| Gate | Status | Notes |
| --- | --- | --- |
| **Nightly #62** | **FAIL** | ~16.3m on `3a1f213` |
| **M2.5.49–61** | **Done** | RC stack through mfnd_smoke stdout-order fix (`1603e43`) |
| **CI** | **GREEN** | On `1603e43` (run `28774283620`, 2026-07-06 10:05 UTC) — first green matrix since M2.5.50 |
| **Nightly #63** | **In progress** | Auto-dispatched on green push, with Linux Soak Audit |

### RC push hold

**All lanes:** no pushes while CI runs on `main` (`cancel-in-progress` ~70 min).

---

## Lanes 1–3 — Done / Doing / Next

| Lane | Done | Doing | Next |
| --- | --- | --- | --- |
| **1** RC core | M2.5.49–61; CI green `1603e43` | Monitor **Nightly #63** | Release evidence after green Nightly |
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
- [x] M2.5.49–61 on `main`
- [x] First green CI on the stack (`1603e43`, run `28774283620`)
- [ ] **Nightly #63** all three green
- [ ] Release evidence refresh
- [ ] B-05 Linux soak evidence

---

Update [`AGENTS.md`](./AGENTS.md) for cross-lane detail.
