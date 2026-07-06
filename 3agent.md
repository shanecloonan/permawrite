# 3agent (legacy name — lanes 1–3)

> **Unified coordination:** [`AGENTS.md`](./AGENTS.md) (master board) and [`docs/AGENTS.md`](./docs/AGENTS.md) (per-lane checklists).
> Lanes **4–6** are overflow lanes.

## Session — 2026-07-05 (B-06 → Nightly #63)

| Gate | Status | Notes |
| --- | --- | --- |
| **Nightly #62** | **FAIL** | ~16.3m on `3a1f213` |
| **M2.5.49–51** | **Done** | RC smoke soft gates + early P2P + hub_tip poll (`0d9646a`) |
| **M2.5.52–54** | **Done** | B-07 god-file splits (`2904ea3` / `bd76bde` / `770e7a9`) |
| **M2.5.55–56** | **Done** | Byzantine light test + anyhow 1.0.103 (`6fe1b18`) |
| **CI #657** | **FAIL** | Pre-hoist clippy/tests on `4cf43b3` |
| **CI #663** | **In progress** | On `6903413` (code `6fe1b18`) |
| **Nightly #63** | Waiting | After green CI #663 |

### RC push hold

No pushes while **CI #663** runs (`cancel-in-progress`).

---

## Lanes 1–3 — Done / Doing / Next

| Lane | Done | Doing | Next |
| --- | --- | --- | --- |
| **1** RC core | M2.5.49–51 | Monitor **CI #663** | **Nightly #63** (B-06) |
| **2** RC ops | M2.5.39–42; M2.5.48 | — | Release evidence after green Nightly |
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
- [x] M2.5.49–56 on `main`
- [ ] **Nightly #63** all three green
- [ ] Release evidence refresh
- [ ] B-05 Linux soak evidence

---

Update [`AGENTS.md`](./AGENTS.md) for cross-lane detail.
