# 3agent (legacy name — lanes 1–3)

> **Unified coordination:** [`AGENTS.md`](./AGENTS.md) (master board) and [`docs/AGENTS.md`](./docs/AGENTS.md) (per-lane checklists).
> Lanes **4–6** are overflow lanes.

## Session — 2026-07-05 (B-06 → Nightly #63)

| Gate | Status | Notes |
| --- | --- | --- |
| **Nightly #62** | **FAIL** | ~16.3m on `3a1f213` |
| **M2.5.49–51** | **Done** | RC smoke soft gates + early P2P + hub_tip poll (`0d9646a`) |
| **M2.5.52–53** | **Done** | B-07 dispatch + `cli/parse.rs` splits (`2904ea3` / `bd76bde`) |
| **M2.5.55–56** | **Done** | Byzantine light test + anyhow 1.0.103 (`6fe1b18`) |
| **M2.5.57–58** | **Done** | DOCS-QA-2 + schema-python resolver (`3e994b9` / `c0e73eb`) |
| **CI #667** | **In progress** | On `70d97c6` (code `c0e73eb`) |
| **Nightly #63** | Waiting | After green CI #667 |

### RC push hold

Doc-only board sync OK. Hold **code** pushes until **CI #667** green.

---

## Lanes 1–3 — Done / Doing / Next

| Lane | Done | Doing | Next |
| --- | --- | --- | --- |
| **1** RC core | M2.5.49–53 (`bd76bde`) | Monitor **CI #667** | **Nightly #63** (B-06) |
| **2** RC ops | M2.5.39–42; M2.5.57–58 | — | Release evidence after green CI + Nightly |
| **3** RC onboarding | M7.11.2 Phase B | — | Participant + observer PASS on #63 |

---

## Lanes 4–6 snapshot

| Lane | Done | Doing | Next |
| --- | --- | --- | --- |
| **4** Protocol | M2.5.52–53 B-07 + M2.5.55 light test | — | Idle |
| **5** Privacy | Wallet README ring-16 | — | Monitor Nightly #63 |
| **6** Permanence | M5.48; M2.5.56 B-10 | — | B-05 Linux soak |

---

## B-06 checklist

- [x] Nightly #62 executed (FAIL ~16.3m on `3a1f213`)
- [x] M2.5.49–58 on `main` (`c0e73eb` code tip)
- [ ] **Nightly #63** all three green
- [ ] Release evidence refresh (after green CI)
- [ ] B-05 Linux soak evidence

---

Update [`AGENTS.md`](./AGENTS.md) for cross-lane detail.
