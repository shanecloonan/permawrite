# 3agent (legacy name — lanes 1–3)

> **Unified coordination:** [`AGENTS.md`](./AGENTS.md) (master board) and [`docs/AGENTS.md`](./docs/AGENTS.md) (per-lane checklists).
> Lanes **4–6** are overflow lanes.

## Session — 2026-07-06 (B-06 closed → B13)

| Gate | Status | Notes |
| --- | --- | --- |
| **Nightly #63** | **GREEN** | Run `28792429191` (all three jobs, 2026-07-06) |
| **B-06** | **Done** | CI `1603e43` + Nightly participant/observer PASS |
| **B13 wallet** | **Done** | `4712811` — size buckets on upload |
| **B13 consensus** | **Done** | `3d8574c` — bucket gate + `anchored_payload` artifacts |
| **B13 compile fix** | **Landing** | spora pad + wasm `&data`; fixes CI #28833777805 |
| **M2.5.64 soak** | **Landing** | workflow pre-build + `start-all --no-build` |

### RC push hold

No pushes while CI in flight on `main` (`cancel-in-progress`).

---

## Lanes 1–3 — Done / Doing / Next

| Lane | Done | Doing | Next |
| --- | --- | --- | --- |
| **1** RC core | M2.5.49–61; Nightly #63; B13 | **M2.5.64** + compile fix push | B-05 soak after green CI |
| **2** RC ops | M2.5.57–59; Nightly #63 | — | Release evidence refresh |
| **3** RC onboarding | M7.11.2; Nightly #63 PASS | — | Monitor soak |

---

## Lanes 4–6 snapshot

| Lane | Done | Doing | Next |
| --- | --- | --- | --- |
| **4** Protocol | B13 consensus gate `3d8574c` | — | B-11 endowment opening |
| **5** Privacy | B13 wallet `4712811`; B4 decoys | — | B7 Dandelion++ (WIP separate) |
| **6** Permanence | M5.48; M2.5.56 B-10 | — | B-05 Linux soak |

---

## B-06 checklist

- [x] Nightly #62 executed (FAIL ~16.3m)
- [x] M2.5.49–61 on `main`
- [x] **Nightly #63** all three green (`28792429191`)
- [x] B13 wallet + consensus on `main`
- [ ] B13 compile fix + M2.5.64 green CI
- [ ] Release evidence refresh
- [ ] B-05 Linux soak evidence

---

Update [`AGENTS.md`](./AGENTS.md) for cross-lane detail.
