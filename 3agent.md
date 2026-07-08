# 3agent (legacy name — lanes 1–3)

> **Unified coordination:** [`AGENTS.md`](./AGENTS.md) (master board) and [`docs/AGENTS.md`](./docs/AGENTS.md) (per-lane checklists).
> Lanes **4–6** are overflow lanes.

## Session — 2026-07-07 PM (F7 proptest + emission sim two-input alignment)

| Gate | Status | Notes |
| --- | --- | --- |
| **F7 proptest tail** | **This commit** | `apply_block_proptest` + `emission_simulation` recycle companion pad input (F7 floor) |
| **F7 smoke/wallet** | **Done** — `81849c8` | Two-block fund + `owned_count>=2` poll before upload |
| **CI #28915985296** | **Monitor** | Prior push `81849c8`; proptest fix follows |

### RC push hold

**Lift after green** — one proptest commit landing now; wait for matrix on head before further pushes.

### Next priority

**Lane 2:** release evidence on green head. **Lane 4+6:** B3 replication accounting.

---

## Session — 2026-07-07 PM (F7 auto-fanout wallet sync → CI `#28915985296`)

| Gate | Status | Notes |
| --- | --- | --- |
| **F7 wallet sync** | **Done** — `81849c8` | `f7_wallet_fund.rs` polls `owned_count>=2` before auto-fanout upload |
| **CI #28915800187** | **Cancelled** | Superseded by `81849c8` push |
| **CI #28915985296** | **In progress** | `81849c8` full matrix |

### RC push hold

**Active** — monitor CI `#28915985296`; no code pushes until green.

### Next priority

**Lane 2:** release evidence on `81849c8` after green. **Lane 6:** B3 replication accounting seed.

---

| Gate | Status | Notes |
| --- | --- | --- |
| **F7 smoke fund** | **Done** — `7a68cc5` | `FUND_WALLET_BLOCKS=2` across mfn-cli smokes |
| **F7 smoke heights** | **Done** — `b00b7dd` | `last_proven_height=4` in chunk/operator smokes |
| **CI #28915800187** | **In progress** | `b00b7dd` full matrix (rustfmt/clippy green) |
| **B2 + F7 stack** | **Done** | `20954b0` + `3933cf0` on `main` |

### RC push hold

**Active** — no code pushes while CI `#28915800187` runs (`cancel-in-progress`).

### Next priority

**Lane 1:** Nightly dispatch after CI green. **Lane 2:** release evidence on `b00b7dd`. **Lane 6:** B3 replication accounting seed.

---

## Session — 2026-07-07 PM (F7 consensus min-input floor)

| Gate | Status | Notes |
| --- | --- | --- |
| **F7 tail** | **Done** — `3933cf0` | `RingPolicy.min_input_count = 2` at `verify_transaction` (uniform tier) |
| **B2 ChunkV2** | **Done** | `20954b0` on `main` |
| **CI #28915343380** | **Failed** — `last_proven_height` off-by-one | **Fixed** — `b00b7dd` |
| **CI #28915800187** | **Superseded** | Cancelled by `b00b7dd` push |

### RC push hold

**Active** — monitor CI on `b00b7dd` (F7 smoke height tail fix).

### Next priority

**Lane 2:** release evidence refresh on `3933cf0` after green CI. **Lane 6:** B3 replication accounting.

---

## Session — 2026-07-07 PM (B2 ChunkV2 Merkle-path gossip)

| Gate | Status | Notes |
| --- | --- | --- |
| **B2 ChunkV2** | **This commit** | `0x12` Merkle-proven chunk gossip; fan-out + operator push emit v2; v1 inbound still accepted |
| **CI / Nightly / RC** | **GREEN** | Prior stack on `96462aa` |
| **Release evidence** | **Done** | `96462aa` + RC audit dry-run **go** |

### RC push hold

**Lifted** until CI on this commit completes.

### Next priority (lane 4+5)

**F7 consensus tail** — `min_input_count` enforcement at `verify_transaction`.

---

## Session — 2026-07-07 PM (revisions — B-11 doc accuracy + gate sync)

| Gate | Status | Notes |
| --- | --- | --- |
| **CI / Nightly / RC** | **GREEN** | No open failures on `96462aa` stack |
| **Release evidence** | **Done** | `96462aa` + RC audit dry-run **go** |
| **Doc fix** | **This commit** | `STORAGE.md` + `PERMANENCE_HARDENING.md` §A6/B1: MFEO opening shipped; stale lane checkboxes cleared |
| **B-11 + B7 stack** | **Done** | MFEO genesis + dandelion rehearsal PASS |

### RC push hold

**Lifted** — full matrix + Nightly green on B-11/B7 stack.

---

## Session — 2026-07-07 (RC stack complete → F7 tail next)

| Gate | Status | Notes |
| --- | --- | --- |
| **Release evidence** | **Done** | `44b25b6` + RC audit dry-run **go** |
| **Nightly #28889931523** | **GREEN** | All three jobs on `b1072e3` stack |
| **CI #28885223488** | **GREEN** | `0d28e4f` B7 dandelion rehearsal evidence |
| **B-11 MFEO** | **Done** | Public devnet genesis `require_endowment_opening: 1` |
| **B-05 soak** | **Done** | `28851202993` max_height=48 |

### RC push hold

**Lifted** — full matrix + Nightly green on B-11/B7 stack.

### Next priority (lane 4+5)

**F7 consensus tail** — `min_input_count` enforcement at `verify_transaction` (network-wide Monero-default tx shape closure).

---

## Session — 2026-07-07 (B7 dandelion rehearsal → CI GREEN on `0d28e4f`)

| Gate | Status | Notes |
| --- | --- | --- |
| **Nightly #28889931523** | **GREEN** | All three jobs on `b1072e3` stack |
| **CI #28885223488** | **GREEN** | Run on `0d28e4f` (B7 dandelion evidence) |
| **CI #28879533724** | **GREEN** | Run on `0fee187` (B-11 public devnet MFEO) |
| **Nightly #28884769330** | **GREEN** | All three jobs on B-11 stack |
| **Release evidence** | **Done** | `1bbc3af` + RC audit go |
| **B7 dandelion rehearsal** | **Done** | `0d28e4f` — Windows PASS with MFEO upload |

### RC push hold

**Lifted** — full matrix green on B-11 + B7 evidence stack.

---

## Session — 2026-07-07 (B-11 public devnet enable → CI on stack)

| Gate | Status | Notes |
| --- | --- | --- |
| **CI #726** | **GREEN** | Run `28871239057` on `837069a` (full matrix) |
| **Nightly #65** | **GREEN** | Run `28877033241` on `837069a` (all three jobs) |
| **B-11 proptests** | **Done** | `9f0a0aa` — MFEO opening + reject without `MFEO` |
| **B-11 public devnet** | **This commit** | `require_endowment_opening: 1` in genesis JSON + spec parser |
| **Release evidence** | **Done** | `837069a` artifacts + ancestor CI lookup fix |

### RC push hold

**Lifted** — CI `28871239057` GREEN; Nightly `28877033241` GREEN.

---

## Session — 2026-07-07 (B-05 soak PASS → release evidence refresh)

| Gate | Status | Notes |
| --- | --- | --- |
| **B-05 Linux soak** | **PASS** | Soak `28851202993` max_height=48 (`234f0a8`) |
| **CI #720** | **In progress** | Run `28853929754` on `234f0a8` |
| **Nightly #63/#64** | **GREEN** | `28792429191` / `28841761235` |
| **B13 stack** | **Done** | `934cc2f` — CI #28838850432 GREEN |

### RC push hold

**Active** — CI `28853929754` in progress on `234f0a8`. Lane 2 runs `release-evidence-refresh-for-head -RunRcAuditDryRun` after green.

---

## Session — 2026-07-06 (B-06 closed → B13 + B7 CI fix)

| Gate | Status | Notes |
| --- | --- | --- |
| **Nightly #63** | **GREEN** | Run `28792429191` (all three jobs) |
| **B-06** | **Done** | CI `1603e43` + Nightly participant/observer PASS |
| **B13 wallet** | **Done** | `4712811` — size buckets on upload |
| **B13 consensus** | **Done** | `3d8574c` — bucket gate + `anchored_payload` artifacts |
| **M2.5.64 soak** | **Done** | `c5e69f6` — workflow pre-build + `start-all --no-build` |
| **B7 Dandelion++** | **Done** | `1cc9ead` — opt-in `--dandelion` (default off) |
| **B13 spora fix** | **Done** | `96fe808` — revert auto-pad in `build_storage_commitment`; test parity `e98ff4f` |
| **B13 authorship** | **Done** | `5d5cf64` CLI/wallet + `7821099` WASM — padded preview for MFCL `data_root` |
| **GHA hub timing** | **Done** | `934cc2f` — `GITHUB_ACTIONS` detection for 20s mesh budget |
| **Nightly #64** | **GREEN** | Run `28841761235` on `934cc2f` stack (auto-dispatched) |
| **B-05 Linux soak** | **Done** | Soak `28851202993` PASS max_height=48 (`234f0a8`) |

### RC push hold

**Lifted.** CI #28838850432 GREEN on `934cc2f`.

---

## Lanes 1–3 — Done / Doing / Next

| Lane | Done | Doing | Next |
| --- | --- | --- | --- |
| **1** RC core | Nightly green; smoke fixes `7a68cc5`/`b00b7dd` | **Monitor** CI `#28915800187` | Nightly after green |
| **2** RC ops | F7+B2 on `main` | **Waiting** — evidence after CI green | Human sign-off packet |
| **3** RC onboarding | B7 dandelion PASS; Nightly green | — | Idle |

---

## Lanes 4–6 snapshot

| Lane | Done | Doing | Next |
| --- | --- | --- | --- |
| **4** Protocol | F7 `3933cf0` + B2 `20954b0` | — | B3 replication accounting |
| **5** Privacy | F7 consensus tail (`3933cf0`) | — | B8 Tor transport (research) |
| **6** Permanence | B2 (`20954b0`) | — | B3 replication accounting |

---

## B-06 checklist

- [x] Nightly #62 executed (FAIL ~16.3m)
- [x] M2.5.49–61 on `main`
- [x] **Nightly #63** all three green (`28792429191`)
- [x] B13 wallet + consensus on `main`
- [x] M2.5.64 soak bootstrap (`c5e69f6`)
- [x] B7 Dandelion++ phase 1 (`1cc9ead`)
- [x] Green CI on B13 stack (CI #28838850432 on `934cc2f`)
- [x] Nightly #64 green (`28841761235`)
- [x] B-05 Linux soak evidence (soak `28851202993` PASS, `234f0a8`)

---

Update [`AGENTS.md`](./AGENTS.md) for cross-lane detail.
