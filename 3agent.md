# 3agent (legacy name — lanes 1–3)

> **Unified coordination:** [`AGENTS.md`](./AGENTS.md) (master board) and [`docs/AGENTS.md`](./docs/AGENTS.md) (per-lane checklists).
> Lanes **4–6** are overflow lanes.

## 3-agent checklist (live)

| Agent / lane | Done | Doing | Next |
| --- | --- | --- | --- |
| **1** RC core | B3 M5.41 `3de427b` | **CI #28934551469** (matrix tests) | Nightly after green |
| **2** RC ops | TL-3 evidence `46677ad` | Idle | Evidence refresh on green head |
| **3** Onboarding | `dc22cb7` fund-wallet F7 top-up | Idle | Participant rehearsal after Nightly green |
| **4+6** Protocol | B3 treasury `88457df`, M5.41 `3de427b` | **B3 phase 3a** (this push) | `StorageOperatorRegister` bond wire (3b) |
| **7** Testnet | TL-1–TL-6 tooling `ef3cbc4` | Await VPS provision | TL-5 soak + TL-6 rehearsal evidence |

---

## Session — 2026-07-08 (B3 phase 3a — operator registry + apply_block gate)

| Unit | Status | Notes |
| --- | --- | --- |
| **B3 phase 3a** | **Done** — this push | `require_registered_operators`; `storage_operators` map; checkpoint **v6**; `StorageProofUnregisteredOperator`; 2× `block_apply` registry tests |
| **CI #28934551469** | **In progress** | `3de427b` — clippy/scripts GREEN; matrix tests running |
| **B3 phase 3b** | **Next** | Signed `StorageOperatorRegister` + bond escrow wire |

**Lane 4+6 — Done:** B3 phase 3a **Doing:** push + CI **Next:** operator register bond op (3b)

---

## Session — 2026-07-08 (CI script fix + B3 M5.40 proptest)

| Unit | Status | Notes |
| --- | --- | --- |
| **Ubuntu scripts CI** | **Fix** — this push | `participant-rehearsal-smoke.sh` plan flow `start-all` not `start-all.sh` |
| **M5.41** | **Done** — this push | `prop_b3_two_operator_proof_chain_treasury` (1–8 blocks) |
| **B3 phase 3 design** | **Seed** | Operator registry sketch in `PERMANENCE_HARDENING.md` |

**Lane 4+6 — Done:** M5.41 proptest **Next:** operator registry wire

---

## Session — 2026-07-08 (B3 treasury settlement + clippy fix)

| Unit | Status | Notes |
| --- | --- | --- |
| **Clippy** | **Fix** — this push | `manual-range-patterns` in checkpoint decode (`3..=5`) |
| **B3 treasury** | **Done** — this push | `storage_proof_operator_settlements` mirrors `apply_block`; proptest treasury identity |
| **CI #28933248309** | **Failed** clippy | Superseded by this push |

**Lane 4+6 — Done:** B3 treasury mirror **Doing:** — **Next:** operator bonding registry

---

## Session — 2026-07-08 (B3 phase 2 — apply_block replication accounting)

| Unit | Status | Notes |
| --- | --- | --- |
| **B3 phase 2** | **Done** — this push | `operator_salted_challenges` flag; per-operator dedup; replication cap; payout split; checkpoint v5 |
| **B3 tests** | **Done** | 4× `block_apply` B3 tests; clippy + fmt green |
| **CI** | **Monitor** | Prior `#28930546797` on `eea59aa`; this push dispatches new matrix |

**Lane 4+6 — Done:** B3 phase 2 **Doing:** — **Next:** operator bonding registry + M5 proptests

---


| Unit | Status | Notes |
| --- | --- | --- |
| **TL-5 scripts** | **Done** — `5a74d57` | `vps-preflight.sh`, `vps-internet-soak.sh`, `soak.sh --vps`, `vps-bind-lib.sh` |
| **TL-5 execution** | **Blocked** | Requires provisioned Linux VPS + `vps-bind.env` |
| **CI** | **Monitor** | Push `5a74d57` stack (`b70b3ec`/`dc22cb7`/`5a74d57`) |

**Lane 7 — Done:** TL-1–TL-5 tooling **Doing:** await VPS **Next:** `vps-internet-soak.sh` + archive evidence

---

## Session — 2026-07-08 (F7 fund-wallet top-up → Nightly rehearsal fix)

| Gate | Status | Notes |
| --- | --- | --- |
| **fund-wallet F7** | **Done** — `dc22cb7` | `--min-owned-count 2` default; top-up until `owned_count>=2` |
| **CI #28929146881** | **In progress** | `dc22cb7` — closes Nightly upload 1-input failure |
| **CI #28924060054** | **GREEN** | `e7d74f7` full F7 test tail |

**Lanes 1+3 — Done:** CI green, TL-4 VPS `2f77eb4` **Doing:** fund-wallet F7 top-up **Next:** push → Nightly re-dispatch → TL-5 VPS soak

---

| Unit | Status | Notes |
| --- | --- | --- |
| **CI #28924060054** | **GREEN** | `e7d74f7` — full matrix ~48m; closes TL-2 |
| **TL-3 evidence** | **Done** | `release-evidence-46677ad` + RC audit dry-run `go` |
| **TL-4 VPS runbook** | **Done** — `2f77eb4` | `vps-start-all.sh`, `VPS_SINGLE_BOX_LAUNCH.md`, P2P bind env |

**Lane 7 — Done:** TL-1–TL-4 **Doing:** *(idle — VPS provision)* **Next:** TL-5 internet soak

---

## Session — 2026-07-08 (F7 mempool tail → CI `#28924060054`)

| Gate | Status | Notes |
| --- | --- | --- |
| **mempool F7** | **Done** — `e7d74f7` | `mfn-runtime` test helpers: companion pad + two-input `signed_tx` / `signed_storage_tx` |
| **CI #28924060054** | **GREEN** | `e7d74f7` — full matrix pass |
| **Prior CI #28921758809** | **Cancelled** | `0825385` — superseded by mempool fix push |

**Lanes 1–3 — Done:** mempool `e7d74f7`, CI `#28924060054` GREEN, TL-3 evidence **Doing:** TL-4 VPS (lane 7) **Next:** Nightly (lane 1) → TL-5 soak (lane 7) → B3 (lanes 4+6)

---

## Session — 2026-07-08 (F7 mfnd_smoke tail → CI `#28921758809`)

| Gate | Status | Notes |
| --- | --- | --- |
| **mfnd_smoke F7** | **Done** — `0825385` | `synth_decoy_*` fixture: `step --blocks 2` → two UTXOs → two-input transfer |
| **CI #28921758809** | **In progress** | `0825385` — clippy/rustfmt/audit/wasm/scripts GREEN; matrix tests running |
| **Prior CI #28919128030** | **Failed** | `996f60f` — 5 mfnd_smoke mempool/P2P tests: 1-input txs rejected |

**Lanes 1–3 — Done:** settlement `996f60f`, mfnd_smoke `0825385` **Doing:** CI monitor `#28921758809` **Next:** release evidence (lane 2) → Nightly (lane 1) → B3 (lanes 4+6)

---

## Session — 2026-07-08 (F7 settlement tail → CI `#28919128030`)

| Gate | Status | Notes |
| --- | --- | --- |
| **F7 settlement tests** | **Done** — `996f60f` | `producer_treasury_settlement.rs` two-input pad recycle across all call sites |
| **CI #28919128030** | **In progress** | `996f60f` — clippy/rustfmt/scripts GREEN; matrix tests running |
| **Prior CI #28917267975** | **Failed** | `a6aebab` — settlement still 1-input (fixed by `996f60f`) |

**Lanes 1–3 — Done:** F7 settlement `996f60f`, TL-1 charter `8661106` **Doing:** CI monitor `#28919128030` **Next:** release evidence (lane 2) → Nightly (lane 1) → B3 (lanes 4+6)

---

## Session — 2026-07-08 (Lane 7 TL-2 — mempool F7 two-input pad)

| Unit | Status | Notes |
| --- | --- | --- |
| **TL-2 mempool fix** | **Done** — `e7d74f7` | `mfn-runtime` test helpers: companion pad + two-input `signed_tx` |
| **CI #28924060054** | **In progress** | `e7d74f7` full matrix |
| **Prior** | **Done** | `996f60f` settlement + `0825385` mfnd_smoke |

**Lane 7 — Done:** TL-1 (`8661106`), mempool `e7d74f7` **Doing:** TL-2 CI monitor **Next:** TL-3 release evidence on green head

---

## Session — 2026-07-08 (Lane 7 testnet launch — TL-1)

| Unit | Status | Notes |
| --- | --- | --- |
| **Lane 7 charter** | **Done** — `8661106` | `docs/TESTNET_LAUNCH.md`, `launch-status.*`, `.cursor/rules/lane-7-testnet-launch.mdc` |
| **TL-2** | **In progress** | CI `#28919128030` on `996f60f` must green before release-evidence refresh |

**Lane 7 — Done:** TL-1 **Doing:** TL-2 CI monitor **Next:** TL-3 release evidence + RC audit dry-run

---

## Session — 2026-07-08 AM (F7 stack CI `#28917267975` on `a6aebab`)

| Gate | Status | Notes |
| --- | --- | --- |
| **F7 full test tail** | **Done** — `a6aebab` | smoke `81849c8` + proptest `4a320ad` + block_apply `668cf17` + clippy fix |
| **CI #28917267975** | **In progress** | clippy/rustfmt/audit/wasm/scripts **GREEN**; matrix tests running |
| **Prior CI #28915985296** | **Failed** | pre-`4a320ad` single-input proptests (fixed) |

### RC push hold

**Active** — monitor CI `#28917267975`; lane 2 evidence after green.

### Next priority

**Lane 1:** CI green → optional Nightly on head. **Lane 2:** release evidence refresh. **Lane 4+6:** B3 replication accounting.

---

## Session — 2026-07-07 PM (F7 block_apply pad inputs → CI `#28917060257`)

| Gate | Status | Notes |
| --- | --- | --- |
| **F7 block_apply** | **Done** — `668cf17` | `block_apply.rs` companion pad for ring + storage shape tests |
| **F7 proptest tail** | **Done** — `4a320ad` | `apply_block_proptest` + `emission_simulation` two-input recycle |
| **F7 smoke/wallet** | **Done** — `81849c8` | Two-block fund + `owned_count>=2` poll |
| **CI #28917060257** | **In progress** | `668cf17` full matrix |

### RC push hold

**Active** — monitor CI `#28917060257`; no pushes until green.

### Next priority

**Lane 2:** release evidence on green head. **Lane 4+6:** B3 replication accounting.

---

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
