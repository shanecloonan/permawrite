# 3agent (legacy name — lanes 1–3)

> **Unified coordination:** [`AGENTS.md`](./AGENTS.md) (master board) and [`docs/AGENTS.md`](./docs/AGENTS.md) (per-lane checklists).
> Lanes **4–6** are overflow lanes.

## 3-agent checklist (live)

| Agent / lane | Done | Doing | Next |
| --- | --- | --- | --- |
| **1** RC core | B8.0 `#419e38a` | **Doing** — CI `#29010590422` + B8.1 push | Nightly on green head |
| **2** RC ops | Release evidence `b06a704` + RC audit **go** | **Done** | Human sign-off packet |
| **3** Onboarding | Local MFER rehearsals PASS | **Idle** | TL-6 VPS rehearsal |
| **4+6** Protocol | **B8.0** + **B8.1** SOCKS5 dial | **Doing** — push + CI | B8.2 hidden service |
| **7** Testnet | Local RC + preflight MFER gate | **Blocked** — VPS provision | **TL-5 internet soak** |

---

## Session — 2026-07-09 (B8.1 SOCKS5 outbound P2P dial)

| Unit | Status | Notes |
| --- | --- | --- |
| **B8.1** | **This push** | `mfn-net::socks5` CONNECT client; Tor transport routes via `MFND_TOR_SOCKS5` |
| **mfnd serve** | **This push** | Tor warning when SOCKS5 must be reachable |

**Lane 4+6 — Doing:** B8.1 **Next:** B8.2 inbound hidden service  
**Lane 1 — Doing:** CI after push **Next:** Nightly dispatch  
**Lane 7 — Blocked:** VPS provision for TL-5

---

| Unit | Status | Notes |
| --- | --- | --- |
| **B8.0** | **Done** — `419e38a` | `mfn-net::transport`; `MFND_P2P_TRANSPORT` / `MFND_TOR_SOCKS5`; Tor stub returns Unsupported |
| **mfnd serve** | **This push** | `mfnd_p2p_transport=…` harness line on P2P enable |
| **Nightly dispatch** | **This push** | `dispatch-rc-workflows.sh` resolves short SHA → full `git rev-parse` |

**Lane 4+6 — Doing:** B8.0 **Next:** B8.1 SOCKS5 outbound dial  
**Lane 1 — Doing:** CI on push **Next:** Nightly with full SHA  
**Lane 7 — Blocked:** VPS provision for TL-5

---

| Unit | Status | Notes |
| --- | --- | --- |
| **vps-preflight** | **Done** — `375f4d0` | Validates `require_endowment_range_proof=1` + `mfn-storage-operator` binary |
| **launch-go-no-go.ps1** | **Done** — `375f4d0` | Local MFER rehearsal WARN parity with bash |
| **B8 plan** | **Done** — `375f4d0` | Phased B8.0–B8.3 table in `PRIVACY_HARDENING.md` |
| **RC evidence** | **Done** — `19dc111` | `release-evidence-19dc111` + RC audit **go** |

**Lane 7 — Doing:** VPS preflight hardening **Next:** TL-5 execution (human VPS)  
**Lane 4+6 — Doing:** B8 research plan **Next:** B8.0 transport trait skeleton  
**Lane 1 — Doing:** Nightly dispatch **Next:** soak maintenance

---

| Unit | Status | Notes |
| --- | --- | --- |
| **launch-status v3** | **Done** — this push | Local MFER rehearsal gates, release evidence, RC audit go; phase → "local RC complete — provision VPS" |
| **permanence-demo.sh** | **Done** | `stop_orphan_chunk_servers` + `remove_stale_log` parity with `.ps1` |
| **launch-go-no-go** | **Done** | WARN when TL-5/TL-6 missing but local MFER rehearsals PASS |
| **CI `#29005580975`** | **GREEN** | `daa8e8e` board sync on `main` |

**Lane 7 — Doing:** launch-status v3 **Next:** TL-5 VPS execution (human provision)  
**Lane 1 — Doing:** CI on `daa8e8e` **Next:** push Lane 7 ops after green  
**Lane 3 — Done:** local rehearsals **Next:** TL-6 on VPS

---

## Session — 2026-07-09 (M4.8 tail — WASM MFER integration test)

| Unit | Status | Notes |
| --- | --- | --- |
| **M4.8 tail** | **Done** — `b3f56a6` | `wasm_storage_upload_attaches_mfer_when_range_proof_required`; observer rehearsal evidence |
| **Observer rehearsal** | **Done** | `participant-rehearsal-observer-windows-20260709T080708Z.txt` |
| **Ops `7dba698`** | **Done** | CI cancelled by concurrent push; superseded by `b3f56a6` |

**Lane 4+6 — Doing:** M4.8 tail **Next:** push after CI green  
**Lane 3 — Doing:** observer MFER rehearsal

---

## Session — 2026-07-09 (M4.8 / B1 2e — WASM MFER + rehearsal evidence)

| Unit | Status | Notes |
| --- | --- | --- |
| **M4.8 / B1 2e** | **Done** — `bbe1d9f` | WASM upload merges live endowment flags; CI `#28999593529` GREEN |
| **MFER rehearsal** | **Done** | `participant-rehearsal-no-observer-windows-20260709T070005Z.txt`; upload+prove+support-bundle PASS |
| **Demo log-lock fix** | **This push** | `permanence-demo.ps1` stale-log + orphan chunk-server cleanup |

**Lane 3 — Done:** MFER rehearsal **Next:** TL-6 VPS  
**Lane 2 — Doing:** release evidence on `bbe1d9f`

---

## Session — 2026-07-09 (B1 phase 2d — public devnet MFER flip)

| Unit | Status | Notes |
| --- | --- | --- |
| **B1 phase 2d** | **Done** — `2958cfa` | `require_endowment_range_proof: 1`; same `genesis_id`; forged-blinding reject test |
| **B1 CI #28995960877** | **GREEN** | Full matrix on `2958cfa` (~35m); soak + Nightly dispatch queued |
| **B1 track** | **Complete** | 2a param → 2b wire → 2c wallet → 2d devnet enable |

**Lane 4+6 — Done:** B1 **Next:** RC evidence (lane 2)  
**Lane 1 — Doing:** Nightly on `2958cfa` **Next:** soak maintenance  
**Lane 3 — Doing:** MFER participant-rehearsal smoke evidence

---

## Session — 2026-07-08 (B1 phase 2c — wallet MFER proof build)

| Unit | Status | Notes |
| --- | --- | --- |
| **B1 phase 2c** | **Done** — `ba53a15` | wallet MFEX v3 + `build_endowment_surplus_range_proof`; unit test |
| **B1 CI #28992802103** | **In progress** | 2c matrix on `ba53a15` |
| **B1 2b** | **Done** — `c084537` | CI `#28989926744` GREEN |

**Lane 4+6 — Done:** B1 2c `ba53a15` **Doing:** forged MFER reject test **Next:** B1 2d devnet flip  
**Lane 1 — Doing:** CI `#28992802103` **Next:** Nightly after green

---

## Session — 2026-07-08 (B7 chunk-inbox disk quota)

| Unit | Status | Notes |
| --- | --- | --- |
| **B7 inbox quota** | **Done** — `930b166` | `MFND_CHUNK_INBOX_MAX_BYTES`; LRU evict incomplete dirs; protect complete sets |
| **CI #28986986012** | **In progress** | Pushed; awaiting full matrix |

**Lane 4+6 — Done:** B5 `1485e67` **Doing:** B7 CI **Next:** B1 opening reveal  
**Lane 1 — Done:** CI `#28983986309` **Doing:** CI on B7 **Next:** Nightly dispatch

---

## Session — 2026-07-08 (B5 phase 5d — M5.51 + public devnet slash enable)

| Unit | Status | Notes |
| --- | --- | --- |
| **B5 phase 5d** | **Done** — `1485e67` | M5.51 proptests; devnet cap=48 slash=250; CI `#28983986309` GREEN |
| **Nightly #28980876807** | **GREEN** | All 3 jobs on `8bdb4ab` stack |
| **Local CI** | **GREEN** | `ci-check.ps1` on `1485e67` |

**Lane 4+6 — Done:** B5 complete **Doing:** push **Next:** B6 size buckets  
**Lane 1 — Done:** Nightly `#28980876807` **Doing:** CI on 5d push **Next:** soak maintenance

---

## Session — 2026-07-08 (B5 phase 5c — slash → treasury + deregister)

| Unit | Status | Notes |
| --- | --- | --- |
| **B5 phase 5c** | **Done** — `8bdb4ab` | Auto-slash on miss cap; treasury credit; zero-bond deregister |
| **CI #28979369780** | **GREEN** | `8bdb4ab` full matrix (~31m) |

**Lane 4+6 — Done:** B5 5c `8bdb4ab` **Doing:** — **Next:** B5 5d M5 proptests + devnet  
**Lane 1 — Done:** CI `#28979369780` **Doing:** Nightly dispatch **Next:** soak maintenance

---

## Session — 2026-07-08 (B5 phase 5c — slash execution + clippy fix)

| Unit | Status | Notes |
| --- | --- | --- |
| **B5 phase 5c** | **This push** | Slash on miss cap → treasury; zero-bond deregister; clippy `or_default` |
| **CI #28977215094** | **FAIL** | clippy on `643a224` — fixed locally |

**Lane 4+6 — Done:** B5 5b `643a224` **Doing:** 5c push **Next:** B5 5d devnet enable  
**Lane 1 — Doing:** CI re-run on 5c head **Next:** Nightly dispatch

---

## Session — 2026-07-08 (B5 phase 5b — retained bond + miss stats)

| Unit | Status | Notes |
| --- | --- | --- |
| **B5 phase 5b** | **This push** | Retained register bond; `StorageOperatorStats`; checkpoint **v9**; pre-proof stale challenge gate |
| **CI #28977215094** | **In progress** | `643a224` B5 5b stack |

**Lane 4+6 — Done:** B5 5a `e81d33e` **Doing:** B5 5b push **Next:** B5 5c slash → treasury  
**Lane 1 — Done:** full RC stack **Doing:** CI on B5 stack **Next:** Nightly re-dispatch

---

## Session — 2026-07-08 (B5 phase 5a — inert slash params + checkpoint v8)

| Unit | Status | Notes |
| --- | --- | --- |
| **B5 phase 5a** | **This push** | `operator_audit_missed_cap` + `operator_slash_bps` in `EndowmentParams`; checkpoint **v8**; [`B5_OPERATOR_SLASHING.md`](docs/B5_OPERATOR_SLASHING.md) |
| **CI** | **Pending** | Local `ci-check.ps1` before push |
| **Nightly** | **Pending** | Re-dispatch after green CI |

**Lane 4+6 — Done:** B4 `89f3498`, Nightly `#28970179853` **Doing:** B5 phase 5a push **Next:** B5 phase 5b retained bond + miss accounting  
**Lane 1 — Done:** full RC stack green **Doing:** CI on B5 push **Next:** Nightly re-dispatch

| Unit | Status | Notes |
| --- | --- | --- |
| **B4 phase 1** | **Done** — `89f3498` | `p2p_repair_sweep.rs`; stale inbox re-fan-out; `MFND_REPAIR_*` env |
| **CI #28966851917** | **GREEN** | `0ede433` M2.5.66 + M5.50 (~28m) |
| **CI #28968642140** | **GREEN** | `89f3498` B4 (~26m) |
| **Nightly #28968584904** | **GREEN** | All 3 jobs on `0ede433` M2.5.66 stack (~7m) |
| **Nightly #28970179853** | **GREEN** | All 3 jobs on B4 stack (`89f3498` ancestor) |
| **Release evidence** | **Done** | `release-evidence-1c633e7` + RC audit **go** |

---

## Session — 2026-07-08 (B5 operator slashing — phase 5a design)

| Unit | Status | Notes |
| --- | --- | --- |
| **B5 phase 5a** | **In progress** | `docs/B5_OPERATOR_SLASHING.md`: retained escrow, miss stats, checkpoint v8 sketch, griefing |
| **Critical gap** | **Documented** | B3 register burns bond to treasury — 5b must change to slashable collateral |
| **CI #28970409945** | **In progress** | `f804ac1` OPERATORS + board sync (docs-only) |

**Lane 4+6 — Done:** B4 `89f3498` **Doing:** B5 phase 5a design **Next:** B5 phase 5b retained escrow  
**Lane 1 — Done:** dual Nightly GREEN **Doing:** monitor CI `#28970409945` **Next:** idle

---

## Session — 2026-07-08 (B4 proactive repair sweep)

| Unit | Status | Notes |
| --- | --- | --- |
| **M2.5.66** | **Done** — `0ede433` | `vps_export_binds` if/fi; hub bind defaults; `vps-bind-lib-smoke.sh` in CI |
| **M5.50** | **Done** — `0ede433` | `prop_b3_duplicate_operator_rejects_after_prefix` + replication-cap reject tests |
| **CI #28966851917** | **In progress** | `0ede433` matrix |
| **Nightly #28962813486** | **FAIL** | Pre-M2.5.66 `start_mesh_fail`; re-dispatch after green CI |

**Lane 1 — Done:** root-cause **Doing:** push M2.5.66 **Next:** Nightly green  
**Lane 4+6 — Done:** 3c `65aea81` **Doing:** M5.50 push **Next:** B4 repair sweep

---

| Unit | Status | Notes |
| --- | --- | --- |
| **Root cause** | **Found** | `[[ -n ... ]] && export` in `vps_export_binds` aborts `start-all` under `set -e` when VPS binds unset |
| **Fix** | **This push** | `if/fi` exports + hub bind defaults in `start-all`; `vps-bind-lib-smoke.sh` |
| **Nightly #28961041302** | **FAIL** | `start_mesh_fail` ~1s — no v0.log (exit before hub launch) |
| **B3 phase 3c** | **Done** — `65aea81` | Genesis operator seeding + public devnet enable |

**Lane 1 — Done:** root-cause **Doing:** CI + push **Next:** Nightly re-dispatch

---

## Session — 2026-07-08 (B3 phase 3c — genesis operator seeding)

| Unit | Status | Notes |
| --- | --- | --- |
| **B3 phase 3c** | **Done** — `65aea81` | Genesis `storage_operators[]`; `apply_genesis` seed; public devnet B3 flags; rehearsal replica seed |
| **CI #28952620476** | **In progress** | `8b4e163` matrix (monitor lane 1) |
| **Board sync** | **Done** — `567da3d` local | Push after CI green |

**Lane 4+6 — Done:** 3b `8b4e163` **Doing:** 3c genesis seeding **Next:** M5 proptest duplicate-operator reject

---

| Unit | Status | Notes |
| --- | --- | --- |
| **B3 phase 3b** | **Done** — `8b4e163` | `StorageOperatorOp::Register`; Schnorr; `bond_section_merkle_root`; checkpoint **v7**; mesh startup fix |
| **Local CI** | **GREEN** | `ci-check.ps1` run2 ~54m |
| **GitHub CI** | **In progress** | `#28952620476` on `8b4e163` |
| **B3 phase 3c** | **Next** | Genesis spec operator seeding + devnet enable |

**Lane 4+6 — Done:** 3b **Doing:** — **Next:** 3c genesis seeding

---

## Session — 2026-07-08 (B3 phase 3b — CI gate + push)

| Unit | Status | Notes |
| --- | --- | --- |
| **B3 phase 3b** | **In progress** — local CI | `StorageOperatorOp::Register`; Schnorr spend-key auth; `bond_section_merkle_root`; checkpoint **v7**; block wire 5th section |
| **Codec tests** | **Done** | `block_codec_*` updated for 311-byte empty block; legacy decode at `header+4` |
| **B3 phase 3c** | **Next** | Genesis spec operator seeding + devnet enable |
| **Nightly #28940474074** | **FAIL** | `start_mesh_fail` (~1s) — lane 1 follow-up after push |

**Lane 4+6 — Done:** codec fix **Doing:** `ci-check.ps1` **Next:** commit + push + 3c

---

## Session — 2026-07-08 (B3 phase 3b — StorageOperatorOp register wire)

| Unit | Status | Notes |
| --- | --- | --- |
| **B3 phase 3b** | **Done** — this push | `StorageOperatorOp::Register`; Schnorr spend-key auth; `bond_section_merkle_root`; checkpoint **v7** |
| **B3 tests** | **Done** | `b3_storage_operator_register_wire_accepted` + duplicate reject |
| **B3 phase 3c** | **Next** | Genesis spec operator seeding + devnet enable |

**Lane 4+6 — Done:** B3 phase 3b **Doing:** CI + push **Next:** genesis seeding (3c)

---

## Session — 2026-07-08 (B3 phase 3b — StorageOperatorRegister wire + bond_root)

| Unit | Status | Notes |
| --- | --- | --- |
| **B3 phase 3b** | **This push** | `StorageOperatorOp::Register` Schnorr wire; `bond_section_merkle_root`; `apply_storage_operator_ops`; checkpoint **v7** (`min_storage_operator_bond`); block wire section; 2× `block_apply` register tests |
| **Nightly #28940474074** | **FAIL** | `start_mesh_fail` (~1s) — hub exit before v0.log; investigate lane 1 (not F7 fund-wallet) |
| **Release evidence** | **Done** — `1b6caba` + RC audit **go** | Refresh again after 3b CI green |

**Lane 4+6 — Done:** 3a `99754b8` **Doing:** 3b push + CI **Next:** genesis operator seeding (3c)

---

## Session — 2026-07-08 (B3 phase 3a — operator registry + apply_block gate)

| Unit | Status | Notes |
| --- | --- | --- |
| **B3 phase 3a** | **Done** — `99754b8` | `require_registered_operators`; `storage_operators` map; checkpoint **v6**; `StorageProofUnregisteredOperator`; 2× `block_apply` registry tests |
| **CI #28935445273** | **GREEN** | Full matrix ~1h30m on `99754b8` |
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
