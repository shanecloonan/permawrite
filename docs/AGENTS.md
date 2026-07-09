# Agent coordination checklists

Master board: [`AGENTS.md`](../AGENTS.md). Release gates: [`TESTNET_CHECKLIST.md`](./TESTNET_CHECKLIST.md).

When a lane completes a unit, update **all three**: this file, `AGENTS.md`, and the matching `TESTNET_CHECKLIST.md` section (if RC-related).

---

## How lanes talk to each other

```text
AGENTS.md (master)  <─── claim / status / backlog
       │
       ├── docs/AGENTS.md (this file) — per-lane detail
       ├── docs/TESTNET_CHECKLIST.md — RC mirror for lanes 1–3
       └── 3agent.md — alias pointer to lanes 1–3
```

**Cross-lane rules**

- **Request:** add a row to `AGENTS.md` § Cross-lane requests; target lane acknowledges in their section below.
- **Blocker:** if your unit depends on another lane, status = `Blocked on lane N` — do not push partial protocol changes.
- **Observed WIP:** if `git status` shows another lane's files modified, note under your lane but do not stage them.

### Done / Doing / Next (mandatory)

Every lane agent **must** announce all three on every session and keep the boards in sync. See [`AGENTS.md` § Agent announcement protocol](../AGENTS.md#agent-announcement-protocol-mandatory).

| Surface | Done | Doing | Next |
| --- | --- | --- | --- |
| Chat (start + end of unit) | ✓ | ✓ | ✓ |
| `AGENTS.md` current board | ✓ | ✓ | ✓ |
| This file — lane section | ✓ | — | ✓ |
| `3agent.md` (lanes 1–3 only) | ✓ | ✓ | ✓ |

**Per-lane checklist format** — keep these three subsections under every active lane:

```markdown
### Done
- [x] …

### Doing
- [ ] **<unit>** — <concrete current step> (claim base: `<sha>`)

### Next
- [ ] …
```

When **Doing** is empty, set lane status to **Idle** on the master board and list Next as backlog claims only.

---

## Lane 1 — RC core (consensus, networking, GHA)

**Owns:** M2.5.x mesh startup, voter-dial timeouts, Nightly rehearsal stability, Linux soak dispatch.

### Done

- [x] M2.5.8–M2.5.9 — GHA startup polls + `query_tip_height`.
- [x] M2.5.17 — Windows voter hub-dial 600s parity.
- [x] M2.5.19 — GHA hub tip 900s; health 600s; liveness 300s; voter-dial soft-continue.
- [x] M2.5.31 - GHA polls 900s; voter soft gate tip>=1; health 900s; nightly jobs 90m; RC Nightly backup dispatch (e0de4e).
- [x] M2.5.34 - macOS CI `--test-threads=2` parity (15fd4c7).
- [x] M2.5.37 - start-all tip>=1; TCP RPC health; hub_liveness 900s (12df02d).
- [x] M2.5.38 - mfn-cli health probe; voter-dial both-listening soft gate (843e055).
- [x] M2.5.49 (`8650543`) - GHA participant smoke soft-continue mesh health + hub_liveness at tip>=1.
- [x] M2.5.50 (`dbf6067`; code `6216aec`) - early P2P listen; POST_START timeout export; participant smoke ps1 parity.
- [x] M2.5.51 (`0d9646a`) - start-all GHA hub_tip_wait uses MFN_POLL_HUB_MAX; observer catchup soft gate.
- [x] M2.4.89 Windows mirror — `ci-check.ps1` `--test-threads=2` (`8e6b3c1`).
- [x] M2.5.66 — `vps_export_binds` set -e abort on loopback mesh; `vps-bind-lib-smoke.sh` in CI (this push).

### Done

- [x] M2.5.65 — soak WARMUP health-check uses mfn-cli `status` for P2P session counts (`76cc778`).
- [x] M2.5.65 — GHA converge soft gate + `MFN_HEALTH_MIN_P2P_SESSIONS=0` (`8ccda5d`; intermediate soak `28850304866` converge FAIL → final PASS `28851202993`).
- [x] **B-05 Linux soak PASS** — soak `28851202993` on `8ccda5d` (max_height=48, 8 iterations).

### Next

- [x] **Nightly #63** all three green (`28792429191` on `85e5870` stack; B-06 gate closed).
- [x] Monitor green CI after B13 tail — **CI #28838850432 GREEN** on `934cc2f`.
- [x] **Nightly #64** all three green (`28841761235` on `934cc2f` stack).
- [x] **Nightly #28889931523** all three green on B-11/B7 stack (`b1072e3`).
- [x] **CI #28871239057 GREEN** on `837069a` (B-11 + B7 + B9 + F7/B15 stack).
- [x] Release evidence refresh on green CI (lane 2) — `release-evidence-96462aa` (this commit).
- [x] Nightly re-dispatch after M2.5.66 — **Nightly #28968584904** all three green (~7m; closes `start_mesh_fail`).

### Do not start (other lanes)

- M7.10 `push-all-chunks` — lanes 2–3 (landed `c1e0373`).
- M5.31+ ring tests — lane 4 (M5.31-M5.33 landed `aae3097`).

---

## Lane 2 — RC ops (security, RPC, release evidence)

**Owns:** `release-evidence-*`, RC audit dry-run, CI/Nightly auto-dispatch, schema validation gates.

### Done

- [x] M2.5.14–M2.5.18 — evidence refresh + inline Nightly dispatch.
- [x] M2.5.20 — nightly STAGE/start-all log dumps (668044d).
- [x] M2.5.21 — preflight `wasm-opt` + ci-check wasm-pack pkg cleanup (`aae3097`).
- [x] B-05 — Linux soak auto-dispatch + RC audit dry-run Linux evidence hook (`aae3097`).
- [x] M2.5.22 — wasm-pack `wasm-opt=false` (`0dcb1e9`).
- [x] M2.5.30 - bash validate-workflow-encoding guard path parity (`2eb8417`).
- [x] M2.5.32 - `.gitignore` debris; board mojibake guard; clean docs/AGENTS rebuild (`a35b7a6`).
- [x] M2.5.39-42 - DOCS-QA-2: git clean -X debris purge; ci-check `-DocsOnly`/`-RustOnly`; mojibake guard; frame/chunk decode (`4a1862b`).
- [x] M2.5.43-45 - shared `rehearsal-poll-timeouts.*`; mfnd_serve P2P expect removal; workspace dep hoist (`b945f73`).
- [x] M2.4.89 Windows mirror — `ci-check.ps1` `--test-threads=2` (`8e6b3c1`).
- [x] M7.10 push-all-chunks (`c1e0373` on `main`).
- [x] M7.11 - STORAGE_ACCESSIBILITY.md section 0 (`bb9600b`).
- [x] M7.11.2 - STORAGE_ACCESSIBILITY Phase B item 4 WASM prove+serve doc sync (`0650ad6`).
- [x] M6.9 — storage-operator JSON logs + `prove_attempt_json` unit test (`aae3097`).

- [x] M2.4.90 — `ci-check.sh` thread cap parity (`aae3097`).

- [x] **Release evidence refresh** — `release-evidence-96462aa` + RC audit dry-run go (CI `28885223488` on `0d28e4f`).

- [x] **Release evidence refresh** — `release-evidence-1c633e7` + RC audit dry-run **go** (CI `#28968642140` on `89f3498`).

### Next

- [x] Idle — RC gates green on B4 stack; periodic B-05 soak re-run is maintenance only.

### Do not start

- M5 protocol tests — lane 4.

---

## Lane 3 — RC onboarding (wallet, storage, faucet, rehearsal)

**Owns:** Participant/observer rehearsal smokes, faucet/demo scripts, operator onboarding polish, M7.10 UX.

### Done

- [x] M2.5.7–M2.5.16 — smoke evidence pipeline + assert gates.
- [x] M4.7 WASM SPoRA bindings (`778053a`).
- [x] M7.10 — `push-all-chunks` + OPERATORS.md (`c1e0373`).
- [x] M7.11 - STORAGE_ACCESSIBILITY.md section 0 (`bb9600b`).
- [x] M7.11.2 - STORAGE_ACCESSIBILITY Phase B item 4 WASM prove+serve doc sync (`0650ad6`).

### Done (continued)

- [x] **Nightly #63** all three green (`28792429191`; B-06 closed).
- [x] **Nightly #64** all three green (`28841761235` on `934cc2f`).
- [x] **B8.3 tor-rpc rehearsal** — plan-only `tor-rpc-rehearsal-smoke` in CI + ci-check (`1ad2dce`).

### Next

- [ ] TL-6 VPS participant rehearsal (human VPS).

### Do not start

- Wallet README ring examples — lane 5 (done `aae3097`).
- Consensus ring tests — lane 4.

---

## Lane 4 — Protocol hardening (M5 privacy + permanence)

**Owns:** Consensus/mempool privacy guards, mixed CLSAG+SPoRA tests, proptests not covered by RC lanes.

**Doctrine:** Tier 1 production policy only (uniform ring-16). No Tier 2/3/4 until `AGENTS.md` backlog explicitly schedules it.

### Done

- [x] **M5.31** — `consensus_rejects_non_uniform_ring_sizes` + `apply_block_rejects_non_uniform_ring_sizes` (uniform ring-16 across all inputs).
- [x] **M5.32** — `mfn-runtime` mempool `admit_rejects_non_uniform_ring_sizes_across_inputs` (claim B-01).
- [x] **M5.33** — prop_mixed_clsag_fee_and_storage_upload_treasury + 64-block deep chain (claim B-02, 1d4d67c).
- [x] **M5.35** - deep_mixed_clsag_fee_and_storage_upload_treasury_64 in default CI (`9537c7b`).
- [x] **M5.36** - deep_mixed_clsag_fee_and_storage_proof_treasury_64 in default CI (`0dcb1e9`).
- [x] **M5.37** - deep_empty_block_chain_128 + deep_storage_proof_chain_32 + deep_validator_mixed treasury in default CI (`ec8122e`).
- [x] **M5.38** - restore deep_mixed_clsag_fee_and_storage_upload_treasury_64 to default CI (`d3a4f36`).
- [x] **M5.39** - deep_alternating_register_storage_treasury_8 proptest in default CI (35734a5).
- [x] **M5.40** - 64-block combined-inflow + PPB + equivocation-PPB emission sims in default CI (`7648ab2`).
- [x] **M5.41** - 128-block PPB + equivocation combined-inflow emission sims in default CI (`c7f90e6`).
- [x] **M2.5.46** (`2b33ced`; code `1152e16`) - split `p2p_peer_quarantine` + `p2p_reconnect_plan` from `p2p_fanout` (B-07 partial).
- [x] **M2.5.47** (`2b33ced`) - mfnd `runner`/`mfnd_cli` production `expect` removal (B-08 partial).

- [x] **M2.5.48** (40d31d) - on-disk debris purge; light-follow quorum `expect` removal (B-08).
- [x] **M2.5.52** (`2904ea3`) - B-07: extract `dispatch/rpc_params.rs` + `rpc_method_meta.rs` from `dispatch.rs`.
- [x] **M2.5.55** (6fe1b18) - light-chain EvolutionFailed integration test; mempool test dead_code cleanup.
- [x] **M2.5.53** (`bd76bde`) - B-07: extract `cli/parse.rs` from `cli.rs`; restore + hoist `mod parse`.
- [x] **M2.5.60** - B-08 lock-in: `clippy::unwrap_used`/`expect_used` warn gate on non-test `mfn-net` + `mfn-node`; delete one-off repair scripts.
- [x] **M5.49 + M7.12** (`890a56c`) - permanence hardening: `validate_storage_commitment_shape` consensus + mempool gate (`chunk_size` power-of-two, `num_chunks == ceil(size/chunk)`); chunk-inbox gossip authenticated against anchored commitments (unknown-commit reject, index/length gate, single-chunk data_root verify, no overwrite of held bytes); fan-out verifies inbox Merkle root against `data_root` before replicating.

- [x] **M2.5.61** (`1603e43`) - fix M2.5.50 stdout-order regression: `mfnd serve` prints `mfnd_p2p_listening=` before `mfnd_serve_listening=`, so sequential prefix reads in `mfnd_smoke` consumed the P2P line and hung (`mfnd_p2p_reconnects_saved_peers_on_restart`, `mfnd_rpc_get_light_follow_p2p_fetches_from_peer_listener` — Windows ci-check red twice). New `read_stdout_lines_with_prefixes_any_order` harness helper; all `--p2p-listen` spawns collect startup announcements order-independently. First green CI matrix since M2.5.50 (run `28774283620`).
- [x] **DOCS-PH-1** - `docs/PERMANENCE_HARDENING.md`: implementation-level log of shipped permanence hardening (M5.49 shape gate, M7.12 gossip auth + fan-out verify, M2.5.61 CI trustworthiness) with code citations and test inventory, plus file-and-function-level plans for the remainder — B-11 endowment binding (opening-reveal vs range-proof designs), ChunkV2 Merkle-path gossip, replication accounting via operator-salted challenges, proactive repair sweep, bonding + slashing, inbox quota. Cross-linked from `docs/README.md`, `STORAGE.md`, `PRIVACY_HARDENING.md`.

- [x] **B-11 phase 1** — `MFEO` wire + `apply_block`/mempool Pedersen opening verify; `require_endowment_opening` param (`3511346`).
- [x] **B-11 proptests** — `prop_mfeo_opening_storage_upload_treasury` + reject without `MFEO` (`9f0a0aa`).
- [x] **B-11 public devnet enable** — genesis spec `endowment` section + `require_endowment_opening: 1` in `public_devnet_v1.json` (same `genesis_id`; operators must sync byte-identical JSON).
- [x] **B2 ChunkV2** (`20954b0`) — Merkle-path chunk gossip tag `0x12`; `validate_gossip_chunk_v2` + `on_chunk_v2`; fan-out/operator push emit proofs; inbound `ChunkV1` retained.
- [x] **F7 consensus tail** (this commit) — `RingPolicy.min_input_count` at `verify_transaction` (with lane 5).

### Next

- [x] **B3 phase 1** — operator-salted SPoRA challenge derivation (`mfn-storage`; `eea59aa`).
- [x] **B3 phase 2** — per-operator proof slots + `apply_block` wire (checkpoint v5; flag off on public genesis).
- [x] **B3 phase 3a** — operator registry in chain state + `require_registered_operators` gate (checkpoint v6; genesis off).
- [x] **B3 phase 3b** — `StorageOperatorOp::Register` Schnorr wire + bond escrow (checkpoint v7 `min_storage_operator_bond`).
- [x] **B3 phase 3c** — genesis spec `storage_operators` seeding + public devnet enable.
- [x] **M5.50** — B3 duplicate-operator + replication-cap reject proptests (this push).
- [x] **B4 phase 1** — proactive repair sweep in `mfnd` (`89f3498`).

### Next

- [x] **B5 phase 5a** — inert slash params + checkpoint v8 + [`B5_OPERATOR_SLASHING.md`](./B5_OPERATOR_SLASHING.md) (`e81d33e`).
- [x] **B5 phase 5b** — retained bond + `storage_operator_stats` + checkpoint v9 (`643a224`).

- [x] **B5 phase 5c** — slash execution → treasury + zero-bond deregister (`8bdb4ab`).

### Next

- [x] **B5 phase 5d** — M5.51 proptests + public devnet slash params (`1485e67`; CI `#28983986309` GREEN).

### Next

- [x] **B7 (permanence inbox quota)** — `MFND_CHUNK_INBOX_MAX_BYTES` gossip disk cap (`930b166`; CI `#28986986012` GREEN).

### Next

- [x] **B1 phase 2a** — inert `require_endowment_range_proof` + checkpoint v10 (`76b5f8f`).
- [x] **B1 phase 2b** — MFEX v3 + `MFER` wire; `apply_block` + mempool verify (`c084537`).
- [x] **B1 phase 2c** — wallet builds `MFER` on upload (`ba53a15`).
- [x] **B1 phase 2c tail** — reject forged `MFER` consensus test (`reject_upload_with_forged_mfer_when_endowment_range_proof_required`).
- [x] **B1 phase 2d** — public devnet flip to `require_endowment_range_proof: 1` (`2958cfa`; CI `#28995960877` GREEN).
- [x] **B1 phase 2e** — WASM upload merges live `get_chain_params.endowment`; RPC exposes endowment policy flags (`bbe1d9f`; CI `#28999593529` GREEN).

### Handoff to lane 3

- Ring-16 is consensus-enforced; wallet/CLI must stay ≥16 (lane 5 documents).

---

## Lane 5 — Privacy surface (wallet, CLI, WASM, docs)

**Owns:** Reference-wallet ring defaults, privacy doc accuracy, “no silent downgrade” UX.

### Done

- [x] **M5.31-docs** — `mfn-wallet/README.md` quick-start uses ring-16 and cites `WALLET_MIN_RING_SIZE`.
- [x] **M5.31-cli** — `mfn-cli wallet` help documents `--ring-size` default 16 (claim B-04).
- [x] **PRIVACY cross-link** — wallet README links uniform-ring policy in [`PRIVACY.md`](./PRIVACY.md).
- [x] **F5-P8** (`23c14d6`) — `lsag` + unwired `oom` gated behind `cfg(test)` / non-default cargo features; release binaries accept CLSAG only (`PRIVACY_HARDENING.md` §B5 shipped).
- [x] **F5-P10** (`3789e39`) — structural authorship-key firewall: canonical `derive_claiming_keypair` in `mfn-crypto`, closed `ClaimingIdentity` constructor, signing-time `ClaimKeyReusesWalletKey` rejection (`PRIVACY_HARDENING.md` §B10 shipped).
- [x] **F5-PM13** (`df70b9c`) — `mfn_consensus::constitution` fork-legitimacy invariants enforced at genesis-spec load (`tail_emission > 0`, uniform rings >= 16, endowment pricing well-formed).
- [x] **F5:B3 (output ordering)** (`d7ee698`) — `spend::build_transfer` shuffles output specs with the plan RNG; change position carries no signal (`PRIVACY_HARDENING.md` §B3).
- [x] **F5-P9 (conformance suite)** (`1c9d578`) — `mfn-wallet/tests/canonical_conformance.rs` pins version / empty-extra / uniform ring-16 / output floor / enc_amount / byte-canonical encoding for transfers + uploads; closes §B3.
- [x] **F5-P5/B1 (consensus output floor)** (`d583ea4`) — `RingPolicy.min_output_count` = 2 under the uniform-ring tier (derived, no codec change); enforced in `verify_transaction`; closes §B1.
- [x] **B2 (age-band coin selection)** (`85e5870`) — `Wallet::select_inputs` spends within one exponential age band (fewest inputs, newest-band ties, cohesive spill); closes §B2.
- [x] **B3 tail (production RNG contract)** (`4a4a9f1`) — `production_tx_rng` alias; CLI/WASM wired; conformance source-scan; closes §B3.
- [x] **B4(a) decoy pool** (`b402db3`) — `build_decoy_pool` excludes only spent input keys; unspent owned outputs eligible.
- [x] **B4(c) co-height randomization** (`297df7c`) — `select_gamma_decoys` uniform pick within height bucket.
- [x] **B13 (wallet size buckets)** (`4712811`) — power-of-two pad in `build_storage_upload`; closes §B13 wallet layer.
- [x] **B13 (consensus size buckets)** (`3d8574c`) — reject non-bucket `size_bytes`; artifact saves padded payload.
- [x] **B7 (Dandelion++ phase 1)** (`1cc9ead`) — opt-in `--dandelion` stem/fluff relay.
- [x] **B7 (phase 2)** — `MFND_DANDELION=1` env + CLI parse tests.
- [x] **B9 (view tags phase 1)** — `indexed_view_tag` in `mfn-crypto` stealth.
- [x] **B9 (view tags phase 2)** — tx v2 wire + wallet encode + scanner skip (~256× filter); legacy v1 accepted.
- [x] **B7 (rehearsal evidence)** — Windows `dandelion-rehearsal-smoke` PASS on B-11 MFEO genesis; `-dandelion` evidence archive tag.
- [x] **B7 (rehearsal soak)** — `--dandelion` on mesh scripts (default off); `dandelion-rehearsal-smoke` / `dandelion-soak` wrappers.
- [x] **B7 (stem wire label)** — `TxStemV1` tag `0x11` on stem relay; fluff on `TxV1`.
- [x] **F7/B15 (two-input wallet floor)** — `WALLET_MIN_TX_INPUTS` + `select_inputs_for_tx`; pad to two real inputs when possible.
- [x] **F7 consensus tail** (this commit) — `RingPolicy.min_input_count` at `verify_transaction` (with lane 4).

### Next

- [x] **B8** — optional Tor/arti transport: **B8.0–B8.3 shipped**; **P31 phase 0–1** + **P32 phase 0** shipped.

### Do not start

- M7.10 replication — lanes 2–3.
- GHA rehearsal — lane 1.

---

## Lane 6 — Permanence depth (economics, SPoRA, treasury)

### Done
- [x] **F5-PM9** — `docs/PQ_MIGRATION.md`: committed consensus-versioned PQ migration path + wire-format headroom audit (soft fork today).
- [x] **F5-PM10** — self-verifying chain+chunk archive: `mfnd archive-export` / `archive-verify` (`mfn-node/src/archive_export.rs`); replay-from-genesis + chunk Merkle re-derivation, no live network.
- [x] **M2.5.59** - debris gitignore (*.utf8.bak, docs/*.test.md); resolve-schema-python invoke via powershell -NoProfile -File.
- [x] **M2.5.58** (c0e73eb) - resolve-schema-python.ps1 wired into ci-check + release scripts.
- [x] **M2.5.57** (`3e994b9`) - debris purge + DOCS-QA-2 closure.
- [x] **M2.5.56** (6fe1b18) - B-10: anyhow 1.0.103 clears RUSTSEC-2026-0190.


**Owns:** Long-run treasury/emission sims, SPoRA payout invariants, operator-bonding research.

### Idle — claim from backlog


- [x] **M5.46** - combined-inflow emission CI tier complete (`1232506`).
- [x] **M5.47** - 256-block equivocation combined-inflow + 1M curve in default CI (`db06c78`).
- [x] **M5.48** - emission deep-sim tier closure; 2048 CLSAG + 100k `apply_block` stay nightly (77f2fe1).
- [x] **M5.34 / B-03** — 64-block validator mixed CLSAG+SPoRA emission sim in default CI (`45a118b`).
- [x] **M5.40** - 64-block combined-inflow + PPB + equivocation-PPB emission sims in default CI (`7648ab2`).
- [x] **M5.41** - 128-block PPB + equivocation combined-inflow emission sims in default CI (`c7f90e6`).
- [x] **M5.42** - 256-block combined-inflow emission sim in default CI (994af36).
- [x] **M5.44** - 512-block combined-inflow emission sim in default CI (3fcb4bc).
- [x] **M5.46** - combined-inflow emission CI tier complete; 2048-block CLSAG fee mix timed nightly-only (~13 min release).
- [x] **M5.45** - 512-block PPB + equivocation combined-inflow emission sims in default CI (66a697a).
- [x] **M5.43** - 256-block PPB combined-inflow emission sim in default CI (7ffcdac).
- [x] B-05 — Linux soak auto-dispatch + workflow evidence commit (`9537c7b`; PASS `28851202993` / `234f0a8`).

### Next

- [x] B-05 — Linux soak PASS transcript archived (`28851202993` / `234f0a8`).
- [x] B-06 — Nightly #63 all three jobs green (`28792429191` on `85e5870` stack; lane 1 RC gate closed).
- [x] **B2 ChunkV2** (this commit) — Merkle-path chunk gossip with lane 4.
- [x] **B4** — proactive repair sweep with lane 4 (`89f3498`).
- [x] **B7 (permanence inbox quota)** — chunk-inbox disk cap (`930b166`).
- [x] **B5 phase 5a** — inert slash params + checkpoint v8 (`e81d33e`).
- [x] **B5 phase 5b** — retained bond + miss stats + checkpoint v9 (`643a224`).
- [x] **B5 phase 5c** — slash → treasury + zero-bond deregister (`8bdb4ab`; CI `#28979369780` GREEN).

### Next

- [x] **B5 phase 5d** — M5.51 proptests + public devnet slash params (with lane 4).

### Next

- [x] **B1 phase 2a** — inert `require_endowment_range_proof` + checkpoint v10 (`76b5f8f`).
- [x] **B1 phase 2b** — MFEX v3 + `MFER` wire; `apply_block` + mempool verify (`c084537`).
- [x] **B1 phase 2c** — wallet builds `MFER` on upload (`ba53a15`).
- [x] **B1 phase 2c tail** — reject forged `MFER` consensus test (with lane 4).
- [x] **B1 phase 2d** — public devnet flip to `require_endowment_range_proof: 1` (`2958cfa`; CI `#28995960877` GREEN).
- [x] **B1 phase 2e** — WASM upload merges live `get_chain_params.endowment`; RPC exposes endowment policy flags (`bbe1d9f`; CI `#28999593529` GREEN).

### Do not start

- RC Nightly fixes — lane 1.
- `push-all-chunks` — lanes 2–3.

---

## Backlog detail (claim → move to lane section)

| ID | Item | Suggested lane | Notes |
| B-06 | Nightly #63 green | 1 | After M2.5.49-58 stack `c0e73eb` (CI #669) |
| B-02 | Proptest CLSAG + storage upload same block | 4 | Done - extends M5.5 |
| B-03 | CI emission sim with privacy fees | 6 | **Done** — 64-block validator mixed |
| B-05 | Linux 30s soak evidence | 2 + 6 | **Done** — soak `28851202993` PASS (`234f0a8`) |
| B-06 | Nightly #63 after M2.5.57 | 1 | M2.5.49-57 stack on `3e994b9` |

---

## Lane 7 — Testnet launch (internet-facing go-live)

**Owns:** [`TESTNET_LAUNCH.md`](./TESTNET_LAUNCH.md) TL phases, VPS deployment runbook, `seed_nodes` publication, launch ceremony tracking, `launch-status.*`.

**Does not own:** M5/F7 protocol (lane 4), release-evidence generators (lane 2), Nightly/CI fixes (lane 1).

### Done

- [x] **TL-1** — charter + [`TESTNET_LAUNCH.md`](./TESTNET_LAUNCH.md) + `launch-status` (`8661106`)
- [x] **TL-2** — green CI `#28924060054` on `e7d74f7` (F7 mempool two-input pad)
- [x] **TL-3** — `release-evidence-46677ad` + RC audit dry-run `go` (CI `#28924060054`)

- [x] **TL-4** — single-VPS runbook (`2f77eb4`: `vps-start-all.sh`, `VPS_SINGLE_BOX_LAUNCH.md`)
- [x] **TL-5 tooling** — `vps-preflight.sh`, `vps-internet-soak.sh`, `soak.sh --vps` (`5a74d57`)

- [x] **TL-6 tooling** — `vps-participant-rehearsal.sh`, `participant-rehearsal-smoke.sh --vps` (`ef3cbc4`)
- [x] **TL-7–TL-9 tooling** — `TESTNET_GENESIS_CEREMONY.md`, `publish-seed-nodes.*`, `launch-go-no-go.*` (`03de79a`)
- [x] **TL-8 invite packet** — [`TESTNET_INVITE.md`](./TESTNET_INVITE.md) + `launch-status.v2` (`a0bf55f`)
- [x] **VPS provision + ceremony** — [`VPS_PROVISION.md`](./VPS_PROVISION.md) + `vps-launch-ceremony.*` (`0a700a5`)
- [x] **TL-5 local RC** — `launch-status.v3` + local MFER rehearsals PASS (no-observer + observer Windows evidence)
- [x] **launch-status v3** — local RC gates + `permanence-demo.sh` log-lock parity
- [x] **TL-5 preflight hardening** — MFER policy + storage-operator binary gate in `vps-preflight.sh`
- [x] **TL-5 execution checklist** — `vps-execution-checklist.*` (this push)

### Doing

- [ ] *(awaiting VPS provision for TL-5/6 execution)*

### Next

- [ ] **TL-5 execution** — run soak on provisioned VPS; archive PASS evidence (height ≥ 10)
- [ ] **TL-6 execution** — `vps-participant-rehearsal.sh` on same VPS after TL-5
- [ ] **TL-7 human sign-off** — Path A (toy keys) or Path B (fresh genesis)
- [ ] **TL-8** — `publish-seed-nodes.sh --apply` after TL-7
- [ ] **TL-9** — `launch-go-no-go.sh` + named watchers before invite

### Do not start

- B3 replication accounting — lanes 4+6.
- F7 / consensus tail — lanes 4+5.

---

## TESTNET_CHECKLIST mirror

RC lanes 1–3 must keep [`TESTNET_CHECKLIST.md`](./TESTNET_CHECKLIST.md) in sync when they land units. Lanes 4–6 add a one-line note under **Agent coordination** when they ship protocol or privacy-surface changes. Lane 7 mirrors TL units into [`TESTNET_LAUNCH.md`](./TESTNET_LAUNCH.md).

---

## See also

- [`3agent.md`](./3agent.md) — legacy lanes 1–3 pointer
- [`DECENTRALIZATION.md`](./DECENTRALIZATION.md), [`PRIVACY.md`](./PRIVACY.md), [`ROADMAP.md`](./ROADMAP.md)
