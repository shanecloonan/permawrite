# Agent Coordination (master board)

Single source of truth for **all** parallel agent lanes (formerly `3agent.md` lanes 1-3, plus overflow lanes 4-6). Release gates: [`docs/TESTNET_CHECKLIST.md`](docs/TESTNET_CHECKLIST.md).

**Priority doctrine:** privacy and permanence over everything. UX, ops, and CI serve those guarantees - never weaken ring policy, endowment enforcement, or SPoRA verification.

Permawrite is pre-audit experimental software. Do not mark public-testnet readiness complete until the exact release commit has green GitHub CI, local CI mirror evidence, ignored/nightly coverage where required, release evidence, archive validation, and named human sign-off.

---

## Conflict prevention (read before every unit)

1. **Check this table first.** If another lane owns the unit with status `In progress`, do not start it.
2. **Claim before coding.** Set status to `In progress` + note the commit base in [`docs/AGENTS.md`](docs/AGENTS.md).
3. **Do not commit another lane's uncommitted work.** List it under **Observed local work** until it lands on `main`.
4. **One coherent unit per commit.** Run `scripts/ci-check` (Windows: `scripts/ci-check.ps1`) before push.
5. **Do not push while CI is in progress** on `main` - concurrency `cancel-in-progress` aborts the matrix (~70 min on Linux/macOS).
6. **Hand off explicitly.** Update this board + lane checklist + any cross-lane request rows when done.

---

## Agent announcement protocol (mandatory)

Every agent working a lane **must** broadcast **Done / Doing / Next** so simultaneous agents on the same roadmap can coordinate without duplicating work or missing handoffs.

### When to announce

| Trigger | Required action |
| --- | --- |
| **Start of session** | Post Done / Doing / Next before touching code. |
| **Claim a unit** | Update current board + lane section; announce Doing + planned Next. |
| **Mid-unit pivot** | Re-announce if scope, lane, or blockers change. |
| **End of unit** | Move unit to Done; announce Next; update cross-lane requests. |
| **Before push** | Board reflects the exact commit about to land; Next names the follow-up owner. |

### What to include (every announcement)

1. **Done**  -  units landed on `main` (commit hash when known) or explicitly abandoned with reason.
2. **Doing**  -  current lane, unit ID, and concrete step (not just the milestone name).
3. **Next**  -  immediate follow-up after this unit, expected lane owner, and any dependency on another lane.

Use this template in chat **and** mirror it on the boards:

```text
Lane N - Done: <completed units + commits>
       Doing: <unit + current step>
       Next:  <follow-up + owner + blockers>
```

### Where to record it

Update **all applicable** surfaces in the same session  -  do not rely on chat alone:

- [`AGENTS.md`](AGENTS.md)  -  current board, cross-lane requests, recently completed.
- [`docs/AGENTS.md`](docs/AGENTS.md)  -  lane Done / Next checklists.
- [`3agent.md`](3agent.md)  -  lanes 1-3 mirror (current board + detailed plans).
- [`docs/TESTNET_CHECKLIST.md`](docs/TESTNET_CHECKLIST.md)  -  when RC-related.

### Coordination rules

- **Read before write:** scan every lane's latest Done / Doing / Next before claiming work.
- **No silent work:** if you are coding without a `Doing` row on the board, stop and claim first.
- **Stale boards are blockers:** if your lane's Doing row is >1 session old, refresh or release the claim.
- **Cross-lane visibility:** when Next depends on another lane, add or update a row in § Cross-lane requests.

---

## Lane registry

| Lane | Scope | Owns (exclusive) | Does *not* own |
| --- | --- | --- | --- |
| **1** | RC core | M2.5.x mesh startup, voter-dial timeouts, Nightly rehearsal stability, Linux soak dispatch | M7.10 replication, M5 ring tests |
| **2** | RC ops | `release-evidence-*`, RC audit dry-run, CI/Nightly auto-dispatch, schema validation gates | M5 protocol tests |
| **3** | RC onboarding | Participant/observer rehearsal smokes, faucet/demo scripts, operator onboarding polish, M7.10 UX | Wallet README ring examples (lane 5), consensus ring tests (lane 4) |
| **4** | Protocol hardening | M5 privacy + permanence tests, `apply_block` invariants, ring/SPoRA consensus guards | RC Nightly fixes, `push-all-chunks` |
| **5** | Privacy surface | Wallet/CLI/WASM ring defaults, privacy doc accuracy, no silent downgrade UX | M7.10 replication, GHA rehearsal |
| **6** | Permanence depth | Treasury/emission sims, SPoRA payout invariants, operator-bonding research | RC Nightly, `push-all-chunks` |

Add lanes 7+ in [`docs/AGENTS.md`](docs/AGENTS.md) when needed. Split lanes before they exceed ~2 active units.

---

## CI gate (2026-07-06)

**CI #28838850432 GREEN** on `934cc2f` (full matrix: B13 authorship + WASM bucket parity + GHA hub-timing fix). **Nightly #63 GREEN** (run `28792429191`). **M2.5.64** landed `c5e69f6`.

**RC push hold:** lifted.

## Current board

| Lane | Current unit | Status | Next handoff |
| --- | --- | --- | --- |
| **1** | Green CI on B13 fix stack (`934cc2f`) | **Done** - CI #28838850432 | B-05 Linux soak dispatch |
| **2** | M2.5.59 schema-python invoke + release evidence | **Done** - `b1c8e6a` | Re-run evidence on `934cc2f` |
| **3** | M7.11.2 STORAGE_ACCESSIBILITY Phase B | **Done** - `0650ad6` | Nightly #63 PASS (`28792429191`) |
| **4** | DOCS-PH-1 `docs/PERMANENCE_HARDENING.md` | **Done** - docs-only | B-11 endowment-opening consensus binding |
| **5** | B13 size-bucket mandate + authorship parity | **Done** - `934cc2f` stack | B7 rehearsal soak + B9 view tags |
| **6** | F5-PM9 `docs/PQ_MIGRATION.md` | **Done** - docs-only | B-05 soak evidence |

---

## Backlog (unassigned -> claim in lane section)

| ID | Item | Suggested lane | Privacy / performance |
| --- | --- | --- | --- |
| B-02 | M5.33 - proptest: mixed CLSAG + storage upload same block treasury identity | 4 | Done - extends M5.5 |
| B-03 | Promote one ignored emission sim with CLSAG fee mix to CI | 6 | Done - M5.34/M5.35 (`45a118b`, `9537c7b`) |
| B-05 | Linux 30s soak evidence | 2 + 6 | Dispatch shipped `9537c7b`; awaiting PASS transcript |
| B-06 | Nightly #63 green (all three jobs) | 1 | **Done** - run `28792429191` on `85e5870` stack |
| B-07 | God-file splits (`dispatch.rs`, `cli.rs`, `p2p_fanout.rs`) | 1 + 4 | **Done** - M2.5.46 `p2p_fanout`; M2.5.52–53 dispatch + `cli/parse.rs` |
| B-08 | P2P production `unwrap`/`expect` audit (`mfn-net`, `mfn-node`) | 4 | **Done** - M2.5.47–48 + M2.5.55 light-chain test |
| B-09 | ps1/sh dedup generator or shared timeout constants | 2 | **Done** - M2.5.43 `rehearsal-poll-timeouts.*` |
| B-10 | Workspace dep hoist + RUSTSEC-2026-0190 anyhow path | 6 | **Done** - M2.5.56 anyhow 1.0.103; M2.5.45 hoisted deps |
| B-11 | Bind `StorageCommitment.endowment` Pedersen opening to `required_endowment` in consensus (range proof or opening reveal; today only the fee-share gate is enforced) | 4 + 6 | Open — highest remaining permanence gap after M5.49/M7.12 |

---

## Cross-lane requests

| From | To | Request | Status |
| --- | --- | --- | --- |
| 2 | 1 | Green CI on M2.5.43–45 stack before Nightly #62 dispatch | **Done** - CI #636 |
| 3 | 1 | Nightly #63 participant + observer PASS | **Done** - run `28792429191` |
| 4 | 3 | M5.31-M5.33 protocol tests green before next M7.10 UX | **Done** - `d3a4f36` |
| TESTNET | all | Mirror completed units into `docs/TESTNET_CHECKLIST.md` | Ongoing |

---

## Recently completed

- **B7 (phase 1)** (`1cc9ead`) - privacy surface (lane 5): Dandelion++ stem/fluff tx relay — `dandelion.rs` + opt-in `mfnd serve --dandelion`; default off preserves legacy parallel fan-out for CI.
- **B13 spora fix** (`96fe808`) - revert auto-pad inside `build_storage_commitment`; bucket padding at wallet/WASM/consensus only.
- **B13 test parity** (`e98ff4f`) - mfn-node chunk/archive tests use canonical bucket payloads.
- **B13 (consensus)** (`3d8574c`) - privacy surface (lane 5): consensus-mandatory upload size buckets — `validate_storage_commitment_shape` rejects NEW anchors whose `size_bytes` is not a canonical power-of-two bucket; CLI persists `UploadArtifacts.anchored_payload`; legacy artifact rebuild pads raw payloads.
- **B13 (wallet)** (`4712811`) - privacy surface (lane 5): upload size buckets — reference uploads pad to next power-of-two before anchoring; on-chain `size_bytes` is the bucket; endowment priced on bucket (`storage_size_bucket` / `pad_to_storage_size_bucket`).
- **M2.5.64** (this commit) - RC ops (lanes 1+2): Linux soak bootstrap uses pre-built `mfnd` (workflow `cargo build` + `soak.sh` → `start-all.sh --no-build`); `start-all` invokes child scripts via `bash` and fails fast when hub PID exits before P2P listen.
- **B4(c)** (`297df7c`) - privacy surface (lane 5): `select_gamma_decoys` picks uniformly among unchosen decoys at the target height instead of always taking the rightmost binary-search index; co-height selection no longer deterministic.
- **B4(a)** (`b402db3`) - privacy surface (lane 5): `build_decoy_pool` excludes only real input keys; other owned UTXOs remain eligible decoys (B4 / `PRIVACY_HARDENING.md`).
- **F5-PM9** (`eaecece`) - permanence depth (lane 6, docs-only): `docs/PQ_MIGRATION.md` — committed consensus-versioned PQ migration path (retroactive-privacy hybrid first, operator-key hybrid second, research-gated CLSAG successor third) + wire-format headroom audit proving each phase is a soft fork today.
- **F5-P9** (`1c9d578`) - privacy surface (lane 5): canonical-encoding conformance suite closes B3 — pins tx version, empty-`extra` default, uniform ring-16 (== consensus production policy), two-output floor, real `enc_amount` ciphertexts, and byte-canonical wire form for reference transfers + uploads; all frontends covered by construction via the two pinned constructors.
- **F5-PM10** (`b260033`) - permanence depth (lane 6): self-verifying chain+chunk archive — `mfnd archive-export --archive-dir DIR` (canonical block log + Merkle-verified chunk sets + `manifest.json`), `mfnd archive-verify` replays from the genesis spec through the full consensus STF and re-derives chunk Merkle roots offline. Archive reuses `mfn-store` fs formats so it doubles as a cold-start bootstrap.
- **F5:B3** (`d7ee698`) - privacy surface (lane 5): reference wallets shuffle output order with the plan RNG in `spend::build_transfer` — "last output is change" no longer holds for any reference tx; position-distribution test added.
- **F5-PM13** (`df70b9c`) - permanence governance (lanes 4+6): `mfn_consensus::constitution` fork-legitimacy invariants (`tail_emission > 0`, uniform rings >= 16, well-formed endowment pricing) enforced on every operator-supplied genesis spec via `GenesisSpecError::Constitution`.
- **F5-P10** (`3789e39`) - privacy surface (lane 5): structural authorship-key firewall — canonical `derive_claiming_keypair` in `mfn-crypto` (byte-compatible with the wallet-local derivation), closed `ClaimingIdentity` constructor, and signing-time `ClaimKeyReusesWalletKey` rejection when a claim pubkey collides with wallet view/spend keys.
- **F5-P8** (`23c14d6`) - privacy surface (lane 5): `mfn_crypto::lsag` (pre-CLSAG legacy) and unwired `oom` compile only under `cfg(test)` or non-default `lsag`/`oom` features — release binaries accept CLSAG only. `PRIVACY_HARDENING.md` §B5 marked shipped.
- **M5.49 + M7.12** (`890a56c`) - permanence hardening (lane 4): consensus + mempool reject storage commitments with inconsistent geometry (`chunk_size` power-of-two, `num_chunks == ceil(size/chunk)`); chunk-inbox gossip writes authenticated against anchored commitments (unknown-commit reject, index/length gate, single-chunk `data_root` verify, no overwrite of held bytes); chunk fan-out verifies the inbox Merkle root against `data_root` before replicating.
- **M2.5.60** (`49c8fb2`) - `clippy::unwrap_used`/`expect_used` warn gate on non-test `mfn-net` + `mfn-node`; delete one-off repair scripts `fix-m2527-boards.ps1` + `write-agents-boards-utf8.ps1` (lane 4).
- **M2.5.59** (`b1c8e6a`) - fix `powershell -NoProfile -File` invoke for resolve-schema-python; archive dry-run staging; `.gitignore` debris patterns (lane 2).
- **M2.5.58** (`c0e73eb`) - `resolve-schema-python.ps1`; wire release-schema scripts + ci-check (lane 2).
- **M2.5.57** (`3e994b9`) - DOCS-QA-2 audit closure; debris purge; gitignore test logs (lane 2).
- **M2.5.56** (`6fe1b18`) - B-10: pin workspace `anyhow` 1.0.103 (RUSTSEC-2026-0190); lane 6.
- **M2.5.55** (`6fe1b18`) - light-chain `EvolutionFailed` integration test; mempool test cleanup; lane 4.
- **M2.5.53** (`bd76bde`) - B-07: restore `cli/parse.rs`; hoist `mod parse` before `run_cli`; lane 4.
- **M2.5.52** (`2904ea3`) - B-07: extract `mfn-rpc/src/dispatch/rpc_params.rs` + `rpc_method_meta.rs` from `dispatch.rs` (~620 lines); lane 4.
- **M2.5.51** (`0d9646a`) - start-all GHA `hub_tip_wait` uses `MFN_POLL_HUB_MAX` (900s); observer catchup soft gate (lag <= 2); ps1 health_check tip>=1 fast path (lane 1).
- **M2.5.50** (`dbf6067`; code `6216aec`) - mfnd early `mfnd_p2p_listening`; POST_START timeout export; participant smoke ps1 parity (lane 1).
- **M2.5.49** (`8650543`) - GHA soft-continue on mesh health + hub_liveness when hub tip>=1 (lane 1).
- **M2.5.48** (`040d31d`) - on-disk debris purge; light-follow quorum `expect` removal (lane 4).
- **M2.5.46–47** (`2b33ced`; code `1152e16`) - B-07 `p2p_peer_quarantine` + `p2p_reconnect_plan` split from `p2p_fanout`; B-08 mfnd `runner`/`mfnd_cli` expect removal; `mfnd_serve` import fix (lane 4).
- **M2.5.43–45** (`b945f73`) - `rehearsal-poll-timeouts.*`; mfnd_serve P2P expect removal; workspace dep hoist; evidence gitignore (lanes 2/4/6).
- **M2.5.39–42** (`4a1862b`) - debris purge via `git clean -X`; mojibake guard + STORAGE_ACCESSIBILITY fix; ci-check `-DocsOnly`/`-RustOnly` + venv cache; frame/chunk decode without panic (lane 2).
- **M2.5.38** (`843e055`) - mfn-cli health probe; GHA voter-dial both-listening soft gate (lane 1).
- **M2.5.37** (`12df02d`) - start-all GHA tip>=1 gate; query_rpc_json_line TCP RPC; hub_liveness 900s (lane 1).
- **DOCS-QA-1** (`5775b07`) - `docs/CODEBASE_IMPROVEMENTS.md` engineering-quality audit (docs-only).
- **M7.11.2** (`0650ad6`) - STORAGE_ACCESSIBILITY Phase B item 4 WASM prove+serve doc sync (lane 3).
- **M2.5.32** (`a35b7a6`) - `.gitignore` debris patterns; board mojibake guard in validate-workflow-encoding; clean `docs/AGENTS.md` rebuild (lane 2).
- **M2.5.31** (`0e0de4e`) - GHA voter-dial/health 900s; nightly rehearsal jobs 90m; soft-continue at tip>=1 + both voters P2P listening (lane 1).
- **M2.5.30** (`2eb8417`) - bash `validate-workflow-encoding` guard path parity with ps1 (lane 2).
- **M2.5.29** (`4bd43f2`) - `-text` gitattributes for boards; `fix-m2527-boards.ps1` UTF-8 repair helper (lane 2).
- **M2.5.27** (`e0a7ebd`) - restore `docs/AGENTS.md` per-lane checklists; sync master board (lane 2).
- **M2.5.26** (`a417f1e`) - UTF-8 guard for agent boards in validate-workflow-encoding (lane 2).
- **M2.5.24** (`001e2c6`) - `validate-rc-helper-scripts` smoke in `ci-check` (lane 2).
- **M7.11** (`bb9600b`) - STORAGE_ACCESSIBILITY.md section 0 (lane 3).
- **M5.48** (`77f2fe1`) - emission deep-sim tier closure (lane 6).
- **M5.47** (`db06c78`) - 256-block equivocation + 1M curve in default CI (lane 6).
- **M5.46** (`1232506`) - combined-inflow emission CI tier complete (lane 6).

---

## Legacy name

The **3agent** board (`3agent.md`) is lanes **1-3** only. It now redirects here so new parallel agents use one registry.

See also: [`docs/ROADMAP.md`](./docs/ROADMAP.md), [`docs/TESTNET.md`](./docs/TESTNET.md), [`scripts/public-devnet-v1/OPERATORS.md`](./scripts/public-devnet-v1/OPERATORS.md).
