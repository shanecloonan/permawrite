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
| **7** | Testnet launch | Internet-facing go-live (`docs/TESTNET_LAUNCH.md`), VPS runbook, `seed_nodes` publication, launch ceremony | Protocol tests (4/6), CI/Nightly fixes (1), evidence tooling (2) |

Add lanes 8+ in [`docs/AGENTS.md`](docs/AGENTS.md) when needed. Split lanes before they exceed ~2 active units.

---

## CI gate (2026-07-12)

**Head:** `83b82dd` (genesis BLS PoP tooling + TL-9 assert hardening). Prior: `66eb1ea` Q30/legacy fee/PoP gate.

## Current board

| Lane | Current unit | Status | Next handoff |
| --- | --- | --- | --- |
| **1** | CI on pending head | **Doing** — post-push monitor | Nightly on green |
| **2** | Release evidence refresh | **Waiting** — after green CI | Human sign-off packet |
| **4** | F15 MFBN-1 + utxo_root lag | **Done** — `83b82dd` | Idle |
| **7** | TL-9 assert + Path B PoP tooling | **Done** — `83b82dd` | TL-5 VPS soak (human) |

---

## Backlog (unassigned -> claim in lane section)

| ID | Item | Suggested lane | Privacy / performance |
| --- | --- | --- | --- |
| B-02 | M5.33 - proptest: mixed CLSAG + storage upload same block treasury identity | 4 | Done - extends M5.5 |
| B-03 | Promote one ignored emission sim with CLSAG fee mix to CI | 6 | Done - M5.34/M5.35 (`45a118b`, `9537c7b`) |
| B-05 | Linux 30s soak evidence | 2 + 6 | **Done** - soak `#29040052424` PASS max_height=48 (`cf99ae5`) |
| B-06 | Nightly #63 green (all three jobs) | 1 | **Done** - run `28792429191` on `85e5870` stack |
| B-07 | God-file splits (`dispatch.rs`, `cli.rs`, `p2p_fanout.rs`) | 1 + 4 | **Done** - M2.5.46 `p2p_fanout`; M2.5.52–53 dispatch + `cli/parse.rs` |
| B-08 | P2P production `unwrap`/`expect` audit (`mfn-net`, `mfn-node`) | 4 | **Done** - M2.5.47–48 + M2.5.55 light-chain test |
| B-09 | ps1/sh dedup generator or shared timeout constants | 2 | **Done** - M2.5.43 `rehearsal-poll-timeouts.*` |
| B-10 | Workspace dep hoist + RUSTSEC-2026-0190 anyhow path | 6 | **Done** - M2.5.56 anyhow 1.0.103; M2.5.45 hoisted deps |
| B-11 | Bind `StorageCommitment.endowment` Pedersen opening to `required_endowment` in consensus (range proof or opening reveal; today only the fee-share gate is enforced) | 4 + 6 | **Done** — phase 1 + proptests + public devnet genesis enable |

---

## Cross-lane requests

| From | To | Request | Status |
| --- | --- | --- | --- |
| 2 | 1 | Green CI on M2.5.43–45 stack before Nightly #62 dispatch | **Done** - CI #636 |
| 3 | 1 | Nightly #63 participant + observer PASS | **Done** - run `28792429191` |
| 4 | 3 | M5.31-M5.33 protocol tests green before next M7.10 UX | **Done** - `d3a4f36` |
| 7 | 1 | Green CI on head before TL-2 release-evidence refresh | **Done** — CI `#28924060054` on `e7d74f7` |
| TESTNET | all | Mirror completed units into `docs/TESTNET_CHECKLIST.md` | Ongoing |

---

## Recently completed

- **Genesis BLS PoP tooling + TL-9 assert** (`83b82dd`) - testnet launch (lane 7) + protocol (lane 4): `genesis-validator-bls-pop.*` + rehearsal smoke; `launch-go-no-go` uses assert scripts; `vps-execution-checklist` tl5/tl6 assert steps; `docs/interop/VRF_MFBN1.md`.
- **TL-9 checkpoint Schnorr verify** (`d04afed`) - testnet launch (lane 7): `launch-go-no-go` Schnorr-verifies checkpoint log when `seed_nodes >= 3`.
- **vps-internet-soak-evidence-rehearsal-smoke** (`78d236c`) - testnet launch (lane 7): ci-check gate for assert + launch-status fixture.
- **P32 phase 4e** (`b4cab93`) - privacy surface (lane 5): observer template `MFND_PM23_HARD_FAIL=1`.
- **TL-5 soak evidence assert** (`1aff0df`) - testnet launch (lane 7): `assert-vps-internet-soak-evidence.*` + fixture; `launch-status` detects `soak: SUMMARY status=PASS`; ci-check negative gate.
- **P32 phase 4d** (`4a429e4`) - privacy surface (lane 5): `MFN_STORAGE_OPERATOR_PM23_HARD_FAIL=1` on operator VPS template; `mfn-storage-operator` aborts on validator seed env; rehearsal smokes gate all role templates.
- **Nightly `#29175519794` GREEN** (`4a429e4`) - RC core (lane 1): all three jobs on P32 4d stack.
- **CI `#29174819450` GREEN** (`4a429e4`) - P32 phase 4d storage-operator PM23 hard-fail; full matrix pass (~28m).
- **launch-status v5** (`cf2c05d`) - testnet launch (lane 7): `execution_checklist` block links `vps-execution-checklist.v2`; ceremony plan adds checkpoint log + invite path.
- **publish-checkpoint-log-rehearsal-smoke + PM23 phase 4b** (`638f260`) - lanes 5+7: TL-8 checkpoint publish plan gate; `mfnd_pm23_warning` + optional `MFND_PM23_HARD_FAIL=1`.
- **vps-preflight + testnet-invite rehearsal smokes** (`9da922a`) - testnet launch (lane 7): plan-only CI gates on VPS preflight docs and TESTNET_INVITE.md packet.
- **Board sync `648676b`** - RC ops (lane 2): CI `#29088674668` GREEN; release evidence refresh on docs-only head.
- **Nightly `#29088007044` GREEN** (`09edd8a`) - RC core (lane 1): all three jobs on board-sync stack.
- **Board sync `09edd8a`** - RC ops (lane 2): CI `#29086333628` GREEN; release evidence refresh on docs-only head.
- **Nightly `#29085709944` GREEN** (`fac313a`) - RC core (lane 1): all three jobs on TL-7/TL-8 + F12 demo board-sync stack.
- **Board sync `fac313a`** - RC ops (lane 2): CI `#29084142605` GREEN; TL-2 gate closed on docs-only head.
- **Release evidence `05e2772`** - RC ops (lane 2): RC audit dry-run **go** on CI `#29082197263` GREEN head.
- **TL-7/TL-8 + F12 demo web phase 5** (`05e2772`) - testnet launch + onboarding (lanes 3+5+7): `publish-seed-nodes-rehearsal-smoke`, `vps-launch-ceremony-rehearsal-smoke`, `demo-web-f12-rehearsal-smoke`; demo/web checkpoint log verify + cross-check UI; CI `#29082197263` GREEN.
- **Nightly `#29081319938` GREEN** (`4688735`) - RC core (lane 1): all three jobs on TL-5/TL-6 VPS rehearsal stack.
- **TL-5/TL-6 VPS rehearsal smokes** (`4688735`) - testnet launch (lane 7): `vps-internet-soak-rehearsal-smoke` + `vps-participant-rehearsal-rehearsal-smoke` plan gates in ci-check + GHA; CI `#29079154415` GREEN.
- **Nightly `#29077379017` GREEN** (`3067bf9`) - RC core (lane 1): all three jobs on launch-go-no-go stack.
- **CI launch-go-no-go bash fix** (`3067bf9`) - RC core (lane 1): capture non-zero exit from `launch-go-no-go.sh` in rehearsal smoke; CI `#29075258454` GREEN.
- **launch-go-no-go-rehearsal-smoke** (`bbc57a1`) - testnet launch (lane 7): plan-only CI gate on pre-launch `launch-go-no-go.v1` JSON + TL-9 command in vps-execution-checklist.
- **F6 Arweave durability comparison** (`bff1b70`) - permanence depth (lane 6): `ECONOMICS.md` §12 permanence durability vs Arweave.
- **F6 tail split approved (docs)** (`9a2673a`) - permanence depth (lane 6): `FEES.md` §5.4 approves 10% subsidy tail → treasury for next parameter fork (implementation deferred).
- **Nightly `#29071784488` GREEN** (`808529a`) - RC core (lane 1): all three jobs on PM23/F6 stack.
- **CI `#29068155204` GREEN** (`808529a`) - RC core (lane 1): PM23/F6/treasury-telemetry rehearsal smokes; full matrix pass.
- **P32 phase 4a / PM23** (`808529a`) - privacy surface (lane 5): `pm23-operator-manifest-rehearsal-smoke` plan gate for operator-manifest separation on role env templates + docs.
- **F6 treasury telemetry watch** (`808529a`) - permanence depth (lane 6): `treasury-telemetry-watch.*` read-only `get_chain_params` helper for FEES.md §5 revisit triggers.
- **launch-status rehearsal smoke** (`808529a`) - testnet launch (lane 7): dedicated `launch-status-rehearsal-smoke.*` wired into ci-check + GHA.
- **F6 fee economics docs** (`d4a5114`) - permanence depth (lane 6): [`FEES.md`](docs/FEES.md) plain-language fee breakdown (90/10 split, upload endowment gate); 2026-07 parameter review (keep current fees; reject tail→treasury split for now); `ECONOMICS.md` §3/§7/§8/§10 sync to shipped operator-direct payout.
- **CI `#29066731152` GREEN** (`6b884ea`) - RC ops (lane 1+2): launch-status v4 GHA gh-token fix; full matrix pass.
- **Release evidence `6b884ea`** - RC ops (lane 2): launch-status v4 stack + RC audit dry-run **go** on CI `#29066731152`.
- **launch-status v4** (`895ac1e`) - testnet launch (lane 7): TL-8 checkpoint log tracking (`entry_count`, `published`, optional `verify`); `launch-go-no-go` requires non-empty log when `seed_nodes >= 3`; ci-check + GHA smoke on `launch-status.v4` schema.
- **P32 phase 2** (`db58ae1`) - privacy surface (lane 5): `vps-role-*.env.example` role-separated VPS templates; OPERATORS.md + `reference-topology-rehearsal-smoke` template gate.
- **F12 phase 4** (`5965525`) - protocol surface (lanes 4+6): `checkpoint-log cross-check` CLI; `publish-checkpoint-log.*` TL-8 operator tooling; live rehearsal smoke.
- **F12 phase 3** (`5d78329`) - protocol surface (lanes 4+6): `mfn-checkpoint-log` shared crate; WASM `checkpointLogVerify` / `checkpointLogCrossCheck` parity with CLI cross-check.
- **F12 phase 2** (`10e606e`) - privacy surface (lanes 4+5): `wallet light-scan --checkpoint-log`; `cross_check_summary_against_checkpoint_log`; rejects log disagreement at same `tip_height`.
- **F12 phase 1** (`50782a3`) - privacy surface (lanes 4+5): `mfn-cli checkpoint-log sign|verify`; [`CHECKPOINT_LOG.md`](docs/CHECKPOINT_LOG.md); plan-only rehearsal in ci-check.
- **B-05 Linux soak refresh** (`cf99ae5`) - RC core (lanes 1+2): soak `#29040052424` PASS max_height=48 on F12/wasm stack (`3b19e7c`); evidence `soak-restart-linux-30s-slot-20260709T185101Z.txt`.
- **P32 reference topology** (`85f3512`) - privacy surface (lanes 4+5): `REFERENCE_TOPOLOGY.md` + plan-only rehearsal in CI; CI `#29040315598` GREEN; Nightly `#29040048884` GREEN; release evidence RC audit **go** (`f6bc358`).
- **F12 checkpoint anchor peers** (`0cf73c6`) - privacy surface (lanes 4+5): `anchor_peers` in trusted summary + `--p2p-anchor-summary`; CI `#29036301962` GREEN after wasm-pack fix (`3b19e7c`).
- **Nightly `#29042017113` GREEN** - RC core (lane 1): all three jobs on P32.1 stack (`85f3512`).
- **P32 reference topology doc** (`85f3512`) - privacy surface (lanes 4+5): [`REFERENCE_TOPOLOGY.md`](docs/REFERENCE_TOPOLOGY.md) + plan-only rehearsal smoke in ci-check.
- **F12 checkpoint anchor peers** (`0cf73c6`) - privacy surface (lanes 4+5): `anchor_peers` in trusted summary + `get_light_snapshot`; `--p2p-anchor-summary` boot merge.
- **P31 diversity redial phase 1** (`571e0bf`) - privacy surface (lanes 4+5): `peer_diversity_redial_candidates` + background sweep; CI `#29028631457` GREEN; release evidence RC audit **go**.
- **Nightly `#29025637498` GREEN** - RC core (lane 1): all three jobs on P32 stack (`f76991a`); auto-dispatched after CI `#29023541155`.
- **Release evidence `f76991a`** - RC ops (lane 2): P32 stack + RC audit dry-run **go** on CI `#29023541155`.
- **P32 role topology lint** (`f76991a`) - privacy surface (lanes 4+5): `mfnd_role_topology_warning` when validator + public RPC (+ operator) share advertised host.
- **P31 peer diversity phase 0** (`d3cc1be`) - privacy surface (lanes 4+5): `mfn-net::peer_diversity` /16 bucket metrics; `get_status.p2p` diversity fields; `mfnd_p2p_diversity_warning`.
- **B8.3 tor-rpc rehearsal smoke** (`1ad2dce`) - onboarding (lane 3): plan-only `tor-rpc-rehearsal-smoke` in CI/ci-check; dispatch jobs `continue-on-error` on runner starvation.
- **B8.3 wallet RPC Tor** (`5e540b3`) - privacy surface (lanes 4+5): `mfn-cli --tor` / `MFN_CLI_RPC_TOR` for onion JSON-RPC; quorum RPC peers mirror Tor mode; [`TOR_P2P.md`](docs/TOR_P2P.md) § B8.3.
- **M4.8 / B1 phase 2e** (`bbe1d9f`) - permanence + privacy (lanes 4+5+6): WASM upload merges live `get_chain_params.endowment`; RPC exposes MFER flags; demo web forwards policy; CI `#28999593529` GREEN.
- **MFER participant rehearsal** (lane 3) — Windows smoke PASS on `bbe1d9f`; evidence `participant-rehearsal-no-observer-windows-20260709T070005Z.txt`.
- **B1 phase 2d** (`2958cfa`) - permanence (lanes 4+6): public devnet `require_endowment_range_proof: 1` (same `genesis_id`); forged-blinding reject test; CI `#28995960877` GREEN.
- **B1 phase 2c** (`ba53a15`) - permanence (lanes 4+6): wallet MFEX v3 `MFER` builder; `build_endowment_surplus_range_proof` in mfn-storage; wallet unit test.
- **B1 phase 2b** (`c084537`) - permanence (lanes 4+6): MFEX v3 + `MFER` surplus range proofs; `apply_block` + mempool verify; M5 accept/reject + treasury proptest.
- **B1 phase 2a** (`76b5f8f`) - permanence (lanes 4+6): inert `require_endowment_range_proof`; checkpoint **v10**; mutual exclusion with MFEO; [`B1_ENDOWMENT_RANGE_PROOF.md`](docs/B1_ENDOWMENT_RANGE_PROOF.md).
- **B5 phase 5c** (`8bdb4ab`) - permanence (lanes 4+6): operator bond slash to treasury when `consecutive_missed_audits >= operator_audit_missed_cap`; zero-bond deregister; clippy fix for 5b CI `#28977215094`; full matrix CI `#28979369780` GREEN.
- **F7 mfnd fanout tail** (`b70b3ec`) - RC core (lane 1): `mfnd_p2p_tx_fanout_reaches_third_hop_peer` expects `applied=2` after two-block F7 fixture; closes Nightly ignored-P2P job on `#28928716414`.
- **F7 fund-wallet tail** (`dc22cb7`) - RC onboarding (lane 3): `fund-wallet` top-up sends until `owned_count >= 2`; closes rehearsal `input count 1` upload rejects on `#28928716414`.
- **TL-3 release evidence** (lane 7) — `release-evidence-46677ad` + RC audit dry-run `go` on CI `#28924060054` (`e7d74f7`); TL-2 gate closed.
- **TL-2 CI GREEN** (`e7d74f7`) — lane 7: mempool F7 two-input pad; CI `#28924060054` full matrix pass (~48m).
- **F7 mfnd_smoke tail** (`0825385`) - RC core (lane 1): `synth_decoy_one_step_signed_transfer_fixture` steps 2 blocks so wallet owns ≥2 UTXOs before two-input transfer; closes CI `#28919128030` mempool/P2P admit failures.
- **F7 settlement test tail** (`996f60f`) - permanence (lane 6): `producer_treasury_settlement.rs` two-input companion pad across genesis + all `sign_self_transfer` call sites; closes CI `#28917267975` failure on `fee_only_block_credits_treasury_ninety_percent`.
- **F7 consensus tail** (`3933cf0`) - protocol (lanes 4+5): `RingPolicy.min_input_count` (`MIN_TX_INPUTS_UNIFORM_TIER = 2`) at `verify_transaction` when uniform-ring tier active; mirrors output floor; conformance + spend tests use two inputs under production policy.
- **B2 ChunkV2** (`20954b0`) - permanence (lanes 4+6): Merkle-path chunk gossip tag `0x12`; `validate_gossip_chunk_v2` + `on_chunk_v2`; fan-out/operator push emit proofs; inbound `ChunkV1` retained for mesh compatibility.
- **Release evidence `96462aa`** - RC ops (lane 2): pre-B2 stack evidence + RC audit dry-run go on CI `28885223488` (`0d28e4f`); refresh after B2 CI green.
- **Nightly #28889931523 GREEN** - RC core (lane 1): all three jobs on B-11/B7 stack (`b1072e3`); auto-dispatched after CI `#28885223488`.
- **CI #28885223488 GREEN** (`0d28e4f`) - B7 dandelion rehearsal evidence commit; full matrix pass.
- **B7 dandelion rehearsal** (this commit) - privacy (lanes 3+5): Windows `dandelion-rehearsal-smoke` PASS with MFEO upload on B-11 genesis; evidence `participant-rehearsal-no-observer-dandelion-windows-20260707T171612Z.txt`; archive filenames tag `-dandelion`.
- **Nightly #28884769330 GREEN** - RC core (lane 1): all three jobs on B-11 stack (`0fee187`).
- **CI #28879533724 GREEN** (`0fee187`) - B-11 public devnet MFEO enable; full matrix pass.
- **B-11 public devnet enable** (`0fee187`) - permanence (lanes 4+6): genesis spec `endowment` section; `require_endowment_opening: 1` in `public_devnet_v1.json` (same `genesis_id`); proptest clippy fix.
- **B-11 proptests** (`9f0a0aa`) - permanence (lane 4): `require_endowment_opening=1` — `prop_mfeo_opening_storage_upload_treasury` + reject without `MFEO`.
- **Release evidence `837069a`** (`0a7e326`) - RC ops (lane 2): `release-evidence-refresh-for-head` + RC audit dry-run go on CI `28871239057`.
- **CI #28871239057 GREEN** (`837069a`) - RC ops (lane 2 gate): full matrix after B-11/B7/B9/F7 stack; ends CI churn from parallel pushes.
- **F7/B15** (`837069a`) - privacy surface (lane 5): canonical two-input wallet floor — `WALLET_MIN_TX_INPUTS` + `select_inputs_for_tx` pad real UTXOs into reference transfers/uploads when a second spendable output exists; same-band preference; single-UTXO wallets unchanged.
- **B-05 Linux soak PASS** (`28851202993` on `8ccda5d`) - RC core (lane 1): 35m / 30s-slot soak — 8 iterations, max_height=48, observer restart; evidence `soak-restart-linux-30s-slot-20260707T083949Z.txt`.
- **M2.5.65 (GHA converge)** (`8ccda5d`) - RC core (lane 1): soak GHA converge soft gate + `MFN_HEALTH_MIN_P2P_SESSIONS=0` when `get_status` reports null sessions; soak `28850304866` passed hub_produced then failed converge.
- **M2.5.65** (`76cc778`) - RC core (lane 1): soak WARMUP health-check — `query_get_status_compat_line` prefers mfn-cli `status` (real `p2p.session_count`) over tip synthesis that returned null sessions.
- **B7 (stem wire label)** (`dc8b53b`) - privacy surface (lane 5): `TxStemV1` P2P tag `0x11` for Dandelion++ stem relays; fluff stays on `TxV1` (`0x06`); recv path accepts both.
- **B7 (rehearsal soak)** (`e2f3f63`) - privacy surface (lane 5): `--dandelion` on `start-all` / `soak` / `participant-rehearsal-smoke` (default off); `dandelion-rehearsal-smoke` + `dandelion-soak` wrappers; mesh asserts `mfnd_dandelion=enabled` when enabled.
- **B9 (phase 2)** (`366dfaf`) - privacy surface (lane 5): tx v2 wire adds 1-byte `view_tag` per output (consensus-bound in preimage); reference wallet/coinbase set tags on send; scanner skips ~256× mismatches before stealth-detect; legacy v1 txs still decode/verify.
- **B9 (phase 1)** (`d0d0bfb`) - privacy surface (lane 5): `indexed_view_tag` / `indexed_view_tag_from_shared` in `mfn-crypto` stealth (F5-P7 prep for wire + scanner).
- **B7 (phase 2)** (this commit) - privacy surface (lane 5): `MFND_DANDELION=1` env + `--dandelion` CLI parse tests.
- **B7 (phase 1)** (`1cc9ead`) - privacy surface (lane 5): Dandelion++ stem/fluff tx relay — `dandelion.rs` + opt-in `mfnd serve --dandelion`.
- **B13 authorship + GHA timing** (`5d5cf64`–`934cc2f`) - privacy surface (lane 5): MFCL claim preview uses padded bucket payload; WASM parity (`7821099`); `GITHUB_ACTIONS` hub-timing budget for three-validator smoke; **CI #28838850432 GREEN**.
- **B13 spora fix** (`96fe808`) - revert auto-pad inside `build_storage_commitment`; bucket padding at wallet/WASM/consensus only.
- **B13 test parity** (`e98ff4f`) - mfn-node chunk/archive tests use canonical bucket payloads.
- **B13 (consensus)** (`3d8574c`) - privacy surface (lane 5): consensus-mandatory upload size buckets — `validate_storage_commitment_shape` rejects NEW anchors whose `size_bytes` is not a canonical power-of-two bucket; CLI persists `UploadArtifacts.anchored_payload`; legacy artifact rebuild pads raw payloads.
- **B13 (wallet)** (`4712811`) - privacy surface (lane 5): upload size buckets — reference uploads pad to next power-of-two before anchoring; on-chain `size_bytes` is the bucket; endowment priced on bucket (`storage_size_bucket` / `pad_to_storage_size_bucket`).
- **M2.5.64** (`c5e69f6` + `c7420a2`) - RC ops (lanes 1+2): Linux soak bootstrap pre-builds `mfnd` + `mfn-cli` (workflow `cargo build` + `soak.sh` → `start-all.sh --no-build`); `start-all` invokes child scripts via `bash` and fails fast when hub PID exits before P2P listen; `mfn-cli` required for `query_tip_height` during `hub_tip_wait`.
- **B3 phase 2** (`7a427fa`) - permanence hardening (lanes 4+6): `apply_block` operator-salted replication accounting; `operator_salted_challenges` flag (default off); checkpoint v5; four `block_apply` tests.
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
