# Privacy-Funded Permanence — Improvement Suggestions

> **Scope.** An independent, source-grounded review of ways to make Permawrite
> **more private**, **more secure**, and **more viable** — every item filtered
> through the one vision: **privacy-funded permanence** (privacy fees are the
> engine that pays to keep data alive forever). Suggestions that would weaken
> ring policy, endowment enforcement, or SPoRA verification to buy a quick win
> were dropped.
>
> This document is **suggestions only** — it changes no code and ships no
> parameter flip. It is the independent-review companion to the project's own
> honest inventory in [`PROBLEMS.md`](./PROBLEMS.md), the frontier menu in
> [`F5.md`](./F5.md), and the shipped-vs-remaining logs in
> [`PRIVACY_HARDENING.md`](./PRIVACY_HARDENING.md) /
> [`PERMANENCE_HARDENING.md`](./PERMANENCE_HARDENING.md). Where an item overlaps
> an existing backlog ID (`B-*`, `PM*`, `F5:P*`) that is called out so this
> report **extends and prioritizes** the roadmap rather than duplicating it.
>
> **Grounding.** Every suggestion cites a specific file, symbol, or design.
> Line numbers are as of `main` at commit `8c71a43a`. No benchmarks or numbers
> are invented; all quantities (`min_fee = 0`, `fee_to_treasury_bps = 9000`,
> `bond_amount = 0`, `quorum_stake_bps = 6666`, tail `>> 8`, cap `195_312`,
> `644_558` ppb, …) are read directly from the code or its own tests.

---

## How to read this

Each suggestion lists: **category**, **what to change**, **why it matters**,
**how (high level)**, **tradeoffs / risks**, **effort** (S / M / L), and
**priority** (Critical / High / Medium / Low). The two items marked **Critical**
are genuine security weaknesses and appear first; the remainder are grouped into
the three requested categories and ranked by impact inside the
[master table](#ranked-summary-by-impact).

A recurring distinction below is **wired vs. helper**: a large amount of
permanence-economics machinery (`recommended_min_storage_operator_bond`,
`recommended_backstop_mint_cap_per_slot`, `recommended_fee_to_treasury_bps`,
`rank_spora_lottery`, `cold_proof_overdue`, …) is implemented and tested but is
**not read by `apply_block`** — it exists as a named lever for a future fork.
Several suggestions are therefore "arm what you already built," not "build
something new."

---

## Critical findings (security)

### C1 — The P2P link is cleartext and peer-unauthenticated; tx relay deanonymizes by default

- **Category:** More secure (with direct privacy impact).
- **Where:** `mfn-net/src/transport.rs` (default `P2pTransportKind::Tcp`, "cleartext TCP"), `mfn-net/src/handshake.rs` (`hello_v1_handshake`), `mfn-net/src/frame.rs` (`HelloV1` carries only `genesis_id`), `mfn-node/src/dandelion.rs` (`DandelionConfig::default` → `enabled: false`), `mfn-net/src/gossip.rs` (`recv_gossip_v1` decodes `TxStemV1` and `TxV1` to the *same* ingress, dropping the stem/fluff distinction per hop), `mfn-node/src/p2p_fanout.rs` (`broadcast_fresh_tx`).
- **What to change.** Add an authenticated, encrypted P2P transport (e.g. a Noise `XX`/`IK` handshake with a persistent per-node static key) under the existing `P2pTransportKind` abstraction, and make Dandelion++ **default-on** with a small randomized stem delay once the mesh is stable. Bind the handshake to the node's static key, not only to the shared, public `genesis_id`.
- **Why it matters.** The whole product thesis is "Monero-grade financial privacy funds permanence." Ring signatures hide *which UTXO* was spent ([`mfn-crypto/src/clsag.rs`](../mfn-crypto/src/clsag.rs)), but the network layer currently negates much of that: a transaction is relayed as **plaintext over unencrypted TCP**, and on `submit_tx` the node fans it to peers immediately (`broadcast_fresh_tx`) with Dandelion++ off by default — so the first peers (and any on-path observer) learn the **origin node** and the **full tx bytes** before confirmation. A passive AS-level or peer-level adversary can map tx → origin IP, which is precisely the metadata ring signatures are meant to deny. On a *permanence* chain this is worse than on a cash chain: correlation logs captured today stay useful forever against immutable history. The handshake authenticating only `genesis_id` (a public value) also means there is no Sybil cost and no cryptographic peer identity to anchor eclipse defenses to.
- **How (high level).** (1) Introduce a `Noise`/`Tor`/`Tcp` variant alongside today's `Tcp`/`Tor` in `transport.rs`; keep plaintext TCP available for loopback CI meshes behind a flag. (2) Generate a static node keypair at first boot; include its public key in the hello and reject mismatches on reconnect. (3) Flip `DandelionConfig::default().enabled` to `true` for internet builds, add per-hop jitter, and preserve the stem/fluff label across hops so a stem tx is not re-fluffed at the first relay. (4) Gate behind the same opt-in soak the project already uses for `--dandelion` to protect CI meshes.
- **Tradeoffs / risks.** Dependency weight and dial latency (Noise/arti); handshake churn risk on the live mesh; CI meshes must keep a cleartext loopback path. Default-on Dandelion++ changes propagation timing and must be soaked (the project already has `dandelion-soak.sh` scaffolding). None of this touches consensus bytes, so it is version-gate-free.
- **Effort:** L. **Priority:** **Critical**.

### C2 — The live chain runs on public, deterministic validator and operator keys (Path A)

- **Category:** More secure / more viable.
- **Where:** `mfn-node/testdata/public_devnet_v1.json` — validator `vrf_seed_hex` = `0101…`, `0202…`, `0303…`; `bls_seed_hex` = `6565…`, `7676…`, `8787…`; operator `payout_seed_hex` = `c3c3…`, `d4d4…`. These seeds deterministically derive the secret keys via `mfn-crypto/src/vrf.rs` (`vrf_keygen_from_seed`) and `mfn-crypto/src/stealth.rs` (`stealth_wallet_from_seed`).
- **What to change.** Treat a real genesis ceremony (fresh, secret, independently-held validator/operator keys) as a hard precondition for **any** value-bearing, incentivized, or production-like deployment — and keep enforcing it mechanically.
- **Why it matters.** Anyone can reconstruct the validator VRF and BLS secret keys from the repo, forge VRF eligibility (`try_produce_slot`), and forge a BLS finality quorum (`verify_finality_proof` in `mfn-consensus/src/consensus/engine.rs`) — i.e. **fully control block production and finality**. This is the single largest security gap between "experimental testnet" and "a network that can hold value." It is *acknowledged and intended* for the current toy testnet; it is listed here because it is the top gating item and must never silently cross into value-bearing use.
- **How (high level).** This is already partly solved and should stay solved: the release signoff/audit tooling (`scripts/public-devnet-v1/release-signoff-manifest-validate.sh`, `release-audit-packet.sh`) **refuses a `go` decision** when genesis carries repeating-byte toy keys, unbonded operators, or `path_a_experimental = true` (see the toy-key and clone-seed rejection cases in `scripts/ci-check.sh`). Keep those gates; pair them with the Path-B ceremony in [`TESTNET_GENESIS_CEREMONY.md`](./TESTNET_GENESIS_CEREMONY.md) and `require_validator_bls_pop: 1` (closes [`PROBLEMS.md` §13](./PROBLEMS.md#13-genesis-validators-bypass-bls-proof-of-possession-partially-resolved)).
- **Tradeoffs / risks.** None to the design — this is operational discipline. The only risk is human: shipping a convenience default into a live value-bearing context. The mechanical `go`-gate is the mitigation.
- **Effort:** S (mechanism exists; this is a standing gate). **Priority:** **Critical** (for any non-toy deployment; already mitigated on the current testnet).

---

## 1. More private

### P1 — Hide the transaction fee inside the balance equation

- **What to change.** Replace the public plaintext `tx.fee` with a committed fee (Pedersen + range proof), revealing only the per-block aggregate fee needed for the coinbase check.
- **Where:** `mfn-consensus/src/transaction/verify.rs` — the balance check uses `balance -= generator_h() * Scalar::from(tx.fee)` with `tx.fee` a cleartext `u64`; `mfn-consensus/src/transaction/wire.rs` carries it in the clear. Tracked as [`F5:P6`](./F5.md) / `B6` in [`PRIVACY_HARDENING.md § B6`](./PRIVACY_HARDENING.md#b6-hidden-fees-f5p6--consensus).
- **Why it matters.** The fee is the **last cleartext amount on every transaction**. Amounts are Pedersen-committed, outputs are stealth, senders are ring-hidden — but a plaintext fee is a strong fingerprint (wallet-version and payment-size correlation) and, because fees are the funding signal for permanence, fee amounts are also the most economically revealing field. Hiding it closes the final amount-privacy gap without weakening the "fees fund permanence" accounting, since consensus only needs the **aggregate** fee per block.
- **How (high level).** Commit each fee as `fee·H + r·G` with a Bulletproof range proof (reuse `mfn-crypto/src/bulletproofs.rs`); carry the per-input pseudo-fee blinding so `Σ pseudo − Σ out − Σ fee == 0` still closes; expose only `Σ fee` for `block_coinbase_specs` / `producer_portion_amount` in `mfn-consensus/src/emission.rs`.
- **Tradeoffs / risks.** Consensus wire change → version gate + M5 proptests; larger txs; the producer-fee split must be recomputed from the aggregate. High blast radius if the balance refactor is wrong (this is the exact surface that produced the historical counterfeit-input class).
- **Effort:** L. **Priority:** High.

### P2 — Shrink the "this is an upload" metadata class

- **What to change.** Move storage-anchor (upload) transactions toward being shape-indistinguishable from ordinary transfers, and bucket upload fees so the funding act is less self-identifying.
- **Where:** `mfn-consensus/src/transaction/verify.rs` makes upload txs a publicly distinguishable class: `let has_storage = tx.outputs.iter().any(|o| o.storage.is_some())`, and MFEX `tx.extra` is *only* allowed on storage txs ("MFEX is only allowed on storage-anchor txs"). `apply.rs` then prices a large, distinctive endowment burden on exactly those txs.
- **Why it matters.** Privacy funds permanence — but the **funding transaction is the most deanonymizing one on the chain.** An upload is publicly flagged (storage output present, `MFER`/`MFEX` extra present, unusually large treasury-bound fee to cover `required_endowment`). So while *who* uploaded is stealth-hidden, the fact that *a given tx is an upload*, its size bucket, and its endowment magnitude partition the anonymity set into "uploaders" vs "payers" and leak the economic act that is central to the system's purpose. The chain's core differentiator should not be its biggest metadata beacon.
- **How (high level).** Incremental: (a) standardize upload fee/endowment into coarse public buckets (extends `B13`/[`F5:P15`](./F5.md) size buckets already shipped in `mfn-storage/src/commitment.rs`) so endowment magnitude reveals a bucket, not a document; (b) allow (optionally require) ordinary transfers to carry a uniform-size `extra` envelope so presence of `extra` is not itself an upload tell; (c) longer term, decouple "pay" from "anchor" so the value transfer and the storage commitment need not co-occur in one visibly-special tx.
- **Tradeoffs / risks.** Full shape-uniformity is expensive (dummy storage fields cost bytes and endowment); partial measures still help. Consensus-visible changes need version gates. Must not weaken endowment enforcement (the funding check in `apply_block` must still bind).
- **Effort:** M–L. **Priority:** Medium.

### P3 — Make decoy selection a canonical, cross-wallet contract (and keep the Tier-3 exit on the roadmap)

- **What to change.** Pin a single deterministic decoy-selection algorithm that every reference frontend shares, and keep driving toward one-of-many membership proofs so rings (and their gamma-calibration weakness) are retired.
- **Where:** `mfn-crypto/src/decoy.rs` — `DEFAULT_GAMMA_PARAMS` are Monero's empirically-tuned constants (`shape: 19.28, scale: 1/1.61`); selection is wallet-side and inherits Monero's known statistical-distinguisher limitation (documented in [`PROBLEMS.md` §9](./PROBLEMS.md#9-decoy-selection-remains-a-statistical-not-cryptographic-privacy-property)). The one-of-many primitive already exists but is unwired in `mfn-crypto/src/oom.rs` ([`F5:P2`/`P11`](./F5.md), `B11`).
- **Why it matters.** Decoy realism is a *statistical*, not cryptographic, property: if two reference wallets sample decoys differently (different gamma params, different co-height tie-breaks, different pool construction from `list_utxos`), the difference **partitions the anonymity set by wallet implementation** — a classic chain-analysis wedge. The project already hardened co-height selection (B4) and the production RNG contract (B3); the remaining uplift is (a) a single normative selection vector all frontends are conformance-tested against, and (b) the Tier-3 OoM endgame that removes the heuristic entirely.
- **How (high level).** (a) Add a decoy-selection golden vector and a conformance test that every reference frontend (wallet, WASM, CLI) must reproduce, extending `mfn-wallet/tests/canonical_conformance.rs`; formalize the decoy-RNG entropy contract ([`F5:F9`](./F5.md)). (b) Wire `oom.rs` into a UTXO-accumulator membership formulation as the long-horizon ring replacement.
- **Tradeoffs / risks.** The conformance vector is low-risk and high-value now. The OoM wiring is research-grade (consensus + crypto, very high effort) and should not be rushed.
- **Effort:** S (conformance vector) / XL (OoM). **Priority:** Medium (conformance) / High-but-long (OoM).

### P4 — Default encrypt-before-upload in every reference frontend

- **What to change.** Make reference upload paths encrypt payloads client-side by default, so permanent public storage is not a permanent plaintext corpus.
- **Where:** `mfn-wallet/src/upload.rs` (`build_storage_upload`), `mfn-wasm/src/upload_core.rs`, `mfn-cli/src/wallet_cmd.rs` upload path. Tracked as [`F5:F2`](./F5.md).
- **Why it matters.** Permanence amplifies every privacy leak: data anchored today is retrievable *forever*. If the reference wallet uploads plaintext by default, the chain becomes a permanent, publicly-served corpus that can be mined for deanonymization long after the fact (and combined with C1's origin leak). Encrypt-by-default makes "permanent" and "private" compose instead of conflict, which is the whole point of fusing the two halves.
- **How (high level).** Derive a per-upload symmetric key from the uploader's seed (domain-separated, disjoint from spend/view/claim keys per the `B10` firewall in `mfn-crypto/src/authorship.rs`); encrypt chunks before Merkle commitment; store the key-wrap for the owner. Keep an explicit "publish plaintext" opt-out for genuinely public data. No consensus change — SPoRA proves possession of whatever bytes were committed.
- **Tradeoffs / risks.** Key management/recovery UX; encrypted data is not publicly readable (feature, not bug, but must be a clear choice); does not change on-chain size/endowment economics.
- **Effort:** M. **Priority:** Medium.

---

## 2. More secure

### S1 — Default header v2 so finality actually attests the tip UTXO/root set

- **What to change.** For any real validator set, default `header_version: 2` so the BLS finality signature covers `utxo_root` (and, ideally, the storage/claims roots) at the tip rather than one block late.
- **Where:** Public devnet pins header v1 (`public_devnet_v1.json` omits `header_version`, defaulting to `HEADER_VERSION` = 1). `HEADER_VERSION_UTXO_QUORUM` (v2) in `mfn-consensus/src/block/header.rs` appends `utxo_root` to `header_signing_bytes`; `apply_block` enforces it when set. Documented in [`PROBLEMS.md` §12](./PROBLEMS.md#12-utxo_root-is-not-covered-by-the-finality-signature-partially-resolved).
- **Why it matters.** On v1, the committee's aggregate signs every header root **except** `utxo_root`; the post-block accumulator is only bound transitively one block later via `prev_hash`. Any feature that consumes the *tip* accumulator (Tier-3 OoM membership proofs, light-client-backed deposits, cross-chain bridges) must treat the tip root as provisional. For a chain that wants light clients and membership proofs over the UTXO set, making the quorum directly attest the tip state removes a one-block trust window and a whole class of "the signature doesn't cover what you think" surprises.
- **How (high level).** Set `header_version: 2` in Path-B genesis (`GenesisConfig::header_version` already threads it; `genesis-header-version-rehearsal-smoke` already gates it). Consider extending v2 coverage to `storage_root`/`claims_root` at the tip in the same bump, and bump `CHAIN_CHECKPOINT_VERSION` so cold-start decode preserves `header_version` fidelity (the residual noted in §12).
- **Tradeoffs / risks.** Consensus/version change (only for new chains); checkpoint-codec follow-up needed for cold start; no effect on existing v1 testnet.
- **Effort:** M. **Priority:** Medium (High before any tip-root-consuming feature ships).

### S2 — Set the finality quorum strictly above two-thirds for real validator sets

- **What to change.** For any production/incentivized validator set, use `quorum_stake_bps ≥ 6667` (strictly greater than 2/3), not the testnet's `6666`.
- **Where:** `public_devnet_v1.json` sets `"quorum_stake_bps": 6666`; the crate default is `6667`. The check is `required = (total_stake * quorum_stake_bps).div_ceil(10_000)` in `mfn-consensus/src/consensus/engine.rs` (`verify_finality_proof`).
- **Why it matters.** Quorum-intersection safety for an aggregate-signature finality gadget needs the quorum fraction *strictly greater than* `(1 + f)/2`; for the classic `f = 1/3` Byzantine bound that is `> 2/3 = 0.66667`. `6666` bps = `0.6666` sits **just below** that boundary: two conflicting quorums can then overlap only in `< 1/3` of stake, which could be entirely Byzantine → two finalized conflicting blocks. On the current 3-validator toy testnet this is a deliberate liveness tuning (and moot, since the keys are public per C2), but it is the wrong default to carry into a real validator set.
- **How (high level).** Pin `quorum_stake_bps: 6667` (or higher) in any Path-B / incentivized genesis; add a constitution check (`mfn-consensus/src/constitution.rs` / `validate_constitution`) that rejects a sub-2/3 quorum for non-experimental genesis.
- **Tradeoffs / risks.** Slightly stricter liveness (needs genuinely `> 2/3` stake online); negligible for a healthy validator set; one-line genesis change plus an optional guard.
- **Effort:** S. **Priority:** Medium.

### S3 — Forward privacy against harvest-now-decrypt-later (hybrid PQ stealth)

- **What to change.** Hybridize the stealth shared-secret derivation with a post-quantum KEM so recipient unlinkability survives a future discrete-log break.
- **Where:** `mfn-crypto/src/stealth.rs` — detection rests entirely on ECDH (`shared = r·A`, `P = H_s(shared)·G + B`). Tracked as [`F5:P12`](./F5.md) / `B12` and in [`PQ_MIGRATION.md`](./PQ_MIGRATION.md).
- **Why it matters.** This is the sharpest place where **permanence makes a privacy risk uniquely urgent.** Pedersen amounts are information-theoretically hiding, but stealth-address linkage is only computationally hidden under ECDH. On an ordinary chain a future DLP break is bad; on a *permanence* chain the ciphertext and outputs are deliberately kept **forever**, so an adversary can archive today and retroactively deanonymize every historical recipient the day discrete log falls. Hybridizing now protects the back-catalog that the system is specifically built to preserve.
- **How (high level).** Derive `s_shared = H(ECDH ‖ ML-KEM_secret)` so unlinkability holds if *either* assumption survives; version-gate the stealth wire; sequence against the broader key-rotation plan in `PQ_MIGRATION.md` ([`F5:PM9`](./F5.md)).
- **Tradeoffs / risks.** Larger outputs (KEM ciphertext per output); wire/version change; added crypto surface. Significant but strategically aligned effort.
- **Effort:** L. **Priority:** High (strategically), Medium (urgency today).

### S4 — Continuous differential fuzzing of `apply_block` (and a path to a second implementation)

- **What to change.** Stand up continuous differential/structure-aware fuzzing of the state-transition function, and keep a second-implementation / formal-core track alive for the consensus hot path.
- **Where:** `mfn-consensus/src/block/apply.rs` is a ~1200-line single function composing privacy checks, ring-membership, double-spend, endowment binding, SPoRA settlement, slashing, bonding, and the coinbase. The attack-surface concern is [`PROBLEMS.md` §8](./PROBLEMS.md#8-extreme-complexity-and-large-attack-surface); tracked as [`F5:PM25`](./F5.md) (fuzzing) / [`PM14`](./F5.md) (second client) / [`PM15`](./F5.md) (formal verification).
- **Why it matters.** The project's own canonical cautionary tale — the counterfeit-input attack — was a single missing check in exactly this function, and it would have been economically catastrophic. The codebase has excellent *deterministic* test coverage and golden vectors, but a privacy+permanence STF with this many interacting invariants (ring membership, torsion-free key images, endowment openings, operator-salted SPoRA, multi-operator replication caps, backstop minting) is where a subtle, value-destroying bug is most likely to hide. Fuzzing that re-applies mutated blocks and asserts the "reject leaves state untouched" invariant is the highest-leverage way to keep finding these.
- **How (high level).** Add a `cargo-fuzz`/proptest harness that mutates encoded blocks and asserts (a) no panic, (b) rejected blocks leave state byte-identical, (c) accepted blocks round-trip through the checkpoint codec; run it in CI/nightly. Keep publishing golden vectors to make an eventual second implementation cheap to conformance-test.
- **Tradeoffs / risks.** Fuzzing is pure upside (no consensus change); the second-implementation and formal-verification tracks are large and long-horizon — list them as direction, not near-term.
- **Effort:** M (fuzzing) / XL (second client, formal core). **Priority:** Medium (fuzzing now).

---

## 3. More viable

### V1 — Require every private transaction to actually fund permanence (a real minimum fee)

- **What to change.** Introduce a consensus- (or at minimum relay-) level minimum fee for value transfers, ideally scaled to the resources a private tx consumes (ring size, output count, bytes), so no private transaction is a zero-cost free rider on the permanence treasury.
- **Where:** `mfn-runtime/src/mempool.rs` — `MempoolConfig::default_config()` sets `min_fee: 0` with the comment "no floor (consensus has no floor either)," and the live daemon constructs exactly this default (`mfn-node/src/mfnd_serve.rs` → `Mempool::new(MempoolConfig::default())`). `verify_transaction` / `apply_block` enforce **no** minimum fee; a pure transfer (no storage output) can carry `tx.fee = 0` and still be relayed and mined.
- **Why it matters.** This is the single sharpest gap against the stated thesis. [`OVERVIEW.md`](./OVERVIEW.md) says "**every confidential transfer pays a fee. Every fee goes 90% into the storage treasury.** Privacy demand becomes the inexhaustible economic engine that funds permanence." But today a confidential transfer can pay **zero**, obtain full privacy (ring-16, stealth, RingCT), consume anonymity-set and block-space resources, and contribute **nothing** to permanence. The funding engine is opt-in. If adoption is privacy-heavy but fee-light, the treasury starves exactly when it is most needed — and the only backstop is unbounded minting (see V3). Coupling the privacy benefit to a minimum permanence contribution is what turns "privacy *can* fund permanence" into "privacy *does* fund permanence."
- **How (high level).** (1) Near term, set a non-zero `min_fee` in the live `MempoolConfig` (relay policy) so the default mesh stops relaying zero-fee transfers. (2) Durable fix: add a consensus minimum-fee rule — a floor, or a size/ring-scaled fee (fee ≥ `k · tx_weight`) — version-gated in `verify_transaction`, so the funding obligation is network-wide and not just local policy. Keep it modest so privacy stays accessible; the goal is "non-trivial and proportional," not "expensive."
- **Tradeoffs / risks.** A consensus fee floor is a version gate + economic parameter needing M5 proptests and a fork; too high harms accessibility and fungibility; interacts with hidden fees (P1 — the floor must be checkable against a committed fee). A relay-only `min_fee` is trivial but bypassable by a hostile producer, so it is a stopgap, not the fix.
- **Effort:** S (relay `min_fee`) / M–L (consensus floor). **Priority:** High.

### V2 — Give permanence an economic stick: enable operator bonds + meaningful slashing

- **What to change.** Set a non-zero minimum storage-operator bond (and non-zero genesis bonds) on any value-bearing deployment, so B5 slashing actually forfeits value when an operator stops proving.
- **Where:** `public_devnet_v1.json` sets `min_storage_operator_bond: 0` and both operators' `bond_amount: 0`, while `operator_slash_bps: 250` and `operator_audit_missed_cap: 48` are enabled. The slash math is wired (`mfn-consensus/src/storage_operator_evolution.rs`: `forfeited = old_bond * slash_bps / 10_000`), but with `old_bond = 0` every slash forfeits **0**. The sizing helper `recommended_min_storage_operator_bond` exists in `mfn-storage/src/endowment.rs` but is **not** applied. Tracked as [`PM1`](./F5.md) / `B-307` and [`PROBLEMS.md` §1](./PROBLEMS.md#1-storage-operators-have-limited-skin-in-the-game-bonding-is-opt-in).
- **Why it matters.** Permanence currently rests on *carrot only*: an operator that accepts an upload, banks the economic benefit, then drops the data loses only future rewards on that one file. There is no realized penalty — the "stick is live and the collateral is empty." For a chain whose entire promise is "data stays alive forever," the absence of slashable skin-in-the-game is the core permanence-incentive hole. The project already built the sizing lever (`recommended_min_storage_operator_bond` targets one 2.5% slash covering `C₀(1 GiB × min_replication)`); arming it makes defection cost real money.
- **How (high level).** On Path B / post-soak, set `min_storage_operator_bond` to `recommended_min_storage_operator_bond(..)` and require genesis/registered operators to post it (the registry and slash path in `storage_operator_evolution.rs` already enforce the rest). Pair with V4 so distinct bonds map to distinct custody.
- **Tradeoffs / risks.** Raising the floor rejects bondless genesis (a feature); higher bonds raise the operator barrier to entry (centralization pressure to balance against V4/V5); must be sequenced with the economics soak (`B-25`).
- **Effort:** M. **Priority:** High.

### V3 — Stop the silent, unbounded backstop mint; arm the cap and runway alerts

- **What to change.** Wire the PM41 backstop-mint cap and the PM22 treasury-runway metric into the live node, and define what happens when the cap binds (defer/queue operator payout, or shrink the prize) instead of minting without limit.
- **Where:** In `apply_block` settlement (`mfn-consensus/src/block/apply.rs`), the storage-reward shortfall is minted with no ceiling: "Treasury drains first; any shortfall is minted via emission as a backstop," and `storage_reward_total = storage_proof_reward · N + bonus` with nothing capping the per-block mint. The cap helper `recommended_backstop_mint_cap_per_slot` (= `195_312` base units at default, per the crate's own test) and `treasury_runway_slots` / `RunwayAlert` in `mfn-consensus/src/emission.rs` are **helpers not read by `apply_block`.** Tracked as [`PM41`](./F5.md)/`B-311` and [`PM22`](./F5.md)/`B-312`.
- **Why it matters.** This is the failure mode V1 feeds into. If privacy-fee volume drops, the treasury empties and the chain **silently mints fresh MFN every block** to pay operators. The per-block mint ceiling is `storage_proof_reward × (active commitments × replication)`, which **grows with stored data** — so as the network succeeds at permanence, the uncapped inflation it can print also grows. "Privacy funds permanence" quietly degrades into "inflation funds permanence," diluting holders (the project's own test pins default tail inflation at `644_558` ppb vs a recommended `322_279` ppb). A visible cap plus an alert keeps the funding story honest and the inflation bounded.
- **How (high level).** (1) Expose `treasury_runway_slots` / `RunwayAlert` via RPC + ops telemetry so a draining treasury is loud, not silent. (2) After the proof prize is sized down to the C₀ backstop (`recommended_backstop_proof_reward`, `B-306c`), enforce `recommended_backstop_mint_cap_for_window` in settlement; when the cap binds, defer/queue the uncovered payout (or reduce the prize) rather than minting past the cap. (3) Sequence with the subsidy→treasury split (`B-13c`) and endowment drip (`B-306b`) so there is a non-mint buffer first.
- **Tradeoffs / risks.** Capping the mint means operator payouts can be deferred under stress — the policy must keep operators whole over time or it undermines V2's incentive. Wiring the cap today (before the prize shrink) would reject honest proofs, so ordering matters (the code comments flag this). Consensus change → version gate.
- **Effort:** M. **Priority:** High.

### V4 — Make `replication` mean distinct custody, not distinct keypairs

- **What to change.** Tie each proven replica to a distinct, bonded operator identity and reward geographic/network diversity, because operator-salted SPoRA challenges alone do **not** force distinct physical copies.
- **Where:** `mfn-storage/src/spora.rs` derives operator identity purely from payout keys (`operator_identity_from_payout(view, spend) = dhash(STORAGE_OPERATOR_ID, view ‖ spend)`), and `apply_block` accepts "up to `commit.replication` distinct operator proofs per commitment" keyed on that identity. Nothing binds an `operator_id` to a distinct host, a distinct bond, or distinct custody. Related: [`PROBLEMS.md` §7](./PROBLEMS.md#7-state-growth-is-fundamentally-linear-with-usage-and-difficult-to-prune) context and the B3 replication-accounting notes in [`PERMANENCE_HARDENING.md § B3`](./PERMANENCE_HARDENING.md#b3-replication-accounting--make-replication-mean-something-at-audit-time--consensus-phases-13-shipped-genesis-flags-off); diversity scoring is [`F5:PM20`](./F5.md).
- **Why it matters.** A user who pays for `replication = 3` is promised three independent copies. But one machine holding the full file can register three payout keypairs, compute all three per-operator challenge indices locally (the salt is a function of its own keys), and answer every "replica" from the single copy — passing audits while providing **one** point of failure. Operator-salting raises the *appearance* of replication diversity without the substance. Because permanence is the durable product, replication that doesn't survive a single disk/host loss is the quietest and most dangerous permanence gap. (Underscored by V2: with `bond_amount = 0`, registering extra identities is free.)
- **How (high level).** (1) Make distinct `operator_id`s cost a distinct bond (V2) so Sybil replicas are expensive. (2) Add geo/ASN-diverse replication scoring ([`F5:PM20`](./F5.md)) that rewards replicas served from distinct network locations. (3) Longer term, move toward proof-of-retrievability / time-separated challenge-response that a single on-demand fetch cannot satisfy, and consider erasure coding below the replication layer (V6). Keep SPoRA's fast per-block audit; add these as the economic/diversity layer on top.
- **Tradeoffs / risks.** Bond-per-identity and diversity scoring add economic and measurement complexity; network-location signals are spoofable and must be weighted, not trusted; true proof-of-replication is research-grade. Partial measures (bonds + diversity rewards) already move the needle.
- **Effort:** L. **Priority:** High.

### V5 — Replace the first-to-publish SPoRA race with the windowed lottery you already built

- **What to change.** Wire the windowed SPoRA lottery ranking so storage rewards stop being a pure latency race to producers.
- **Where:** `apply_block` pays storage proofs in **block-body order** (first valid proof that lands accrues the slot's yield), and `mfn-storage/src/spora.rs` notes rewards go to "the first proof that lands." The ranking helper `rank_spora_lottery` / `spora_lottery_window_seed` in `mfn-storage/src/lottery.rs` is implemented and tested but **not wired**. Tracked as [`PM3`](./F5.md) / `B-308` / `B-44` and [`PROBLEMS.md` §6](./PROBLEMS.md#6-spora-proof-winning-is-a-pure-first-to-publish-latency-race).
- **Why it matters.** First-to-publish rewards whoever has the lowest-latency path to active producers, which structurally favors well-connected data centers and cloud regions — a centralization pressure on exactly the operator set permanence depends on. Over time that concentrates custody (the opposite of V4) and makes the storage layer fragile to correlated failure. A per-window lottery that ranks in-window operators independently of arrival order lets geographically diverse, slower operators win their fair share, which keeps replication genuinely distributed.
- **How (high level).** In settlement, select winners for a window via `rank_spora_lottery(window_seed, operator_ids)` instead of body order; seed from `prior_block_id` (not producer VRF, to avoid leader bias — the module already warns against this). Coinbase-fork change, so sequence after the multi-operator pack (`B-32`).
- **Tradeoffs / risks.** Consensus change → version gate + heavy multi-operator proptests; must not let the lottery be grindable by producers; interacts with V4 (diversity) and V2 (bonds).
- **Effort:** L. **Priority:** Medium.

### V6 — Survive correlated loss: erasure coding + availability sampling

- **What to change.** Add erasure coding beneath the replication layer and availability sampling so light clients can probabilistically confirm data is actually retrievable, not merely proven-held by whoever answered.
- **Where:** SPoRA proves possession of one challenged chunk by whoever publishes first (`mfn-storage/src/spora.rs`); there is no erasure coding and no client-side availability sampling. Tracked as [`F5:PM4`](./F5.md) (erasure coding) / [`PM7`](./F5.md) (availability sampling) / [`PM11`](./F5.md) (DAS at consensus).
- **Why it matters.** Replication protects against independent single failures, but correlated loss (an operator cohort churns, a region goes dark) can take out all replicas of cold data at once, and SPoRA only tells you *someone* answered this block — not that the data is broadly retrievable. Erasure coding lets the network reconstruct from a subset of surviving shards (more durability per byte stored), and availability sampling gives light clients a cryptographic reason to believe permanence is real rather than trusting that an operator will answer a retrieval later. Both deepen the actual durability guarantee behind the permanence promise.
- **How (high level).** Encode chunks with an `(n, k)` erasure code before Merkle commitment (chunk-format v2, [`F5:PM21`](./F5.md)); define shard challenges so proving a shard implies reconstructability; add a light-client availability-sampling RPC that fetches random shards and verifies inclusion. Large, staged, consensus-adjacent work.
- **Tradeoffs / risks.** Significant protocol complexity and wire changes; erasure coding changes endowment pricing (cost per usable byte); research-grade for the DAS variant. High payoff for the permanence guarantee, high effort.
- **Effort:** XL. **Priority:** Medium (long-horizon).

### V7 — Buffer treasury inflow so permanence isn't one-point-dependent on fee volume

- **What to change.** Arm the already-built non-fee inflows — the subsidy→treasury split and the r=0 endowment drip — so the treasury has buffers before it ever reaches the mint backstop.
- **Where:** `DEFAULT_EMISSION_PARAMS.subsidy_to_treasury_bps = 0` and `DEFAULT_ENDOWMENT_PARAMS.deflation_funded_drip = 0` (both off on Path A). The machinery exists: `subsidy_treasury_credit` / `effective_emission_params` in `mfn-consensus/src/emission.rs` and `deflation_funded_drip` accrual in `mfn-storage/src/endowment.rs`. Tracked as `B-13c` ([`FEES.md § 5.4`](./FEES.md#54-subsidy-tail-split--approved-for-next-parameter-fork-10--treasury)), `B-306b` ([`B306_ENDOWMENT_DRIP.md`](./B306_ENDOWMENT_DRIP.md)), and [`F5:PM5`](./F5.md); context in [`PROBLEMS.md` §2](./PROBLEMS.md#2-r--0-default-makes-permanence-heavily-dependent-on-continuous-high-privacy-transaction-volume).
- **Why it matters.** Today permanence funding on Path A is almost entirely privacy-fee volume plus the mint backstop. That is a single point of failure: a quiet-fee period drains the treasury and forces minting (V3). Routing a slice of block subsidy into the treasury (B-13c) and letting r=0 proofs drip the sized first-year cost from the endowment principal (B-306b) give the treasury structural buffers, so privacy fees become *surplus that accelerates permanence* rather than *the only thing keeping old data alive* — which is the intended "privacy as surplus" shape of the thesis.
- **How (high level).** Sequence the already-drafted forks: enable `subsidy_to_treasury_bps` (e.g. the drafted `1000`) via the activation-height overlay after the soak (`B-13b`/`B-13c` human sign-off); enable `deflation_funded_drip` with the C₀-sized backstop prize on Path B / post-`B-25`. Keep the `go`-gates and telemetry from C2 in force.
- **Tradeoffs / risks.** Each is a coinbase/parameter fork needing sign-off and M5 sims; shifting subsidy from producers to treasury slightly weakens producer margins (balance against security budget); must not be flipped silently on Path A (the code is deliberately inert until a named ceremony).
- **Effort:** M. **Priority:** Medium.

---

## Ranked summary (by impact)

| # | Suggestion | Category | Effort | Priority |
|---|---|---|---|---|
| C1 | Authenticated + encrypted P2P transport; default-on Dandelion++ | Secure / Private | L | **Critical** |
| C2 | Replace Path A public validator/operator keys before value-bearing use | Secure / Viable | S | **Critical** (gated) |
| V1 | Minimum fee so every private tx funds permanence (close zero-fee free-rider) | Viable | S / M–L | High |
| V2 | Enable operator bonds + meaningful slashing (`PM1`/`B-307`) | Viable | M | High |
| V4 | Make `replication` mean distinct custody, not distinct keypairs | Viable | L | High |
| V3 | Cap the backstop mint (`PM41`) + runway alerts (`PM22`); define fallback | Viable | M | High |
| P1 | Hide the transaction fee in the balance equation (`F5:P6`) | Private | L | High |
| S3 | Hybrid PQ stealth — forward privacy for permanent data (`F5:P12`) | Secure / Private | L | High |
| V5 | Windowed SPoRA lottery instead of latency race (`PM3`/`B-308`) | Viable | L | Medium |
| S1 | Default header v2 — finality covers the tip `utxo_root` (`PROBLEMS §12`) | Secure | M | Medium |
| P2 | Shrink the "this is an upload" metadata class | Private | M–L | Medium |
| P3 | Canonical cross-wallet decoy contract + Tier-3 OoM exit (`F5:P2/P11`) | Private | S / XL | Medium / High-long |
| V6 | Erasure coding + availability sampling (`PM4`/`PM7`) | Viable | XL | Medium |
| S2 | Quorum strictly `> 2/3` (`≥ 6667` bps) for real validator sets | Secure | S | Medium |
| V7 | Arm non-fee treasury inflows (subsidy split + drip) (`B-13c`/`B-306b`) | Viable | M | Medium |
| P4 | Default encrypt-before-upload in reference frontends (`F5:F2`) | Private | M | Medium |
| S4 | Continuous `apply_block` fuzzing (+ second-impl / formal-core track) | Secure | M / XL | Medium |

---

## Explicitly out of scope (dropped — conflict with or do not serve the vision)

- **Chain-native casino / gambling treasury top-ups** — already assessed and rejected ([`PROBLEMS.md` §20](./PROBLEMS.md#20-chain-native-casino-as-treasury-funding-assessed--rejected), [`CASINO_RANDOMNESS_FEASIBILITY.md`](./CASINO_RANDOMNESS_FEASIBILITY.md)): expands regulatory/brand risk and competes with "privacy fees fund permanence."
- **General-purpose smart contracts / programmability** — assessed and rejected ([`SMART_CONTRACTS_FEASIBILITY.md`](./SMART_CONTRACTS_FEASIBILITY.md)): large privacy/permanence/complexity cost, off-thesis.
- **Weakening ring policy, endowment enforcement, or SPoRA verification to lower fees/latency** — directly violates the priority doctrine; omitted by construction.

## What is already strong (so these suggestions are read in context)

The core privacy primitives (CLSAG with consensus-enforced uniform ring-16, Bulletproofs, stealth, Pedersen) are faithful ports with the historical counterfeit-input and key-image-malleability classes **closed** (ring-membership check and torsion-free key-image gate in `mfn-consensus/src/transaction/verify.rs` and `apply.rs`). The header-binds-body root family, operator-direct SPoRA payouts, endowment opening/range-proof binding, size-bucketed commitments, chunk-gossip authentication, Dandelion++/Tor as opt-in, signed checkpoint logs, and the release `go`-gates are all shipped. The suggestions above are about **arming built-but-dormant economic levers**, **closing the network-layer and zero-fee gaps that undercut the funding thesis**, and **deepening the durability guarantee** — not about basic cryptographic soundness, which is sound under its stated assumptions.

---

## See also

- [`PROBLEMS.md`](./PROBLEMS.md) — the project's own honest weakness inventory (this report cross-references §§1, 2, 6, 7, 8, 9, 12, 13).
- [`F5.md`](./F5.md) — the privacy/permanence frontier menu (backlog IDs referenced above).
- [`PRIVACY_HARDENING.md`](./PRIVACY_HARDENING.md) / [`PERMANENCE_HARDENING.md`](./PERMANENCE_HARDENING.md) — shipped-vs-remaining implementation logs.
- [`SECURITY_CONSIDERATIONS.md`](./SECURITY_CONSIDERATIONS.md) — protocol trust model and determinism surface.
- [`ECONOMICS.md`](./ECONOMICS.md) / [`FEES.md`](./FEES.md) — treasury, emission, fee split, endowment derivation.
- [`ROADMAP.md`](./ROADMAP.md) — where scheduled items live; [`AGENTS.md`](../AGENTS.md) — live execution board.
