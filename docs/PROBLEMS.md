# Known Problems and Weaknesses

This document is an honest inventory of real limitations, incentive misalignments, and architectural tensions in the Permawrite protocol and implementation. It does **not** invent problems for balance. Where the design appears sound under its stated assumptions, that is noted.

The focus is on **economics/incentives** (the harder and more fundamental category), **architectural viability**, and — as of the 2026-07 source audit — **protocol/security-model gaps** (items 11–16 in [SECURITY_CONSIDERATIONS.md](./SECURITY_CONSIDERATIONS.md)). Items 17–18 recorded two vision-critical gaps (**operator-direct SPoRA payout**, **consensus ring-16**); both are **closed** in the current tree. Open operator-pay pressure is now mostly **treasury inflow** (§§ 2, 4, 19) and **proof inclusion fairness** (§ 6), not mis-routed coinbase.

## Economic and Incentive Problems

### 1. Storage operators have limited skin in the game (bonding is opt-in)

> **Status: partially mitigated** (B5 operator bonding + slashing shipped; public devnet enables `min_storage_operator_bond`, operator audit slash params, and `require_endowment_opening` / `require_endowment_range_proof` on uploads). Residual: bondless tier remains valid where genesis permits `bond_amount: 0`; permanence still depends on rational operators holding data without mandatory global bonds.

Storage operators earn by winning SPoRA challenges. **Bonded** operators escrow slashable stake; missed operator-salted audits can forfeit bond to the treasury ([`B5_OPERATOR_SLASHING.md`](./B5_OPERATOR_SLASHING.md)). Unbonded operators still face only the carrot (forego future rewards on defection).

- If an operator accepts an upload, collects the economic benefit (the endowment payment flows into the treasury, and the file contributes to the set of challenges that can earn rewards), and later drops the data, the only consequence for a **bondless** operator is that they stop earning future rewards *on that specific file*. Bonded operators additionally risk slash-to-treasury.
- The `min_replication` parameter (default 3) provides redundancy against single failures, but it is an upload-time check only. There is no ongoing economic penalty for widespread or selective non-compliance beyond B5 audit slashing when enabled.
- See [ECONOMICS.md § 10 Future work](./ECONOMICS.md#10-future-work) and [ROADMAP.md](./ROADMAP.md) for premium-tier bonding research.

This remains a genuine hole for bondless deployments: the permanence guarantee still rests partly on the assumption that enough rational operators will continue to find it profitable to hold data indefinitely.

### 2. r = 0 default makes permanence heavily dependent on continuous high privacy transaction volume

> **Status: open (by design)** — permanence **does not stop** when fees dry up: the emission backstop mints operator payouts when the treasury is short ([`apply_block`](../mfn-consensus/src/block/apply.rs) settlement; `emission_backstop_only_when_treasury_short` in CI). What varies is **inflation character** (scheduled fee/treasury inflow vs emergency backstop spikes). Approved but **not yet shipped:** route 10% of block subsidy to treasury ([`FEES.md` § 5.4](./FEES.md#54-subsidy-tail-split--approved-for-next-parameter-fork-10--treasury), [`ECONOMICS.md` § 12](./ECONOMICS.md#12-permanence-durability-vs-arweave--is-this-model-more-likely-to-break)) — see [§ 19](#19-subsidy-tail-split-approved-but-not-in-consensus-yet).

After the shift to `real_yield_ppb = 0` as the expected/default case (see the two-mode endowment model), storage operators no longer receive yield harvested from individual endowments. Payouts come from:

- 90% of priority fees flowing into the treasury, then out as storage rewards.
- The tiny per-proof emission backstop (`storage_proof_reward = 0.1 MFN` per accepted proof).
- **When treasury is empty:** settlement mints the storage-reward shortfall unconditionally (backstop).

The "endowment" an uploader pays is now largely a large one-time capitalization of the treasury rather than a self-sustaining principal whose yield covers future costs. If privacy-preserving transaction volume (the primary long-term source of treasury inflows) declines or never reaches sufficient scale, the treasury drains and operator revenue relies more on the **emission backstop** — solvency holds, but inflation becomes spikier and less predictable.

This is not a hidden assumption — it is the explicit economic thesis of the project ("privacy demand funds permanence"). It is also a real concentration risk: the storage side of the system has a single point of failure in sustained high-value private economic activity.

### 3. Permanent tail emission is large in absolute terms and creates ongoing dilution

Default tail emission is `(50 MFN) >> 8 ≈ 0.195 MFN per block forever`.

At ~2.63 million slots per year this is roughly **half a million MFN per year** in permanent new issuance (on top of any fee-driven dynamics). Early cumulative pre-tail supply is on the order of hundreds of millions of MFN. Whether this level of perpetual issuance is acceptable depends on adoption and velocity assumptions that are not yet proven. It is a deliberate choice to keep a security + storage budget (see [ECONOMICS.md § 2](./ECONOMICS.md#2-subsidy-curve)), but it is a real long-term dilution vector for holders.

### 4. Producer and storage-operator incentives are only loosely aligned

> **Status: partially mitigated** — operator-direct SPoRA coinbase outputs shipped (§ 17). Producers and operators no longer compete for the **same** coinbase output. Residual: funding paths still diverge — producers keep subsidy + 10% fees + tail; operators depend on treasury + backstop.

- Block producers receive the 10% fee share + subsidy/tail.
- Storage operators are paid out of the treasury (funded by the 90% fee share + validator bonds + slashes + backstop emission), with per-proof coinbase outputs to operator stealth keys.

A rational producer's direct revenue still does not depend on the health of the storage operator set. In a low-fee or low-privacy-usage regime, producers can continue earning the tail emission while operators see **treasury-funded** revenue shrink and backstop minting rise (§ 2).

### 5. Adverse selection on which data actually gets reliably stored

Larger endowments and "hot" (frequently challenged / recently uploaded) files are more economically attractive to store and prove against. Cold archival data, small files, or files whose owners are no longer active have weaker incentives for operators to prioritize. While the protocol enforces minimum replication at upload time, nothing forces ongoing economic interest in every anchored commitment years later.

## Architectural and Viability Concerns

### 6. SPoRA proof winning is a pure first-to-publish latency race

> **Status: open** — no latency-fair inclusion rule in consensus yet. Mitigations are operational (many observers, replication breadth, RPC-only operators) and research-tracked in [`DECENTRALIZATION.md` § Phase C](./DECENTRALIZATION.md) (commit-reveal, VRF-weighted pools). Privacy/permanence policy rejects merging storage into validator duties to “fix” latency.

The challenge is deterministic per slot. The first valid proof that reaches a producer and is included wins the reward (or the accrued yield, when `r > 0`). In a globally distributed network this strongly favors:

- Operators with superior peering and low-latency paths to active producers.
- Geographic or infrastructure concentration (well-connected data centers or cloud regions).

This is a centralization pressure on the storage operator set that the current design does not economically or cryptographically mitigate.

### 7. State growth is fundamentally linear with usage and difficult to prune

Every storage upload creates a permanent `StorageCommitment` entry (with its endowment commitment) that must be retained for future proof verification and light-client inclusion proofs. Combined with a privacy-oriented UTXO model (no easy pruning of spent outputs without breaking decoy sets or ring membership), full node state grows with both economic activity and stored data volume.

Light clients and checkpoints (M2) mitigate verification cost but do not solve archival or resource requirements for operators who must actually serve the data.

### 8. Extreme complexity and large attack surface

The protocol composes:
- Monero-style privacy (stealth addresses, Pedersen commitments, CLSAG, Bulletproofs, decoy sampling)
- Arweave-style permanence (endowment math + SPoRA)
- Custom PoS (VRF leader election + BLS finality + validator rotation with bonds + liveness/equivocation slashing)
- Multiple Merkle roots binding every part of every block body
- PPB-precision accumulator arithmetic for tiny per-slot yields
- Light-client verification primitives

A single subtle error in any commitment, root, range check, or state transition can be economically catastrophic (the counterfeit-input attack that was caught and fixed before deployment is the canonical example). The surface area is large relative to the number of eyes and the maturity of the implementation.

### 9. Decoy selection remains a statistical (not cryptographic) privacy property

The gamma-distribution decoy sampling inherits Monero's known limitation: it only provides plausible deniability *if real user behavior matches the calibration*. Deviations (e.g., always spending the youngest output) create a statistical distinguisher. The planned Tier 3 "OoM over the whole UTXO set" upgrade would remove rings entirely, but until then this is a real, documented weakness (see [PRIVACY.md § Decoy realism](./PRIVACY.md#decoy-realism-gamma-age-sampling)).

### 10. Light-client security ultimately rests on long-term cryptographic and economic assumptions

Header + body verification for light clients is elegant and powerful, but a light client that never sees full state still trusts:
- BLS aggregate signature unforgeability over long ranges.
- VRF correctness and uniqueness.
- That economic finality (slashing) has worked as intended for the checkpoints it relies on.
- Correctness of the various domain-separated Merkle roots.

Long-range attacks are heavily constrained compared to naive PoS, but the mitigations are economic/cryptographic hybrids rather than pure cryptographic finality.

## Protocol / Security-Model Problems

These were surfaced by a source-level audit of the consensus and crypto crates
(2026-07). Each is verified against the referenced code, not inferred from
docs. Deeper analysis of every item lives in
[SECURITY_CONSIDERATIONS.md](./SECURITY_CONSIDERATIONS.md).

### 11. ~~Committee finality does not attest state-transition validity~~ (partially mitigated)

> **Status: fraud-proof phase 3 shipped** — body-root (v1) + coinbase (v2) + invalid CLSAG/SPoRA (v3) verify; P2P tag `0x13` gossips via `verify_interactive_fraud_proof`. Ring-membership mint fraud + producer slash remain phase 3b+.

The reference voting path (`cast_vote` → `verify_producer_proof` in
`mfn-consensus/src/consensus/engine.rs`) verifies the producer's VRF
eligibility and BLS header signature — it does **not** run `apply_block`. A
finality quorum therefore proves "≥ 2/3 stake signed these header bytes," not
"this block's transactions, coinbase, and state roots are valid."

Full nodes are unaffected (they re-execute `apply_block` and reject invalid
blocks regardless of signatures). Light clients can now reject headers whose
body Merkle roots disagree with the attached body (phase 0). Residual risk:
invalid but root-consistent bodies still need honest-quorum or later fraud
classes. See [SECURITY_CONSIDERATIONS.md § 2](./SECURITY_CONSIDERATIONS.md#2-what-a-finalized-header-does--and-does-not--prove).

### 12. `utxo_root` is not covered by the finality signature (partially resolved)

> **Status: genesis-threaded** — header version 2 ([`HEADER_VERSION_UTXO_QUORUM`](../mfn-consensus/src/block/header.rs)) appends `utxo_root` to [`header_signing_bytes`](../mfn-consensus/src/block/header.rs). [`GenesisConfig::header_version`](../mfn-consensus/src/block/genesis.rs) + JSON `header_version` (Path B) pin the chain; [`build_unsealed_header`](../mfn-consensus/src/block/builder.rs) and [`apply_block`](../mfn-consensus/src/block/apply.rs) enforce it. Public devnet v1 stays at header v1 (one-block confirmation lag via [`utxo_root_quorum_confirmation_lag`](../mfn-consensus/src/header_verify/types.rs)). CI: `genesis-header-version-rehearsal-smoke`.

**Historical note (v1 chains).** `header_signing_bytes` committed every
header root **except `utxo_root`**, which appears only in `block_header_bytes`
(the `block_id` preimage). The committee's BLS aggregate therefore does not
directly attest the post-block UTXO accumulator root; it is bound only
transitively, one block later, via `block_id` → next header's `prev_hash`.

Impact is bounded on v1 — full nodes recompute the root, and the tip inherits quorum
binding after one confirmation — but (a) prior doc claims that the BLS
aggregate covers `utxo_root` were wrong (fixed in the same change as this
entry), and (b) any future feature that consumes the **tip** accumulator root
(Tier-3 OoM membership proofs, light-client-backed deposits) must treat it as
provisional for one block on v1 chains.

**Residual:** public devnet v1 stays at header v1; Path B may set `header_version: 2`.
[`CHAIN_CHECKPOINT_VERSION`](../mfn-consensus/src/chain_checkpoint/mod.rs) v10 decode still
defaults `header_version` to 1 — v2 chains need a future checkpoint bump for
cold-start fidelity. See [SECURITY_CONSIDERATIONS.md § 3](./SECURITY_CONSIDERATIONS.md#3-header-commitment-coverage--what-the-quorum-actually-signs).

### 13. ~~Genesis validators bypass BLS proof-of-possession~~ (partially resolved)

> **Status: tooling gate shipped** — [`genesis_config_from_json_bytes`](../mfn-runtime/src/genesis_spec.rs) accepts optional `bls_register_sig_hex` per validator (same payload as `BondOp::Register`) and rejects invalid signatures. Path B ceremonies set `require_validator_bls_pop: 1` to mandate PoP on every row. CLI: [`genesis-validator-bls-pop`](../scripts/public-devnet-v1/genesis-validator-bls-pop.sh); CI: `genesis-validator-bls-pop-rehearsal-smoke`. Toy Path A devnet specs remain seed-derived trusted setup (PoP optional).

Same-message BLS aggregation is rogue-key-attackable without proof-of-possession. Registered validators get PoP for free via `BondOp::Register`. Genesis validators installed by `apply_genesis` still have **no on-chain PoP field** — the gap is closed at **spec-load time** for JSON genesis, not inside `apply_genesis` itself.

- **Path A (toy keys):** seeds in repo ⇒ trusted setup; optional `bls_register_sig_hex` for audit.
- **Path B (ceremony):** set `require_validator_bls_pop: 1`; each operator supplies `bls_register_sig_hex` proving knowledge of `bls_seed_hex` without publishing the seed in the ceremony packet (seed still lands in the final genesis bytes operators deploy — treat genesis file custody as trusted setup).

See [SECURITY_CONSIDERATIONS.md § 4](./SECURITY_CONSIDERATIONS.md#4-bls-aggregation-and-rogue-key-resistance) and [TESTNET_GENESIS_CEREMONY.md](./TESTNET_GENESIS_CEREMONY.md).

### 14. ~~One `f64` survives on the consensus verification path~~ (resolved)

> **Status: closed** — [`eligibility_threshold`](../mfn-consensus/src/consensus/engine.rs) now takes a precomputed Q30 factor from [`proposers_factor_q30_from_f64_bits`](../mfn-consensus/src/consensus/engine.rs) (integer IEEE-754 decode). Header verification never performs `f64` multiply/round. `expected_proposers_per_slot` remains `f64` in `ConsensusParams` checkpoint encoding for compatibility; only `to_bits()` crosses the boundary.

**Historical note.** `eligibility_threshold` previously used `(expected_proposers_per_slot * 2^30).round()` on every `verify_finality_proof` call. Default `F = 1.5` was exactly representable, but non-exact values relied on cross-platform IEEE-754. See [SECURITY_CONSIDERATIONS.md § 6](./SECURITY_CONSIDERATIONS.md#6-determinism-surface-the-one-f64-on-a-consensus-path).

### 15. The VRF is RFC 9381-style, not RFC 9381-conformant

> **Status: documented** — exact MFBN-1 variant spec in [`interop/VRF_MFBN1.md`](./interop/VRF_MFBN1.md). Security-equivalent to RFC 9381; off-the-shelf RFC verifiers reject proofs until they implement try-and-increment `hash_to_point`.

`mfn-crypto/src/vrf.rs` substitutes the protocol's try-and-increment
`hash_to_point` for the RFC-mandated Elligator2 hash-to-curve. Security is
equivalent; **interop is not** — off-the-shelf RFC 9381 verifiers reject
Permawrite proofs. External tooling must implement the MFBN-1 variant, or the
chain must hard-fork to strict Elligator2 before claiming conformance. Docs
that previously said "RFC 9381" without the caveat have been corrected. See
[SECURITY_CONSIDERATIONS.md § 5](./SECURITY_CONSIDERATIONS.md#5-vrf-near-rfc-9381-not-rfc-9381).

### 16. ~~Legacy (validator-less) mode silently drops the producer fee share~~ (resolved)

> **Status: closed** — when no producer coinbase is required (`require_coinbase` false: legacy harness or validators without payout), [`apply_block`](../mfn-consensus/src/block/apply.rs) credits the **full** `fee_sum` to `ChainState.treasury`. The producer share is no longer burned. Emission subsidy still does not mint without a validator coinbase (intentional for test harnesses).

**Historical note.** When `state.validators` was empty, no coinbase was allowed, so only the treasury fee tranche (default 90%) credited `treasury` while the producer share vanished. Fee-split diagrams in [ECONOMICS.md](./ECONOMICS.md) assume a producer exists — legacy mode is dev/test only.

### 17. ~~Storage rewards are paid to the block producer, not to the operator that proved the data~~ (resolved)

> **Status: closed** (operator-direct payout shipped). Each [`StorageProof`](../mfn-storage/src/spora.rs) now carries `operator_view_pub` / `operator_spend_pub`; [`apply_block`](../mfn-consensus/src/block/apply.rs) settlement mints per-operator coinbase outputs (see [`mfn-consensus::coinbase`](../mfn-consensus/src/coinbase.rs)). Consumer storage feasibility is discussed in [`STORAGE_ACCESSIBILITY.md`](./STORAGE_ACCESSIBILITY.md).

**Historical note (pre-fix).** This was the most important incentive gap relative to the project's thesis
("storage operators are paid to keep data alive forever"), and it was
previously mis-described by the economics illustration.

Previously, a [`StorageProof`](../mfn-storage/src/spora.rs) carried
only `{ commit_hash, chunk, proof }` — **there was no operator identity or
payout address**. In [`apply_block`](../mfn-consensus/src/block/apply.rs)'s
settlement phase, the reward for every accepted proof (`storage_proof_reward`
per proof, plus any PPB endowment-yield bonus) was summed into
`storage_reward_total` and folded into `expected_reward = subsidy +
producer_fee + storage_reward_total`, which was the amount the **producer's
coinbase** had to pay. Operators submitted proofs through the runtime proof pool /
`submit_storage_proof` RPC; the current block producer drained that pool,
included the proofs, and collected the reward.

Consequences (before the fix):

- A storage operator that was **not** the current block producer received
  **nothing** on-chain for holding and proving data. Its only realized income
  required also winning VRF leader election and producing the block that
  carried its own proof.
- Because the submitted proof already contained the chunk bytes, a producer could
  bank a proof relayed by an operator and keep the reward, contributing
  nothing to storage itself.
- This concentrated all permanence income in the validator/producer set,
  which was in tension with "maximally decentralized" storage.

**Fix shipped:** operator stealth payout keys in `StorageProof`, extended proof
codec + `storage_proof_leaf_hash` golden vectors, and per-proof coinbase outputs
drained from the treasury/backstop on the same accounting footing as before —
instead of crediting only the producer coinbase. Residual concern: proof
inclusion is still a latency race to producers ([§ 6](#6-spora-proof-winning-is-a-pure-first-to-publish-latency-race)).
Tracked historically in [`ECONOMICS.md § 10`](./ECONOMICS.md#10-open-economic-questions) and
[`ROADMAP.md`](./ROADMAP.md).

### 18. ~~No consensus-enforced minimum or uniform ring size~~ (resolved)

> **Status: closed** (uniform ring-16 shipped). [`ConsensusParams`](../mfn-consensus/src/block/state.rs)
> carries `min_ring_size` / `uniform_ring_size` (production default **16 / 16**);
> [`verify_transaction`](../mfn-consensus/src/transaction/verify.rs) rejects undersized or
> non-uniform rings at mempool ingress and in [`apply_block`](../mfn-consensus/src/block/apply.rs).
> Reference wallets (`mfn-wallet`, CLI) default to 16 and refuse lower values.

**Historical note.** Before this fix, ring size was wallet policy only — a ring of size 1
(no decoys) was structurally valid, and heterogeneous ring sizes leaked metadata.
Monero mandates uniform rings of 16 for exactly this reason; Permawrite now matches that
at consensus. Residual Tier-3 work (OoM over full UTXO set) remains in [`PRIVACY.md`](./PRIVACY.md).

### 19. Subsidy tail split approved but not in consensus yet

> **Status: open (docs-only approval)** — [`FEES.md` § 5.4](./FEES.md#54-subsidy-tail-split--approved-for-next-parameter-fork-10--treasury) and [`ECONOMICS.md` § 12](./ECONOMICS.md#12-permanence-durability-vs-arweave--is-this-model-more-likely-to-break) approve routing **10% of block subsidy** (`subsidy_to_treasury_bps = 1000`) into the storage treasury on every block with a producer coinbase. **No such field exists** in `ChainState` / `ConsensusParams` or [`apply_block`](../mfn-consensus/src/block/apply.rs) settlement today — only the 90/10 **fee** split and emission backstop affect treasury inflow.

Without this parameter, operator revenue in low-fee regimes depends almost entirely on privacy tx volume (§ 2) and emergency backstop minting. The tail subsidy still flows entirely to producers until a parameter fork ships the F6 phase-2 consensus change.

### 20. Chain-native casino as treasury funding (assessed — rejected)

> **Status: out of scope (not an open protocol gap)** — full analysis in [`CASINO_RANDOMNESS_FEASIBILITY.md`](./CASINO_RANDOMNESS_FEASIBILITY.md). Verdict: **do not prioritize**; not a roadmap item.

Delayed-entropy games are technically possible (SPoRA already uses the same pattern), but a house-bankrolled on-chain casino would:

- Increase validator/producer grinding incentives against treasury variance targets.
- Expand regulatory and brand risk for a privacy-permanence network without improving ring policy or endowment enforcement.
- Compete with the stated thesis that **privacy transaction fees** (not speculative gaming) fund permanence.

Treasury top-ups belong in fee economics (§§ 2, 19), operator bonding (§ 1), and latency-fair SPoRA (§ 6) — not chain-native gambling.

## Areas That Appear Relatively Sound (Under Stated Assumptions)

- The core privacy primitives (Pedersen + CLSAG + Bulletproofs + stealth) are well-understood and directly ported from battle-tested designs, with consensus-enforced uniform ring-16 (§ 18) and canonical reference-tx conformance (F5-P9).
- The header-binds-body commitment family (all the `*_root` fields) plus BLS finality gives strong structural guarantees once a block is finalized; body-root fraud proofs (§ 11) give light clients a first rejection path without the UTXO set.
- Operator-direct SPoRA coinbase outputs (§ 17) align permanence payouts with proving operators rather than block producers only.
- Public devnet genesis enables endowment opening / range-proof gates (`require_endowment_opening`, `require_endowment_range_proof` in [`public_devnet_v1.json`](../mfn-node/testdata/public_devnet_v1.json); see [`B1_ENDOWMENT_RANGE_PROOF.md`](./B1_ENDOWMENT_RANGE_PROOF.md)).
- The two-mode endowment math (r > 0 vs r = 0 + deflation) is cleanly implemented; emission backstop guarantees operator settlement when the treasury is short (§ 2).
- Validator bonding + slashing + treasury loop is a closed, auditable economic mechanism (B5 partial on public devnet).
- Genesis ceremony tooling: BLS PoP verification at spec load (§ 13), optional `header_version: 2` for new chains (§ 12).

These do not mean the overall system is risk-free; they mean the documented problems above are the more material open issues rather than basic cryptographic soundness of the building blocks.

---

**This document should be updated whenever a material new weakness is discovered or a planned mitigation ships.** It is not marketing copy; it is part of the protocol's self-assessment.

## See also

- [`DECENTRALIZATION.md`](./DECENTRALIZATION.md) — hardware role split, centralization pressures, latency-fair SPoRA research
- [`STORAGE_ACCESSIBILITY.md`](./STORAGE_ACCESSIBILITY.md) — consumer storage feasibility
- [`ECONOMICS.md`](./ECONOMICS.md) — treasury, fees, operator payouts
- [`FEES.md`](./FEES.md) — 90/10 fee split, approved subsidy tail (§ 5.4)
- [`FRAUD_PROOFS.md`](./FRAUD_PROOFS.md) — interactive fraud proof phase 0 (§ 11)
- [`CASINO_RANDOMNESS_FEASIBILITY.md`](./CASINO_RANDOMNESS_FEASIBILITY.md) — assessed extension, rejected (§ 20)
- [`SECURITY_CONSIDERATIONS.md`](./SECURITY_CONSIDERATIONS.md) — protocol trust model companion
- [`scripts/public-devnet-v1/OPERATORS.md`](../scripts/public-devnet-v1/OPERATORS.md) — production runbook
