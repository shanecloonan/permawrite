# Consensus Subsystem

> **Audience.** Protocol engineers and PoS designers. The non-formula version is in [`OVERVIEW.md`](./OVERVIEW.md); the high-level architecture lens is in [`ARCHITECTURE.md`](./ARCHITECTURE.md).

---

## What "consensus" decides

Each block on Permawrite has a unique decider: a single producer, drawn from the validator set, who proposes the block, and a committee of validators who finalize it. Consensus answers:

1. **Who's allowed to propose this block?** (stake-weighted VRF sortition)
2. **Is this block agreed upon?** (BLS-aggregated committee finality)
3. **Was anyone caught cheating?** (slashing — equivocation + liveness)

This is a **deterministic, single-finalized-chain** model. No forks under honest majority. No probabilistic finality. A block, once finalized, is irreversible.

---

## Threat model

We assume:

- The validator set is partially adversarial — up to but less than the slashing threshold.
- Honest validators can come online and go offline transiently (network blips, restarts).
- Adversarial validators may try to double-sign (equivocate), withhold votes (censor), or stall.
- All validators have access to a synchronized clock to within a slot duration (~12s).
- Long-range attacks (rewriting history from far in the past) are out of scope at v0.1 — addressed by future weak-subjectivity checkpoints.

We do **not** assume:

- Bounded message delay (validators can be temporarily partitioned).
- Validators are honest by default (everything must be cryptographically enforced).

---

## 1. Slot model

**Intuition.** Time is divided into fixed slots (12 seconds each). Each slot may produce 0, 1, or rarely more than 1 blocks. There's no race to mine; eligibility is determined by cryptographic sortition.

### Mechanics

- **Slot duration:** ~12 seconds (target — implementation-level, not consensus-critical).
- **Slot number:** monotonically increasing `u32`. Slot 0 = genesis.
- **One block per slot:** if multiple producers are eligible (rare), a deterministic tie-break picks the winner.

### Slot seed

For each slot `S` with previous block id `prev_id`:

```text
slot_seed = dhash(CONSENSUS_SLOT, [prev_id, S.to_be_bytes()])
```

[`slot_seed`](../mfn-consensus/src/consensus.rs). This seed is the input to every validator's VRF for slot `S`.

---

## 2. Leader election (stake-weighted VRF sortition)

**Intuition.** Each validator computes a private cryptographic random number from the slot seed using their secret key. If their number falls below a threshold proportional to their stake share, they're eligible to propose. The math guarantees: more stake → more eligibility, but the *specific* slot a validator is eligible for is unpredictable to outside observers.

### Eligibility threshold

For a validator with stake `s` out of total `S`:

```text
threshold(s, S, k) = (s / S) × k × u64::MAX
```

where `k = expected_proposers_per_slot` (default `1.5`).

The fractional `1.5` means the protocol expects ~1.5 eligible producers per slot on average, providing **liveness slack** — if the slot's primary eligible producer is offline, secondaries can take over.

In code:

```rust
pub fn eligibility_threshold(stake: u64, total_stake: u64, expected_per_slot: f64) -> u64 {
    let ratio = (stake as f64 / total_stake as f64) * expected_per_slot;
    (ratio.clamp(0.0, 1.0) * (u64::MAX as f64)) as u64
}
```

> **Determinism note.** The use of `f64` here is for documentation; the production verification path uses integer arithmetic to avoid cross-platform float drift. See [`is_eligible`](../mfn-consensus/src/consensus.rs).

### VRF (Verifiable Random Function)

Each validator computes:

```text
(proof, output) = VRF_PROVE(secret_vrf_key, slot_seed)
```

Module: [`mfn_crypto::vrf`](../mfn-crypto/src/vrf.rs). This is an **ECVRF over ed25519** implementation following the RFC 9381 IETF-Algorand variant.

Properties:

- **Verifiable.** Anyone with the validator's `vrf_public_key` can verify `(proof, output)` came from the right secret and the right input.
- **Pseudo-random.** Without the secret, the output is computationally indistinguishable from random.
- **Unique.** Each `(secret, input)` pair produces exactly one valid `(proof, output)`.

### Eligibility check

```rust
pub fn is_eligible(
    vrf_output: &[u8; 32],
    stake: u64,
    total_stake: u64,
    expected_per_slot: f64,
) -> bool {
    let threshold = eligibility_threshold(stake, total_stake, expected_per_slot);
    let output_u64 = vrf_output_as_u64(vrf_output);
    output_u64 < threshold
}
```

### Tie-breaking

If multiple validators are eligible for the same slot, the protocol picks the one with the **lowest VRF output** ([`pick_winner`](../mfn-consensus/src/consensus.rs)). This is deterministic and unambiguous.

### Why VRF sortition (and not round-robin)

- **Round-robin** is predictable. An attacker knows exactly which validator to bribe or DDoS for slot S.
- **Public PoW** wastes energy and concentrates power in the most-hashing pools.
- **VRF sortition** is unpredictable to outsiders but verifiable after the fact. The adversary doesn't know who's the producer until they publish.

This is the same model Algorand introduced and Ouroboros refined.

---

## 3. Committee finality (BLS12-381)

**Intuition.** Once a producer publishes a block, every validator BLS-signs it. The producer aggregates all signatures into one 96-byte signature. The aggregate, combined with a bitmap showing who signed, *is* the block's finality proof. Verifying it is a single pairing check.

### BLS signatures

The crate [`mfn-bls`](../mfn-bls/src/sig.rs) implements the IETF BLS-12-381 signature scheme:

- Secret key `sk` ∈ 𝔽_r (BLS12-381 group order)
- Public key `pk = sk · G₁` ∈ G₁ (48 bytes compressed)
- Signature `σ = sk · H(m)` ∈ G₂ (96 bytes compressed)
- Hash-to-curve via IETF SSWU with DST `"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_"`
- Verify: pairing equation `e(G₁, σ) == e(pk, H(m))`

Matches the Ethereum 2.0 / Filecoin BLS variant. Light clients on those chains can verify Permawrite finality using existing libraries.

### Vote aggregation

Each validator BLS-signs `header_signing_hash(header)` to produce a `CommitteeVote { validator_index, signature }`. The producer collects votes and aggregates:

```text
agg_sig = Σ σ_i              (point addition in G₂)
agg_pk  = Σ pk_i              (for validators who signed, point addition in G₁)
bitmap  = bit i set iff validator i signed
```

Verification:

```text
e(G₁, agg_sig) == e(agg_pk, H(header_signing_hash))
```

One pairing equality regardless of how many signers. This is the magic of BLS — the verifier cost is constant in the committee size.

### Quorum

Sum of stake of signers (per the bitmap) must reach:

```text
stake_signed >= total_stake × quorum_stake_bps / 10_000
```

Default `quorum_stake_bps = 6667` (= 2/3 + 1bp). Standard PoS finality threshold.

### `FinalityProof` wire format

The producer packs the aggregate + bitmap into a [`FinalityProof`](../mfn-consensus/src/consensus.rs):

```rust
pub struct FinalityProof {
    pub committee_aggregate: CommitteeAggregate {
        pub agg_sig: BlsSignature,
        pub bitmap:  Vec<u8>,
    },
    pub producer: ProducerProof {
        pub vrf_proof: VrfProof,
        pub schnorr_sig: SchnorrSignature,
    },
}
```

The `producer_proof` field of the block header carries the MFBN-encoded `FinalityProof`. Verification (see [`verify_finality_proof`](../mfn-consensus/src/consensus.rs)) checks:

1. The producer's VRF + Schnorr sig — verifies the producer was eligible for the slot.
2. The committee aggregate — pairing equation passes.
3. Stake threshold — signer stake ≥ quorum.

---

## 4. Slashing — equivocation

**Intuition.** If a validator BLS-signs two different headers for the same slot at the same height, they've committed an unrecoverable cryptographic sin. Anyone who sees both signatures can publish them as evidence; the chain verifies and **zeros the offender's stake** outright.

### Evidence format

[`SlashEvidence`](../mfn-consensus/src/slashing.rs):

```rust
pub struct SlashEvidence {
    pub header_a: BlockHeader,
    pub header_b: BlockHeader,
    pub sig_a:    BlsSignature,
    pub sig_b:    BlsSignature,
    pub validator_index: u32,
}
```

### Canonicalization

The two headers are sorted so the evidence is deterministic regardless of which observer found them first. [`canonicalize`](../mfn-consensus/src/slashing.rs) orders by `block_id(header)` lexicographically.

### Verification

[`verify_evidence`](../mfn-consensus/src/slashing.rs) returns `EvidenceCheck` ∈ {`Valid`, `InvalidSignature`, `SameHeader`, `DifferentSlotOrHeight`, …}.

- Both BLS sigs must verify under the validator's `bls_public_key`.
- The two headers must share `(height, slot)` but have distinct `block_id`s.
- If both checks pass: evidence is valid.

### Slashing action

If `apply_block` sees a valid `SlashEvidence` in `block.slashings`:

```rust
next.validators[validator_index].stake = 0;
```

Permanent removal. The validator's `ValidatorStats` are also no longer updated (zero-stake validators are excluded from liveness tracking).

Equivocation slashing is **harsh and immediate** because it's the one provably-malicious action a validator can take. There's no benefit-of-the-doubt: signing two conflicting headers is impossible by accident.

---

## 5. Slashing — liveness

**Intuition.** A validator who consistently misses finality votes is at best offline (degrading throughput), at worst censoring (refusing to vote on blocks they don't like). Either way, the chain needs to discourage chronic absenteeism. Solution: multiplicatively reduce stake after N consecutive missed votes.

### Why multiplicative slashing

Two options:

1. **Additive.** "Lose X% of your original stake per offense." After enough offenses, stake hits zero.
2. **Multiplicative.** "Lose X% of your *current* stake per offense." Stake approaches zero asymptotically but never quite reaches it.

We chose multiplicative because:

- **Smooth incentive curve.** A validator near zero stake has very little to lose from one more offense. Multiplicative slashing keeps the "loss per offense" proportional to skin in the game — always meaningful.
- **No abrupt cliff.** Validators don't suddenly drop out of the set; they slowly drift to negligible-stake (and can be replaced via future validator rotation).
- **Robust to parameter choice.** Whether `liveness_slash_bps` is 50 or 500, the asymptotic behavior is exponentially decaying stake, which is well-defined and bounded.

### Tracking

Per-validator stats in [`ValidatorStats`](../mfn-consensus/src/block.rs):

```rust
pub struct ValidatorStats {
    pub consecutive_missed: u32,
    pub total_signed:       u64,
    pub total_missed:       u64,
    pub liveness_slashes:   u32,
}
```

`ChainState` carries `validator_stats: Vec<ValidatorStats>` aligned with `validators` by index.

### Update rule (in `apply_block` after finality verification)

```python
for i, v in enumerate(next.validators):
    if v.stake == 0: continue  # already-slashed validator, skip

    bit_set = (finality_bitmap[i >> 3] >> (i & 7)) & 1
    stats = next.validator_stats[i]

    if bit_set:
        stats.consecutive_missed = 0
        stats.total_signed += 1
    else:
        stats.consecutive_missed += 1
        stats.total_missed += 1

        if stats.consecutive_missed >= params.liveness_max_consecutive_missed:
            new_stake = v.stake * (10_000 - params.liveness_slash_bps) / 10_000
            v.stake = new_stake
            stats.liveness_slashes += 1
            stats.consecutive_missed = 0   # counter resets after slash
```

### Default calibration

- `liveness_max_consecutive_missed = 32` (≈ 6.4 minutes at 12-second slots).
- `liveness_slash_bps = 100` (1% per offense).
- Compounding: 100 successive trip-ups → stake ≈ `(0.99)^100 ≈ 0.366`, ~63% reduction.

The threshold of 32 is long enough to absorb a transient network blip (a couple of slots of network unavailability won't trigger), short enough to make chronic absenteeism expensive.

### Test coverage

Block-level unit tests in `mfn-consensus/src/block.rs`:

- `liveness_validator_signing_resets_counter`
- `liveness_validator_missing_increments_counter`
- `liveness_slashing_triggers_at_threshold`
- `liveness_slashes_compound_multiplicatively`
- `liveness_short_transient_outage_forgiven`
- `liveness_skipped_for_zero_stake_validators`
- `liveness_handles_short_bitmap`
- `liveness_slash_caps_at_stake_floor`

Integration test in `mfn-consensus/tests/integration.rs`:

- `liveness_slashing_chronic_absentee_gets_slashed` — full 3-validator chain where one validator goes dark and ends up multiplicatively slashed.

---

## 6. Validator set

**Intuition.** As of M1, the validator set rotates **on-chain**. New validators register via burn-on-bond `BondOp::Register`; existing validators exit via BLS-signed `BondOp::Unbond` with a delayed settlement that keeps them slashable across the delay. Per-epoch churn caps prevent the set from thrashing under griefing.

### `Validator` shape

```rust
pub struct Validator {
    pub index:               u32,            // monotonic, never reused
    pub vrf_public_key:      EdwardsPoint,
    pub bls_public_key:      BlsPublicKey,
    pub schnorr_public_key:  EdwardsPoint,
    pub stake:               u64,
    pub payout:              Option<ValidatorPayout>,
}

pub struct ValidatorSecrets {
    pub vrf_secret:     Scalar,
    pub bls_secret:     BlsSecretKey,
    pub schnorr_secret: Scalar,
}
```

Three keypairs per validator:

- **VRF keypair** — for leader election.
- **BLS keypair** — for finality voting **and** for authorizing the validator's own `BondOp::Unbond`.
- **Schnorr keypair** — for producer claim (signing the VRF proof in their `ProducerProof`).

Why three? Different roles, different schemes. VRF and BLS use different curves; Schnorr lets us bind the VRF proof to the producer's stable identity. Keeping them separate keeps the security reductions clean.

### `Validator` index = identity

The validator's identity in the chain is just their `index`. The finality bitmap is keyed by this index. `validator_stats[i]` is the stats for `validators[i]`. **Indices are never reused** — `ChainState::next_validator_index` is a monotonic counter — so historical finality bitmaps and slash evidence reference stable slots even after a validator unbonds or is zeroed out.

### Rotation (M1 — live)

`BlockHeader` carries `bond_root: [u8; 32]` (Merkle root over the block's `bond_ops`, zero sentinel for empty), and `Block` carries `bond_ops: Vec<BondOp>`.

```rust
pub enum BondOp {
    Register {
        stake:   u64,
        vrf_pk:  EdwardsPoint,
        bls_pk:  BlsPublicKey,
        payout:  Option<ValidatorPayout>,
        sig:     BlsSignature,           // domain-separated under MFBN-1/register-op-sig
    },
    Unbond {
        validator_index: u32,
        sig:             BlsSignature,   // domain-separated under MFBN-1/unbond-op-sig
    },
}
```

Both arms are BLS-authenticated by the operator's own voting key — the same `bls_sk` that signs finality. `Register` commits its signature over `(stake, vrf_pk, bls_pk, payout)`, binding the rest of the op to a single operator's keys (defeating mempool replay against a stranger's keys). `Unbond` commits over `validator_index` and is independently replay-protected by `pending_unbonds` rejecting duplicate enqueues.

`apply_block` validates and applies `bond_ops` atomically. On success:

- `BondOp::Register` verifies the operator's signature under `bls_pk`, then appends a new `Validator` (with a fresh `ValidatorStats` row) and **burns its declared stake into `treasury`** — the same sink that funds permanence.
- `BondOp::Unbond` is BLS-verified against the validator's own `bls_public_key` and enqueued into `pending_unbonds: BTreeMap<u32, PendingUnbond>` with `unlock_height = height + bonding_params.unbond_delay_blocks`.

Per-epoch entry / exit churn caps (`max_entry_churn_per_epoch`, `max_exit_churn_per_epoch`; default 4 each) bound how fast the set can change.

### Settlement and slashing during the delay

A separate settlement phase later in `apply_block` finalizes any pending unbond whose `unlock_height ≤ height`: the validator's stake is zeroed and they become a non-signing zombie. Because settlement runs **after** equivocation slashing and liveness updates, a validator who unbonds and then equivocates inside the delay is still fully forfeited — and the forfeited stake credits the treasury. There's no "rage-quit" exit.

### Slashed / settled stake disposition

Both equivocation slashing (full stake forfeit) and liveness slashing (multiplicative forfeit) **credit the lost amount to `treasury`** using saturating `u128` arithmetic. Settled unbonds also leave their originally bonded MFN in the treasury (M1 deliberately defers any operator payout). The result: rotation in M1 is a **closed economic loop** — bonds in, slashes in, storage rewards out — see [`ECONOMICS.md § Validator bond economics`](./ECONOMICS.md#9-validator-bond-economics-m1-closed-loop) for the full picture.

For the full design note + test matrix, see [`docs/M1_VALIDATOR_ROTATION.md`](./M1_VALIDATOR_ROTATION.md).

### Validator-set commitment in the header (M2.0)

Every block header now also commits to the validator set the block was produced against:

```rust
struct BlockHeader {
    // ...
    bond_root:          [u8; 32],
    slashing_root:      [u8; 32],   // ← M2.0.1 — merkle over block.slashings
    validator_root:     [u8; 32],   // ← M2.0
    storage_proof_root: [u8; 32],   // ← M2.0.2 — merkle over block.storage_proofs
    producer_proof:     Vec<u8>,
    utxo_root:          [u8; 32],
}
```

`validator_root` is the binary Merkle root over the **pre-block** `state.validators` in canonical chain-stored (index) order, with each leaf

```text
dhash(VALIDATOR_LEAF,
      index(u32, BE) ‖ stake(u64, BE)
   ‖  vrf_pk(32) ‖ bls_pk(48)
   ‖  payout_flag(u8) ‖ [view_pub(32) ‖ spend_pub(32)]?)
```

Why "pre-block" and not "post-block":

- Phase 0 of `apply_block` verifies the producer-proof + finality bitmap **against `state.validators`** — the set in force *before* this block. Committing that exact set under the header means a light client holding only the header can verify producer eligibility and committee quorum without holding the live validator list.
- Any rotation / slashing / unbond settlement applied *by* this block moves the **next** header's `validator_root`. Each header is internally consistent: `validator_root` is the set its `producer_proof` was checked against.

What this **doesn't** commit:

- `ValidatorStats` (liveness counters) — they churn every block; leaving them out keeps the root stable across blocks that didn't change the set. Light clients don't need them.

Reference root commitments under the header are now `tx_root`, `bond_root`, `slashing_root`, `validator_root`, `storage_proof_root`, `storage_root`, `utxo_root` — covering txs, validator-set deltas, equivocation evidence, the live validator set, this block's storage proofs, newly-anchored storage commitments, and the post-block UTXO accumulator. **The header binds the entire block body** (the producer proof itself is the only structural exception, since it's *part of* the header). Domain tags for the new leaves: `MFBN-1/validator-leaf` (M2.0), `MFBN-1/slashing-leaf` (M2.0.1), `MFBN-1/storage-proof-leaf` (M2.0.2).

### Slashing-evidence commitment (M2.0.1)

Each leaf is the domain-separated hash of one equivocation piece in its canonicalized form — `canonicalize()` orders the conflicting `(hash_a, sig_a)` / `(hash_b, sig_b)` pair lexicographically by hash before encoding, so swapping the pair produces the same leaf. The Merkle root over all leaves (in the producer's emit order) is rooted under the header. Two consequences:

- A light client can verify the slashings list independently of the rest of the block body — just request `block.slashings`, recompute leaves, recompute the root, compare against `header.slashing_root`.
- An adversarial producer cannot forge "phantom" slashings: any leaf added to or removed from the list moves the root, and any pair-order tampering is canonicalized away before hashing.

### Storage-proof commitment (M2.0.2)

Each leaf is the domain-separated hash of one storage proof in its canonical SPoRA wire form — `dhash(STORAGE_PROOF_LEAF, encode_storage_proof(p))`, where `encode_storage_proof` is the exact byte string the SPoRA verifier already consumes (no second "for-Merkle-only" encoding). The Merkle root over all leaves (in the producer's emit order) is rooted under the header. Three consequences:

- A light client can verify the block's SPoRA yield-event surface independently of the rest of the body — just request `block.storage_proofs`, recompute leaves, recompute the root, compare against `header.storage_proof_root`.
- An adversarial producer cannot smuggle phantom proofs past the header: any added or removed proof moves the root. Per-commitment duplicates are already rejected separately by `apply_block`, so emit order is the only ordering choice — and that order is what actually gets paid out (first proof wins each slot's yield).
- The producer's BLS aggregate signs over `header_signing_hash`, which now includes `storage_proof_root`, so any post-seal flip necessarily invalidates the aggregate.

For the full design note + test matrix, see [`docs/M2_STORAGE_PROOF_ROOT.md`](./M2_STORAGE_PROOF_ROOT.md).

### Light-header verification (M2.0.5)

With every block-body element now header-bound (M2.0 / M2.0.1 / M2.0.2), the natural payoff is a *light* verifier: a function that given only a `BlockHeader` and a trusted pre-block validator set, returns whether a real quorum of that set signed the header. That's [`verify_header`](../mfn-consensus/src/header_verify.rs) — the first piece of `mfn-light`.

```rust
pub fn verify_header(
    header: &BlockHeader,
    trusted_validators: &[Validator],
    params: &ConsensusParams,
) -> Result<HeaderCheck, HeaderVerifyError>;
```

Checks performed (in order):

1. `trusted_validators` non-empty → otherwise `EmptyTrustedSet`.
2. `validator_set_root(trusted_validators) == header.validator_root` → the **trust anchor**: caller asserts which set the producer claimed to commit to. Mismatch → `ValidatorRootMismatch`.
3. `header.producer_proof` non-empty → otherwise `GenesisHeader` (genesis is the *anchor*, not light-verifiable).
4. `header.producer_proof` decodes as a `FinalityProof` → otherwise `ProducerProofDecode(_)`.
5. `verify_finality_proof(…)` returns `Ok` → covers producer VRF + ed25519 + slot eligibility, BLS aggregate over the header signing hash, signing-stake-bitmap consistency, and quorum threshold. Otherwise `FinalityRejected(_)`.

Properties:

- **Pure function.** No IO, no async, no state mutation. Same inputs → byte-for-byte same outputs.
- **Same checks `apply_block` runs.** Exercised by the integration test `verify_header_agrees_with_apply_block_across_three_blocks` (in `mfn-node`): for every block of a real 3-block chain, `verify_header` accepts iff `apply_block` does.
- **One hop.** This verifies a single header against a single trusted set. Walking the chain — and tracking how the trusted validator set evolves through `BondOp`s, slashings, and unbond settlements — is the job of the [`mfn-light`](../mfn-light/README.md) crate. The M2.0.6 slice of `mfn-light` provides the chain-following skeleton (header linkage + `verify_header` + tip advance); **M2.0.7 adds body-root verification** (see below); **M2.0.8 adds validator-set evolution across rotations** via the shared `validator_evolution` module (see below).

For the full design note + test matrix, see [`docs/M2_LIGHT_HEADER_VERIFY.md`](./M2_LIGHT_HEADER_VERIFY.md) (M2.0.5 primitive) and [`docs/M2_LIGHT_CHAIN.md`](./M2_LIGHT_CHAIN.md) (M2.0.6 chain follower).

### Light-body verification (M2.0.7)

`verify_header` proves the *commitment values* in a header are genuine. M2.0.7 adds the second light-client primitive: a function that proves a delivered **body** matches those commitments. Combined, the two give a light client cryptographic confidence that the `(header, body)` pair it accepted is byte-for-byte what some honest 2/3-stake quorum endorsed — no node trust required.

```rust
pub fn verify_block_body(block: &Block) -> Result<(), BodyVerifyError>;
```

Re-derives the four header-bound body roots that are pure functions of the block body and matches each against `block.header`:

| # | Check | Failure → |
|---|---|---|
| 1 | `header.tx_root == tx_merkle_root(&block.txs)` | `TxRootMismatch { expected, got }` |
| 2 | `header.bond_root == bond_merkle_root(&block.bond_ops)` | `BondRootMismatch { expected, got }` |
| 3 | `header.slashing_root == slashing_merkle_root(&block.slashings)` | `SlashingRootMismatch { expected, got }` |
| 4 | `header.storage_proof_root == storage_proof_merkle_root(&block.storage_proofs)` | `StorageProofRootMismatch { expected, got }` |

Each variant carries the value the *header* claimed (`expected`) and the value the verifier recomputed from the delivered body (`got`) — useful for peer scoring and log diagnostics.

`storage_root` and `utxo_root` are *not* covered: both are state-dependent (the former requires cross-block dedup of storage commitments; the latter the cumulative UTXO accumulator). A forged block can't smuggle a fake value for either past `verify_header` — the BLS aggregate signs `header_signing_hash` which includes both — so a stateless verifier loses nothing material by skipping their re-derivation. `validator_root` is the trust anchor of `verify_header` itself.

In `mfn-light`, the full-block analogue of `apply_header` is `apply_block(&Block)` — five steps in order: height monotonicity → prev_hash linkage → `verify_header` → `verify_block_body` → tip advance. State is byte-for-byte untouched on any failure. Header verification runs **before** body verification so the diagnostic distinction is clean: `HeaderVerify` = forged header; `BodyMismatch` = right header, wrong body.

For the full design note + test matrix (8 unit tests in `mfn-consensus`, 7 unit + 5 integration in `mfn-light`), see [`docs/M2_LIGHT_BODY_VERIFY.md`](./M2_LIGHT_BODY_VERIFY.md).

### Light-client validator-set evolution (M2.0.8)

M2.0.5 + M2.0.7 give a light client cryptographic confidence in a single `(header, body)` pair. **M2.0.8** lets the light client follow the chain across arbitrary **rotations** — `BondOp::Register` adds, equivocation slashings zero, unbond settlements zero, liveness slashings reduce — by mirroring `apply_block`'s validator-set transition byte-for-byte via a **shared pure-helper module**: [`mfn-consensus::validator_evolution`](../mfn-consensus/src/validator_evolution.rs).

Architecturally:

```text
                            mfn_consensus::validator_evolution
                                       │
        ┌──────────────────────────────┴──────────────────────────────┐
        │                                                              │
   mfn_consensus::block::apply_block             mfn_light::chain::apply_block
   (full-node STF)                               (light-client chain follower)
```

The four shared phase functions:

| Phase | Function | Mutates |
|---|---|---|
| A | `apply_equivocation_slashings(&mut [Validator], &[SlashEvidence])` | `validators[*].stake` ← 0 for verified evidence |
| B | `apply_liveness_evolution(&mut [Validator], &mut Vec<ValidatorStats>, &[u8] bitmap, &ConsensusParams)` | `validator_stats` + multiplicative stake reduction |
| C | `apply_bond_ops_evolution(height, &mut counters, &mut Vec<Validator>, &mut Vec<ValidatorStats>, &mut BTreeMap, &BondingParams, &[BondOp])` | extends validators / extends stats / enqueues pending unbonds / advances epoch counters |
| D | `apply_unbond_settlements(height, &mut counters, &BondingParams, &mut [Validator], &mut BTreeMap)` | zeroes settled validators' stake / drains pending unbonds / consumes exit churn |

`apply_block` (full node) and `LightChain::apply_block` (light client) **call the same four functions**. There is no hand-written mirror of the evolution logic in `mfn-light` — drift is structurally impossible.

The cross-block audit invariant: after `apply_block(n)` succeeds, the light client's evolved `trusted_validators` MUST equal the full node's `state.validators` after the same block — otherwise the next `apply_block(n+1)` fails with `HeaderVerify { ValidatorRootMismatch }`. Block `n+1`'s header commits to the *post-block-n* validator set (M2.0), and `verify_header` checks it against the trusted set. **The chain's own headers are the audit of the light client's evolution.**

In `mfn-light::LightChain`, the four phases run on **staging copies** of `trusted_validators`, `validator_stats`, `pending_unbonds`, and `BondEpochCounters`. If any phase rejects (e.g. an invalid bond op surfaces as `LightChainError::EvolutionFailed`), nothing is committed — the chain's tip and shadow state stay byte-for-byte equal to their pre-call values. Atomic commit on success only.

For the full design note + test matrix (8 unit tests in `mfn-consensus::validator_evolution`, 8 unit + 2 integration in `mfn-light`), see [`docs/M2_LIGHT_VALIDATOR_EVOLUTION.md`](./M2_LIGHT_VALIDATOR_EVOLUTION.md).

### Light-client checkpoint serialization (M2.0.9)

M2.0.8 made the light client survive **rotations**; M2.0.9 makes it survive **restarts**.

A *checkpoint* is a self-contained binary snapshot of a `LightChain`: tip identity, frozen consensus / bonding params, the current trusted validator set, the per-validator liveness stats, the pending-unbond queue, and the four bond-epoch counters. The codec lives in [`mfn-light::checkpoint`](../mfn-light/src/checkpoint.rs); the `LightChain` exposes thin `encode_checkpoint` / `decode_checkpoint` methods on top.

Properties:

- **Deterministic.** Two callers serializing the same `LightChain` state produce byte-identical output (including the trailing integrity tag). Foundation for content-addressable snapshot storage.
- **Self-contained.** The payload carries `genesis_id`, `params`, and `bonding_params` so restore needs no external config. Callers who want to pin a checkpoint to a specific genesis can compare `decoded.genesis_id() == build_genesis(cfg).id()` post-decode.
- **Domain-separated integrity.** The trailing 32 bytes are `dhash(LIGHT_CHECKPOINT, payload)` under the dedicated `MFBN-1/light-checkpoint` domain. A tampered checkpoint can't be made to collide with any other protocol hash.
- **Versioned.** A 4-byte magic (`MFLC`) + a 4-byte version (`1`) at the front means older clients fail loudly on a newer format, and newer clients can branch on the version word to keep accepting older checkpoints.

Cross-field invariants enforced on decode (defence-in-depth against malicious peers / corrupted files):

| Invariant | Error variant |
|---|---|
| `validator_stats.len() == validators.len()` | `StatsLengthMismatch` |
| `Validator::index` uniqueness | `DuplicateValidatorIndex` |
| `pending_unbonds` strictly ascending by `validator_index` | `PendingUnbondsNotSorted` |
| `bond_counters.next_validator_index > max(validator.index)` | `NextIndexBelowAssigned` |
| `dhash(LIGHT_CHECKPOINT, payload)` matches the trailing tag | `IntegrityCheckFailed` |
| Magic prefix and version word are recognised | `BadMagic` / `UnsupportedVersion` |
| All-bytes-consumed contract | `TrailingBytes` |
| Edwards-point and BLS-G1 decompression succeed | `InvalidVrfPublicKey` / `InvalidBlsPublicKey` / `InvalidPayoutViewPub` / `InvalidPayoutSpendPub` |

For the full wire layout, design rationale, and 28-test matrix (7 header-codec unit + 13 checkpoint codec unit + 5 LightChain-level unit + 3 integration), see [`docs/M2_LIGHT_CHECKPOINT.md`](./M2_LIGHT_CHECKPOINT.md).

### Tests added for M2.0

- `validator_set_root_empty_is_zero_sentinel` — empty set folds to the all-zero sentinel.
- `validator_set_root_changes_when_stake_changes` — slashing / rotation moves the root.
- `validator_set_root_changes_with_order` — the set is committed in canonical (chain-stored) order, not a sorted multiset.
- `validator_set_root_changes_when_validator_added` — registering a validator moves the root.
- `validator_leaf_bytes_depend_on_every_field` — index, stake, vrf_pk, bls_pk, payout flag all materially affect the leaf.
- `validator_leaf_hash_is_domain_separated` — `VALIDATOR_LEAF` is not confusable with any other dhash domain.
- `validator_root_mismatch_is_rejected` — `apply_block` rejects a header whose `validator_root` doesn't match the pre-block set.
- `build_unsealed_header_commits_pre_block_validator_set` — the producer's own header builder commits the pre-block root.
- `validator_root_commits_pre_block_set_each_block` (integration) — multi-block invariant.
- `validator_root_moves_on_equivocation_slash` (integration) — slashing zeroes stake → next header's root differs.
- `validator_root_moves_on_unbond_settlement` (integration) — unbond settlement zeroes stake → next header's root differs.
- `tampered_validator_root_in_signed_block_is_rejected` (integration) — flipping `validator_root` post-signing is rejected (also invalidates the BLS aggregate, which is by design — `header_signing_hash` now binds `validator_root`).

---

## 7. Genesis

Genesis block is unique:

- `height = 0`.
- `prev_hash = [0u8; 32]`.
- `tx_root = [0u8; 32]` (no txs at genesis).
- `producer_proof = []` (no finality at genesis — bootstrapped).
- `storage_root` is the Merkle root over `cfg.initial_storage` (any storage pre-anchored at chain start).
- `utxo_root` is the accumulator root after `cfg.initial_outputs` are appended.

Genesis is **trusted setup**. It's the one point in chain history where the rules don't apply — the chain hasn't started yet. [`build_genesis`](../mfn-consensus/src/block.rs) constructs it; [`apply_genesis`](../mfn-consensus/src/block.rs) initializes `ChainState` from it.

After genesis, every subsequent block must satisfy the full `apply_block` rule set.

---

## 8. Consensus parameters

```rust
pub struct ConsensusParams {
    pub expected_proposers_per_slot:   f64,   // default 1.5
    pub quorum_stake_bps:              u32,   // default 6667 (= 2/3 + 1bp)
    pub liveness_max_consecutive_missed: u32, // default 32
    pub liveness_slash_bps:            u32,   // default 100 (1% per offense)
}
```

All frozen at genesis. Changing any of these is a hard fork.

---

## 9. Why these design choices over alternatives

| Choice | Alternative | Why we picked ours |
|---|---|---|
| Slot-based PoS | PoW | Energy efficiency; deterministic finality; no fork-choice ambiguity. |
| Stake-weighted VRF sortition | Round-robin | Unpredictable to adversaries; resists targeted DoS / bribery. |
| BLS12-381 finality | Per-validator ECDSA aggregation | Constant-time pairing verification regardless of committee size. |
| Multiplicative liveness slashing | Additive / outright eviction | Smooth incentive curve; no cliff. |
| Outright equivocation slashing | Multiplicative | Equivocation is unambiguously malicious; no benefit-of-the-doubt warranted. |
| Single-finalized chain | Probabilistic finality (PoW-style) | Deterministic permanence guarantees rest on deterministic finality. |
| Frozen-at-genesis validator set (v0.1) | Live rotation from day one | Simpler audit surface; rotation in v0.2 with the bond/unbond machinery. |

---

## 10. Public API surface

```rust
// Building blocks
let seed: [u8; 32] = slot_seed(&prev_block_id, slot);
let threshold: u64 = eligibility_threshold(stake, total_stake, expected_per_slot);
let eligible = is_eligible(&vrf_output, stake, total_stake, expected_per_slot);

// Producing a block
let ctx = SlotContext { slot, prev_id, /* … */ };
let maybe_proof: Option<ProducerProof> = try_produce_slot(&secrets, &ctx, /* … */);

// Voting
let vote: CommitteeVote = cast_vote(&secrets, &header_signing_hash, validator_index);

// Finalizing
let agg: CommitteeAggregate = finalize(&validators, &votes)?;
let proof: FinalityProof = FinalityProof { committee_aggregate: agg, producer: producer_proof };
let check: ConsensusCheck = verify_finality_proof(&proof, &validators, &header_signing_hash);

// Slashing
let check: EvidenceCheck = verify_evidence(&evidence, &validators);
```

For full type signatures and the wire encode/decode helpers, see [`mfn-consensus/README.md`](../mfn-consensus/README.md).

---

## See also

- [`STORAGE.md`](./STORAGE.md) — the half consensus is funding
- [`PRIVACY.md`](./PRIVACY.md) — the half consensus is protecting
- [`ECONOMICS.md`](./ECONOMICS.md) — emission curve, fee split, treasury settlement
- [`ARCHITECTURE.md`](./ARCHITECTURE.md) — full system view
- [`ROADMAP.md`](./ROADMAP.md) — validator rotation is the next big consensus-layer feature
