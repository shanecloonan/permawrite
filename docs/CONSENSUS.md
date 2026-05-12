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

**Intuition.** Today's validator set is frozen at genesis. Future protocol upgrades will introduce bond/unbond transactions and entry/exit queues so the set can rotate. (See [`ROADMAP.md`](./ROADMAP.md).)

### Current state (v0.1)

```rust
pub struct Validator {
    pub vrf_public_key:  EdwardsPoint,
    pub bls_public_key:  BlsPublicKey,
    pub schnorr_public_key: EdwardsPoint,
    pub stake:           u64,
}

pub struct ValidatorSecrets {
    pub vrf_secret:     Scalar,
    pub bls_secret:     BlsSecretKey,
    pub schnorr_secret: Scalar,
}
```

Three keypairs per validator:

- **VRF keypair** — for leader election.
- **BLS keypair** — for finality voting.
- **Schnorr keypair** — for producer claim (signing the VRF proof in their `ProducerProof`).

Why three? Different roles, different schemes. VRF and BLS use different curves; Schnorr lets us bind the VRF proof to the producer's stable identity. Keeping them separate keeps the security reductions clean.

### `Validator` index = identity

The validator's identity in the chain is just their index in `ChainState::validators`. The finality bitmap is keyed by this index. `validator_stats[i]` is the stats for `validators[i]`. Tight coupling, simple semantics.

### What's missing (v0.2 roadmap)

- **Bond/unbond transactions.** Staking and unstaking must be on-chain, with delays (to prevent unbond-then-attack).
- **Entry/exit queues.** Bounded per-epoch churn so the validator set is predictable.
- **Slashing-aware unbond.** Equivocation slashes that are anchored *after* an unbond should still take effect (delayed unbond ≥ max-evidence-window).
- **Validator metadata.** Optional fields for monitoring (last-active height, slash history visible to wallets).

See [`ROADMAP.md`](./ROADMAP.md) for the implementation plan.

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
