# `mfn-consensus`

The state-transition function for Permawrite — the crate that takes the raw primitives from `mfn-crypto`, `mfn-bls`, and `mfn-storage` and turns them into an **actual chain**.

**Tests:** 81 passing &nbsp;·&nbsp; **`unsafe`:** forbidden &nbsp;·&nbsp; **Clippy:** clean

This is where `apply_block` lives — the single deterministic function that validates every consensus rule, performs every state mutation, and either produces a new `ChainState` or rejects the block with a typed error list.

For the system view, see [`docs/ARCHITECTURE.md`](../docs/ARCHITECTURE.md). For the consensus engine, [`docs/CONSENSUS.md`](../docs/CONSENSUS.md). For block-by-block flow, [`docs/ARCHITECTURE.md § State-transition function`](../docs/ARCHITECTURE.md#state-transition-function-apply_block).

---

## Modules

| Module | Responsibility |
|---|---|
| [`emission`](src/emission.rs) | Hybrid emission curve (Bitcoin halvings → Monero tail), fee-split bps. |
| [`bonding`](src/bonding.rs) | M1 rotation **parameters** — min stake, unbond delay, epoch churn caps (wire + `apply_block` next). |
| [`transaction`](src/transaction.rs) | RingCT-style confidential tx — wire format, build, sign, verify. |
| [`coinbase`](src/coinbase.rs) | Deterministic synthetic block-reward tx. |
| [`consensus`](src/consensus.rs) | Slot model, VRF leader election, BLS committee finality, `FinalityProof`. |
| [`slashing`](src/slashing.rs) | Equivocation evidence + verification. |
| [`storage`](src/storage.rs) | Re-exports `StorageCommitment` from `mfn-storage` (for consumer convenience). |
| [`block`](src/block.rs) | **`BlockHeader`, `Block`, `ChainState`, `apply_block` — the heart of it all.** |

---

## What `apply_block` enforces

In order, every block goes through these checks. Any failure produces a typed `BlockError` variant and rejects the block.

1. **Header sanity.** Height increments by 1, prev_hash matches, version matches, timestamp increases.
2. **Finality proof.** Decode `producer_proof`; verify producer's VRF + Schnorr; verify committee BLS aggregate; verify quorum stake share.
3. **Merkle roots.** Reconstruct `tx_root` and `storage_root`; reject mismatches.
4. **Equivocation slashing.** For each `SlashEvidence`: verify, zero offending validator's stake.
5. **Coinbase** (when applicable): verify `amount == emission(height) + producer_fee_share`.
6. **Regular tx verification.** For each tx: CLSAG signatures, Pedersen balance, Bulletproof range proofs.
7. **Ring-membership chain guard.** For each CLSAG input, every ring member `(P, C)` must exist in the UTXO set with **exact** commitment match. **Closes the counterfeit-input attack.**
8. **Key-image uniqueness.** Cross-block double-spend check; insert each new key image into `spent_key_images`.
9. **Storage upload endowment.** New `StorageCommitment` requires `tx_fee_treasury_share ≥ required_endowment(size, replication)`. Replication enforced in `[min, max]`.
10. **State updates.** Insert new UTXOs, append to accumulator, register new commitments, add treasury inflow.
11. **SPoRA proofs.** For each `StorageProof`: reject duplicates, verify against deterministic challenge, accrue PPB yield, pay out integer base units.
12. **Treasury settlement.** Drain treasury for storage rewards; emission backstop covers any shortfall.
13. **Liveness tracking + auto-slash.** Walk finality bitmap; update `ValidatorStats`; multiplicatively slash any validator over the consecutive-missed-vote threshold.
14. **UTXO root.** Recompute accumulator root; reject if `header.utxo_root` doesn't match.
15. **Commit.** Append block_id to `block_ids`, return new state.

Full implementation in [`src/block.rs`](src/block.rs).

---

## Public API (selected highlights)

```rust
// === Genesis ======================================================
let genesis: Block       = build_genesis(&cfg);
let state:   ChainState  = apply_genesis(&genesis, &cfg)?;

// === Building / sealing a block ===================================
let unsealed: BlockHeader = build_unsealed_header(
    prev_block_id, height, slot, timestamp,
    &txs, &slashings, /* … */,
);
let block: Block = seal_block(
    unsealed, txs, slashings, producer_proof, storage_proofs,
);

// === Applying a block =============================================
let outcome: ApplyOutcome = apply_block(&state, &block)?;
let new_state: ChainState  = outcome.state;
let block_id:   [u8;32]    = outcome.block_id;
let coinbase:   Option<…>  = outcome.coinbase;

// === Transaction lifecycle =========================================
let tx: TransactionWire = sign_transaction(
    &inputs, &outputs, &recipients, fee, /* storage_commit, etc. */,
)?;
let res: VerifyResult = verify_transaction(&tx);
let id:  [u8;32]      = tx_id(&tx);

// === Consensus ====================================================
let seed     = slot_seed(&prev_block_id, slot);
let elig     = is_eligible(&vrf_output, stake, total_stake, expected_per_slot);
let prod     = try_produce_slot(&secrets, &ctx, /* … */);
let vote     = cast_vote(&secrets, &header_signing_hash, validator_index);
let agg      = finalize(&validators, &votes)?;
let proof    = FinalityProof { committee_aggregate: agg, producer: prod };
let check    = verify_finality_proof(&proof, &validators, &header_signing_hash);

// === Slashing =====================================================
let check    = verify_evidence(&evidence, &validators);
let encoded  = encode_evidence(&evidence);
let decoded  = decode_evidence(&encoded)?;

// === Emission / endowment =========================================
let subsidy: u64 = emission_at_height(height, &emission_params);
let cum:     u128 = cumulative_emission(height, &emission_params);
validate_emission_params(&emission_params)?;
```

Full types in [`src/lib.rs`](src/lib.rs).

---

## Key types

```rust
pub struct BlockHeader {
    pub version:        u32,
    pub prev_hash:      [u8; 32],
    pub height:         u32,
    pub slot:           u32,
    pub timestamp:      u64,
    pub tx_root:        [u8; 32],
    pub storage_root:   [u8; 32],
    pub producer_proof: Vec<u8>,    // MFBN-encoded FinalityProof
    pub utxo_root:      [u8; 32],
}

pub struct Block {
    pub header:         BlockHeader,
    pub txs:            Vec<TransactionWire>,
    pub slashings:      Vec<SlashEvidence>,
    pub storage_proofs: Vec<StorageProof>,
}

pub struct ChainState {
    pub height:            Option<u32>,
    pub utxo:              HashMap<[u8;32], UtxoEntry>,
    pub spent_key_images:  HashSet<[u8;32]>,
    pub storage:           HashMap<[u8;32], StorageEntry>,
    pub block_ids:         Vec<[u8;32]>,
    pub validators:        Vec<Validator>,
    pub validator_stats:   Vec<ValidatorStats>,
    pub params:            ConsensusParams,
    pub emission_params:   EmissionParams,
    pub endowment_params:  EndowmentParams,
    pub treasury:          u128,
    pub utxo_tree:         UtxoTreeState,
}
```

---

## Default consensus parameters

```rust
pub const DEFAULT_CONSENSUS_PARAMS: ConsensusParams = ConsensusParams {
    expected_proposers_per_slot:     1.5,    // Algorand-style with liveness slack
    quorum_stake_bps:                6667,   // = 2/3 + 1bp
    liveness_max_consecutive_missed: 32,     // ~6.4 min at 12s slots
    liveness_slash_bps:              100,    // 1% per offense
};

pub const DEFAULT_EMISSION_PARAMS: EmissionParams = EmissionParams {
    initial_reward:        50 * MFN_BASE,         // 50 MFN/block
    halving_period:        8_000_000,             // ~3 years at 12s slots
    halving_count:         8,                     // 8 halvings = 24 years
    tail_emission:         (50 * MFN_BASE) >> 8,  // ~0.195 MFN/block forever
    storage_proof_reward:  MFN_BASE / 10,         // 0.1 MFN emission backstop
    fee_to_treasury_bps:   9000,                  // 90% treasury, 10% producer
};
```

Defaults from `DEFAULT_ENDOWMENT_PARAMS` come from `mfn-storage`. See the [`mfn-storage` README](../mfn-storage/README.md) for the full default storage params.

---

## `BlockError` highlights

Typed reasons a block can be rejected. Selected variants (full list in [`src/block.rs`](src/block.rs)):

```rust
pub enum BlockError {
    // Header
    HeaderVersionMismatch { expected, got },
    HeaderHeightMismatch { expected, got },
    HeaderPrevHashMismatch,

    // Finality
    FinalityVerifyFailed(ConsensusCheck),
    InvalidProducerProof,

    // Txs
    TxVerifyFailed(VerifyResult),
    DoubleSpend(KeyImage),
    RingMemberNotInUtxoSet { tx, input, ring_index, one_time_addr },
    RingMemberCommitMismatch { tx, input, ring_index, one_time_addr },

    // Storage
    UploadUnderfunded { required, supplied },
    StorageReplicationTooLow { min, got },
    StorageReplicationTooHigh { max, got },
    DuplicateStorageProof { commit_hash },
    StorageProofUnknownCommit { commit_hash },
    StorageProofInvalid(StorageProofCheck),
    EndowmentMathFailed(EndowmentError),

    // Coinbase
    UnexpectedCoinbase,
    CoinbaseInvalid(Vec<String>),

    // Roots
    TxRootMismatch,
    StorageRootMismatch,
    UtxoRootMismatch,
}
```

---

## Test categories

- **Genesis** (`apply_genesis` behavior, initial output insertion, initial storage anchoring).
- **Header** (height/prev-hash/version/timestamp sanity).
- **Tx semantics** (CLSAG verify, Pedersen balance, range proofs, key-image uniqueness).
- **Ring membership** (counterfeit-input attack closure — fabricated members rejected, real-P-wrong-C rejected).
- **Storage** (endowment burden enforcement, replication bounds, duplicate proofs, unknown commits, corrupt chunks, accrual correctness).
- **Slashing** (equivocation: stake zeroed; liveness: 8 unit tests + 1 multi-block integration test).
- **Consensus** (finality verification, quorum threshold, missing producer proof).
- **Roots** (tx_root, storage_root, utxo_root reconstruction).
- **Integration** (multi-block flows: genesis → block1 → block2 with privacy tx, storage upload, slashing).

```bash
cargo test -p mfn-consensus --release
```

---

## Dependencies

```
mfn-crypto       = path     # primitives
mfn-bls          = path     # finality
mfn-storage      = path     # storage proofs + endowment math
curve25519-dalek = "4.1"
sha2             = "0.10"
subtle           = "2.5"
zeroize          = "1.7"
rand_core        = "0.6"
thiserror        = "1.0"
hex              = "0.4"
```

---

## See also

- [`docs/CONSENSUS.md`](../docs/CONSENSUS.md) — PoS engine deep dive
- [`docs/ECONOMICS.md`](../docs/ECONOMICS.md) — emission curve + treasury settlement
- [`docs/STORAGE.md`](../docs/STORAGE.md) — what storage proofs do here
- [`docs/PRIVACY.md`](../docs/PRIVACY.md) — what tx verification guards against
- [`docs/ARCHITECTURE.md`](../docs/ARCHITECTURE.md) — the system view
- [`docs/ROADMAP.md`](../docs/ROADMAP.md) — what's next (validator rotation)
