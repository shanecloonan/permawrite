# `mfn-consensus`

The state-transition function for Permawrite — the crate that takes the raw primitives from `mfn-crypto`, `mfn-bls`, and `mfn-storage` and turns them into an **actual chain**.

**Tests:** 161 passing (147 unit + 14 integration) &nbsp;·&nbsp; **`unsafe`:** forbidden &nbsp;·&nbsp; **Clippy:** clean

This is where `apply_block` lives — the single deterministic function that validates every consensus rule, performs every state mutation, and either produces a new `ChainState` or rejects the block with a typed error list.

For the system view, see [`docs/ARCHITECTURE.md`](../docs/ARCHITECTURE.md). For the consensus engine, [`docs/CONSENSUS.md`](../docs/CONSENSUS.md). For block-by-block flow, [`docs/ARCHITECTURE.md § State-transition function`](../docs/ARCHITECTURE.md#state-transition-function-apply_block).

---

## Modules

| Module | Responsibility |
|---|---|
| [`emission`](src/emission.rs) | Hybrid emission curve (Bitcoin halvings → Monero tail), fee-split bps. |
| [`bonding`](src/bonding.rs) | M1 rotation parameters + pure validation helpers — min stake, unbond delay, per-epoch entry/exit churn caps. |
| [`bond_wire`](src/bond_wire.rs) | M1 wire format — `BondOp::{Register, Unbond}` (both BLS-signed by the operator's voting key), `register_signing_hash`, `unbond_signing_hash`, `bond_op_leaf_hash`, `bond_merkle_root`. |
| [`transaction`](src/transaction.rs) | RingCT-style confidential tx — wire format, build, sign, verify. |
| [`coinbase`](src/coinbase.rs) | Deterministic synthetic block-reward tx. |
| [`consensus`](src/consensus.rs) | Slot model, VRF leader election, BLS committee finality, `FinalityProof`. M2.0 — `validator_leaf_bytes` / `validator_leaf_hash` / `validator_set_root` for the per-block `validator_root` commitment. |
| [`slashing`](src/slashing.rs) | Equivocation evidence + verification. M2.0.1 — `slashing_leaf_hash` / `slashing_merkle_root` for the per-block `slashing_root` commitment. |
| [`storage`](src/storage.rs) | Re-exports `StorageCommitment` from `mfn-storage` (for consumer convenience). |
| [`header_verify`](src/header_verify.rs) | **M2.0.5 + M2.0.7 — pure-function light-client verification primitives.** `verify_header(header, trusted_validators, params)` (M2.0.5) verifies `validator_root` + producer-proof + BLS finality aggregate against a trusted pre-block validator set. `verify_block_body(block)` (M2.0.7) re-derives `tx_root` / `bond_root` / `slashing_root` / `storage_proof_root` from `block.<field>` and matches each against the header. Both return typed `Result<_, *VerifyError>`. The cryptographic primitives for `mfn-light`. |
| [`validator_evolution`](src/validator_evolution.rs) | **M2.0.8 — shared validator-set evolution helpers.** Pure functions `apply_equivocation_slashings`, `apply_liveness_evolution`, `apply_bond_ops_evolution`, `apply_unbond_settlements` plus `BondEpochCounters` + `finality_bitmap_from_header`. `apply_block` (the full-node STF) and `mfn-light::LightChain::apply_block` (the light-client chain follower) both call these helpers, guaranteeing byte-for-byte parity between full-node and light-client validator-set transitions. |
| [`block`](src/block.rs) | **`BlockHeader`, `Block`, `ChainState`, `apply_block` — the heart of it all.** Each per-block validator-set mutation is a single line that delegates into `validator_evolution`. |

---

## What `apply_block` enforces

In order, every block goes through these checks. Any failure produces a typed `BlockError` variant and rejects the block.

1. **Header sanity.** Height increments by 1, prev_hash matches, version matches, timestamp increases.
2. **Finality proof.** Decode `producer_proof`; verify producer's VRF + Schnorr; verify committee BLS aggregate; verify quorum stake share.
3. **Merkle roots.** Reconstruct `tx_root`, `storage_root`, `bond_root` (M1), `slashing_root` (M2.0.1 — over `block.slashings`, each leaf canonicalized so pair-swap is a no-op), `validator_root` (M2.0 — over the *pre-block* validator set), and `storage_proof_root` (M2.0.2 — over `block.storage_proofs` in producer-emit order, leaf = `dhash(STORAGE_PROOF_LEAF, encode_storage_proof(p))`); reject mismatches. The header now binds every block-body element.
4. **Equivocation slashing.** For each `SlashEvidence`: verify, **credit forfeited stake to `treasury`**, zero offending validator's stake.
5. **Coinbase** (when applicable): verify `amount == emission(height) + producer_fee_share`.
6. **Regular tx verification.** For each tx: CLSAG signatures, Pedersen balance, Bulletproof range proofs.
7. **Ring-membership chain guard.** For each CLSAG input, every ring member `(P, C)` must exist in the UTXO set with **exact** commitment match. **Closes the counterfeit-input attack.**
8. **Key-image uniqueness.** Cross-block double-spend check; insert each new key image into `spent_key_images`.
9. **Storage upload endowment.** New `StorageCommitment` requires `tx_fee_treasury_share ≥ required_endowment(size, replication)`. Replication enforced in `[min, max]`.
10. **State updates.** Insert new UTXOs, append to accumulator, register new commitments, add treasury inflow.
11. **SPoRA proofs.** For each `StorageProof`: reject duplicates, verify against deterministic challenge, accrue PPB yield, pay out integer base units.
12. **Treasury settlement.** Drain treasury for storage rewards; emission backstop covers any shortfall.
13. **Liveness tracking + auto-slash.** Walk finality bitmap; update `ValidatorStats`; multiplicatively slash any validator over the consecutive-missed-vote threshold (forfeited stake **credited to `treasury`**).
14. **Bond operations (M1, M1.5-authenticated).** Atomically apply `BondOp::Register` (BLS-authenticated by the operator's own `bls_pk` over `(stake, vrf_pk, bls_pk, payout)` under domain `MFBN-1/register-op-sig`; on success the validator is registered and its declared stake is **burned into `treasury`**) and `BondOp::Unbond` (BLS-signed under `MFBN-1/unbond-op-sig`; enqueued into `pending_unbonds`). Per-epoch entry / exit churn caps enforced. Any rejection rolls back the entire bond-op block.
15. **Unbond settlement (M1).** Any pending unbond whose `unlock_height ≤ block.height` is settled: the validator's stake is zeroed, the entry becomes a non-signing zombie, and the originally bonded MFN remains in the treasury (permanent contribution to the permanence endowment).
16. **UTXO root.** Recompute accumulator root; reject if `header.utxo_root` doesn't match.
17. **Commit.** Append block_id to `block_ids`, return new state.

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

// === Light-header verification (M2.0.5) ===========================
// Pure function: given a trusted pre-block validator set, verify
// validator_root + producer_proof + BLS finality aggregate.
let check: Result<HeaderCheck, HeaderVerifyError> =
    verify_header(&header, &trusted_validators, &params);

// === Light-body verification (M2.0.7) =============================
// Pure function: re-derive tx_root / bond_root / slashing_root /
// storage_proof_root from `block.<field>` and match them against
// `block.header`. Combined with verify_header above, gives a light
// client cryptographic confidence that the delivered (header, body)
// pair is the one a 2/3-stake quorum signed over.
let body_ok: Result<(), BodyVerifyError> = verify_block_body(&block);

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
    pub height:                  Option<u32>,
    pub utxo:                    HashMap<[u8;32], UtxoEntry>,
    pub spent_key_images:        HashSet<[u8;32]>,
    pub storage:                 HashMap<[u8;32], StorageEntry>,
    pub block_ids:               Vec<[u8;32]>,
    pub validators:              Vec<Validator>,
    pub validator_stats:         Vec<ValidatorStats>,
    pub params:                  ConsensusParams,
    pub emission_params:         EmissionParams,
    pub endowment_params:        EndowmentParams,
    pub bonding_params:          BondingParams,            // M1
    pub bond_epoch_id:           u64,                       // M1
    pub bond_epoch_entry_count:  u32,                       // M1
    pub bond_epoch_exit_count:   u32,                       // M1
    pub next_validator_index:    u32,                       // M1
    pub pending_unbonds:         BTreeMap<u32, PendingUnbond>, // M1
    pub treasury:                u128,
    pub utxo_tree:               UtxoTreeState,
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

- **Genesis** (`apply_genesis` behavior, initial output insertion, initial storage anchoring, optional `bonding_params`).
- **Header** (height/prev-hash/version/timestamp sanity).
- **Tx semantics** (CLSAG verify, Pedersen balance, range proofs, key-image uniqueness).
- **Ring membership** (counterfeit-input attack closure — fabricated members rejected, real-P-wrong-C rejected).
- **Storage** (endowment burden enforcement, replication bounds, duplicate proofs, unknown commits, corrupt chunks, accrual correctness).
- **Slashing** (equivocation: stake zeroed + forfeited stake credited to treasury; liveness: 8 unit tests + 1 multi-block integration test; both routed to treasury).
- **Consensus** (finality verification, quorum threshold, missing producer proof).
- **Roots** (tx_root, storage_root, bond_root, slashing_root, validator_root, storage_proof_root, utxo_root reconstruction).
- **Bond wire** (`bond_op_round_trip`, `bond_register_wire_matches_cloonan_ts_smoke_reference`, `bond_unbond_wire_matches_cloonan_ts_smoke_reference`, `register_sig_is_bound_to_bls_pk_and_payload`, `register_signing_hash_is_domain_separated`, `unbond_op_round_trip_and_sig_verify`, `unbond_signing_hash_is_domain_separated`, `unbond_sig_does_not_verify_under_different_index`, `unbond_decode_rejects_trailing_bytes`).
- **Bond apply** (burn-on-bond credits treasury, per-epoch entry/exit churn cap enforcement, atomic rollback of failed bond ops, unbond-of-unknown-validator rejection, **forged-register-signature rejection** under `register_rejects_invalid_signature`).
- **Light-header verification (M2.0.5)** — 10 unit tests in `header_verify::tests`: happy path round-trip, tampered `validator_root` / wrong trusted set, tampered producer proof, empty trusted set, empty / truncated producer proof, tampered height and slot (each breaks the header signing hash → finality rejection), determinism. Plus 3 integration tests in `mfn-node/tests/light_header_verify.rs` proving `verify_header` and `apply_block` agree on every block of a real 3-block chain. Plus 5 integration tests in `mfn-light/tests/follow_chain.rs` (M2.0.6 chain follower).
- **Light-body verification (M2.0.7)** — 8 unit tests in `header_verify::tests`: happy path on real signed block, tampered header fields for each of the four body-bound roots (`tx_root` / `bond_root` / `slashing_root` / `storage_proof_root`), body-side tamper (pushed duplicate tx), determinism, genesis consistency. Plus 7 + 5 mfn-light tests for `apply_block` (see [`mfn-light/README.md`](../mfn-light/README.md)).
- **Validator-set evolution (M2.0.8)** — 8 unit tests in `validator_evolution::tests`: empty-input no-ops for each of the four phases; liveness consecutive-missed reset on signed bit; zero-stake validators skipped by liveness; stats-vec auto-resize when misaligned; unbond settlement zeroes stake at unlock_height; bitmap extractor returns `None` on genesis headers. The `apply_block` refactor that delegates to these helpers preserves every pre-M2.0.8 test (all 147 unit + 14 integration tests pass byte-for-byte unchanged). Plus 8 + 2 mfn-light tests for the light-client integration (see [`mfn-light/README.md`](../mfn-light/README.md)).
- **Integration** (multi-block flows: genesis → block1 → block2 with privacy tx, storage upload, slashing; full `unbond_lifecycle` with 3 validators, BLS finality, request → delay → settle, equivocation-during-delay still slashes, exit-churn cap spills across blocks).

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
