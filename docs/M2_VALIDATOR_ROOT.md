# M2.0 — Validator-set Merkle root in `BlockHeader`

**Status:** ✓ shipped (mainnet-ready wire format).

This note records the rationale, surface, and tests added by milestone **M2.0**. The companion milestone for live validator rotation is [M1 — Validator Rotation](./M1_VALIDATOR_ROTATION.md).

---

## Why

Once M1 made the validator set rotate on-chain, a structural gap opened up: the `BlockHeader` committed to txs (`tx_root`), storage commitments (`storage_root`), bond ops (`bond_root`), and the post-block UTXO accumulator (`utxo_root`), but **not** to the validator set the block was produced against. That left several capabilities on the table:

- **No light-client verification path.** Phase 0 of `apply_block` verifies the producer-proof + finality bitmap against `state.validators`. A client holding only the header chain had no way to verify Phase 0 from the header alone — it would have had to replay every bond op and slashing event back to genesis.
- **Long-range attack surface.** Without a header-level binding, a forking attacker has more degrees of freedom in re-presenting the validator set than they should.
- **Asymmetric root commitments.** The header bound every consensus-critical input *except* the validator set, which is the most security-critical input of all.

M2.0 closes all three by adding a single 32-byte field — `BlockHeader::validator_root`.

---

## What shipped

### Domain tag

```text
MFBN-1/validator-leaf
```

Declared in [`mfn-crypto::domain::VALIDATOR_LEAF`](../mfn-crypto/src/domain.rs).

### Canonical leaf encoding

```text
dhash(VALIDATOR_LEAF,
      index(u32, BE) ‖ stake(u64, BE)
   ‖  vrf_pk(32) ‖ bls_pk(48)
   ‖  payout_flag(u8) ‖ [view_pub(32) ‖ spend_pub(32)]?)
```

What's deliberately **excluded** is `ValidatorStats`. Liveness counters churn every block, and reincluding them would force a needless re-hash of every leaf even on blocks that didn't touch the validator set. The minimum data a light client needs to verify a finality bitmap is `(index, stake, bls_pk)`; the other fields round out the canonical record for completeness.

Helpers:

```rust
pub fn validator_leaf_bytes(v: &Validator) -> Vec<u8>;
pub fn validator_leaf_hash(v: &Validator) -> [u8; 32];
pub fn validator_set_root(validators: &[Validator]) -> [u8; 32];
```

All in [`mfn-consensus::consensus`](../mfn-consensus/src/consensus.rs).

### Header field

```rust
struct BlockHeader {
    // ...existing fields...
    bond_root:      [u8; 32],
    validator_root: [u8; 32],   // M2.0
    producer_proof: Vec<u8>,
    utxo_root:      [u8; 32],
}
```

Included in **both** `header_signing_bytes` (the BLS-signed pre-image) and `block_header_bytes` (the full header used for `block_id`). The producer's BLS aggregate now binds the validator-set commitment in addition to everything it used to bind.

### Pre-block semantics

`validator_root` commits to `state.validators` *as it stood before applying the block*. This is the set Phase 0's producer-proof and finality bitmap are verified against. Any rotation / slashing / unbond settlement applied *by* this block moves the **next** header's `validator_root`.

Genesis convention: `genesis.header.validator_root = [0u8; 32]` (the pre-genesis validator set is empty). The block at height 1 commits `validator_set_root(&cfg.validators)`.

### `apply_block` enforcement

Phase 1 ("Roots") now reconstructs `validator_set_root(&state.validators)` and rejects mismatching headers with a new error:

```rust
BlockError::ValidatorRootMismatch
```

The check runs *before* finality verification, so a tampered `validator_root` is rejected even if (somehow) the BLS aggregate were valid — defense in depth.

---

## Test matrix

| # | Test | Layer |
|---|---|---|
| 1 | `validator_set_root_empty_is_zero_sentinel` | `consensus.rs` unit |
| 2 | `validator_leaf_bytes_depend_on_every_field` | `consensus.rs` unit |
| 3 | `validator_leaf_hash_is_domain_separated` | `consensus.rs` unit |
| 4 | `validator_set_root_changes_when_stake_changes` | `consensus.rs` unit |
| 5 | `validator_set_root_changes_with_order` | `consensus.rs` unit |
| 6 | `validator_set_root_changes_when_validator_added` | `consensus.rs` unit |
| 7 | `validator_root_mismatch_is_rejected` | `block.rs` unit |
| 8 | `build_unsealed_header_commits_pre_block_validator_set` | `block.rs` unit |
| 9 | `validator_root_commits_pre_block_set_each_block` | `tests/integration.rs` |
| 10 | `validator_root_moves_on_equivocation_slash` | `tests/integration.rs` |
| 11 | `validator_root_moves_on_unbond_settlement` | `tests/integration.rs` |
| 12 | `tampered_validator_root_in_signed_block_is_rejected` | `tests/integration.rs` |
| 13 | `validator_root_wire_matches_cloonan_ts_smoke_reference` | `consensus.rs` unit (TS-parity golden vector) |

(13 new tests; +13 vs. the post-M1.5 baseline.)

---

## Closed economic / security property

Combined with M1's burn-on-bond + slash-to-treasury:

- Every block's header binds the validator set its producer-proof and finality bitmap were verified against.
- Every transition that changes the validator set (registration, equivocation, liveness slash, unbond settlement) is itself authorized either by a BLS signature (`Register`, `Unbond`) or by hard-on-chain evidence (slashing) **and** is reflected in the *next* block's `validator_root`.
- A long-range fork attacker must either (a) re-present the exact pre-block validator set under every header they want to fork — which requires regenerating consistent BLS aggregates — or (b) cooperate with a quorum of bonded validators who can be slashed for equivocation.

The combination makes the chain's validator history both **commit-bound** (header-level) and **economically bound** (slashable evidence), which is the textbook setup for long-range attack resistance.

---

## Future work

- **TS-side reference port.** Rust-side byte-parity vectors are pinned in `validator_root_wire_matches_cloonan_ts_smoke_reference` (covers both with-payout and no-payout leaf branches plus a two-validator root). The matching TS smoke fixture in `cloonan-group` will mirror the same hex once the port is wired. See [`docs/interop/TS_VALIDATOR_ROOT_GOLDEN_VECTORS.md`](./interop/TS_VALIDATOR_ROOT_GOLDEN_VECTORS.md).
- **Light-client crate (`mfn-light`).** The header is now self-describing; the crate that *consumes* it has to wait until the node daemon (M2.1) is up and there's something to talk to.
- **Validator-set sparse-Merkle proofs.** Currently `validator_set_root` is a balanced binary Merkle root; a future sparse variant could let a light client verify "validator at index `i` has stake `s`, bls_pk `K`" with a log-size proof.

---

## Code map

- [`mfn-crypto/src/domain.rs`](../mfn-crypto/src/domain.rs) — `VALIDATOR_LEAF` domain tag.
- [`mfn-consensus/src/consensus.rs`](../mfn-consensus/src/consensus.rs) — `validator_leaf_bytes`, `validator_leaf_hash`, `validator_set_root` + unit tests.
- [`mfn-consensus/src/block.rs`](../mfn-consensus/src/block.rs) — `BlockHeader::validator_root` field, header signing/serialization, `build_unsealed_header` commits the pre-block root, `apply_block` Phase 1 check, `BlockError::ValidatorRootMismatch`.
- [`mfn-consensus/src/lib.rs`](../mfn-consensus/src/lib.rs) — exports `validator_leaf_bytes`, `validator_leaf_hash`, `validator_set_root`.
- [`mfn-consensus/tests/integration.rs`](../mfn-consensus/tests/integration.rs) — multi-block invariants & adversarial tamper test.
- [`docs/ARCHITECTURE.md`](./ARCHITECTURE.md) — header shape + Phase 1 description.
- [`docs/CONSENSUS.md § Validator-set commitment in the header`](./CONSENSUS.md) — protocol-level description.
- [`docs/ROADMAP.md § Milestone M2.0`](./ROADMAP.md) — roadmap entry.
