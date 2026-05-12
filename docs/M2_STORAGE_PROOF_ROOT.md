# M2.0.2 — Storage-proof Merkle root in `BlockHeader`

**Status:** ✓ shipped (mainnet-ready wire format).

This note records the rationale, surface, and tests added by milestone **M2.0.2**. It is the third and final increment in the M2.0.x "header binds every body element" series, after [M2.0 — Validator-set Merkle root](./M2_VALIDATOR_ROOT.md) and **M2.0.1 — Slashing-evidence Merkle root**.

---

## Why

After M2.0 and M2.0.1, every block-body element committed to in the header except one — `block.storage_proofs`. The header bound:

| Body element | Header field | Since |
|---|---|---|
| transactions | `tx_root` | M0 |
| storage commitments | `storage_root` | M0 |
| bond ops | `bond_root` | M1 |
| validator set (pre-block) | `validator_root` | M2.0 |
| slashing evidence | `slashing_root` | M2.0.1 |
| **storage proofs** | **—** | gap |
| post-block UTXO accumulator | `utxo_root` | M0 |

That gap had real consequences:

- **No light-client path to verify SPoRA yield.** A client holding only the header chain could see commitments land (`storage_root`) and could see the post-block UTXO accumulator commit to the payouts (`utxo_root`), but it had no way to verify the *intermediate* "which proofs landed this block" question from the header alone. It would have had to download the full block body and rehash the proofs to check anything about storage operator behaviour.
- **Asymmetric body commitment.** Every other body element was header-bound. Storage proofs are revenue events (they accrue yield against locked endowments), and not binding them at the header level was the largest remaining asymmetry in the protocol's commitment surface.
- **Producer-proof tamper window (minor).** Because the producer's BLS aggregate didn't sign over the storage-proof set, a producer could in principle propose two blocks with the same header but different storage-proof bodies and not be slashable for equivocation under the current rules. The check is defence-in-depth — duplicate-proof rejection and `apply_block` re-verification already prevent the actual yield from being double-paid — but a clean header binding is the right place to close it.

M2.0.2 closes all three by adding a single 32-byte field — `BlockHeader::storage_proof_root`.

---

## What shipped

### Domain tag

```text
MFBN-1/storage-proof-leaf
```

Declared in [`mfn-crypto::domain::STORAGE_PROOF_LEAF`](../mfn-crypto/src/domain.rs).

### Canonical leaf encoding

```text
storage_proof_leaf_hash(p) = dhash(STORAGE_PROOF_LEAF, encode_storage_proof(p))
```

The leaf rides on top of the **already-canonical** SPoRA proof wire form ([`mfn-storage::spora::encode_storage_proof`](../mfn-storage/src/spora.rs)). That codec is what `verify_storage_proof` consumes today, so the leaf hash is a pure function of the same bytes the proof verifier sees — there's no second "for-Merkle-only" encoding to keep in sync.

`encode_storage_proof(p)` lays out the struct as:

```text
commit_hash(32)
‖ blob(chunk)                              // blob(x) = varint(x.len) ‖ x
‖ varint(index)
‖ varint(siblings.len)
‖ [ siblings[i](32) ‖ u8(right_side[i] ? 1 : 0) ]*
```

Helpers:

```rust
pub fn storage_proof_leaf_hash(p: &StorageProof) -> [u8; 32];
pub fn storage_proof_merkle_root(proofs: &[StorageProof]) -> [u8; 32];
```

Both in [`mfn-storage::spora`](../mfn-storage/src/spora.rs).

### Header field

```rust
struct BlockHeader {
    // ...existing fields...
    bond_root:           [u8; 32],
    validator_root:      [u8; 32],   // M2.0
    slashing_root:       [u8; 32],   // M2.0.1
    storage_proof_root:  [u8; 32],   // M2.0.2
    producer_proof:      Vec<u8>,
    utxo_root:           [u8; 32],
}
```

Included in **both** `header_signing_bytes` (the BLS-signed pre-image) and `block_header_bytes` (the full header used for `block_id`). The producer's BLS aggregate now binds the storage-proof set in addition to everything it already binds.

### Order semantics — producer-emit, not sorted

Unlike `slashing_leaf_hash` (which canonicalizes pair order *inside* each leaf), the storage-proof leaf does **not** sort or reorder anything. We commit to the producer's emit order across distinct commitments because:

1. **Duplicate proofs are already rejected.** `apply_block`'s storage-proof phase rejects any block that includes two proofs for the same `commit_hash`. So within a single block there is no reorder-ambiguity *within* a commitment.
2. **First proof wins the slot's yield.** The chain pays out yield to the *first* storage proof that lands for each commitment. Re-sorting proofs in the commitment would force the applier to also re-sort just to verify the header, and would lose the natural alignment between "the order the producer wrote them" and "the order the payouts happened".
3. **Empty list → zero sentinel.** Matches every other consensus root (`tx_root`, `bond_root`, `slashing_root`, `validator_root` all do this).

### `apply_block` enforcement

Phase 1 ("Roots") now reconstructs `storage_proof_merkle_root(&block.storage_proofs)` and rejects mismatching headers with a new error:

```rust
BlockError::StorageProofRootMismatch
```

The check runs *before* the storage-proof per-proof verification phase, so a tampered `storage_proof_root` is rejected even if every individual proof would otherwise pass — defense in depth.

---

## Test matrix

| # | Test | Layer |
|---|---|---|
| 1 | `storage_proof_merkle_root_empty_is_zero_sentinel` | `spora.rs` unit |
| 2 | `storage_proof_leaf_hash_is_deterministic` | `spora.rs` unit |
| 3 | `storage_proof_leaf_hash_changes_with_proof_content` | `spora.rs` unit |
| 4 | `storage_proof_merkle_root_changes_with_addition` | `spora.rs` unit |
| 5 | `storage_proof_merkle_root_is_order_sensitive` | `spora.rs` unit |
| 6 | `storage_proof_leaf_is_domain_separated` | `spora.rs` unit |
| 7 | `storage_proof_root_wire_matches_cloonan_ts_smoke_reference` | `spora.rs` unit (TS-parity golden vector) |
| 8 | `storage_proof_root_mismatch_is_rejected` | `block.rs` unit |
| 9 | `storage_proof_flow_at_genesis_plus_block1` *(updated to thread storage_proofs through `build_unsealed_header` + `seal_block`)* | `tests/integration.rs` |
| 10 | `tampered_storage_proof_root_in_signed_block_is_rejected` | `tests/integration.rs` |

(8 net-new tests + 2 strengthened.)

---

## Closed economic / security property

Combined with M2.0 + M2.0.1:

- **Every** block-body element is now committed at the header level: `tx_root`, `storage_root`, `bond_root`, `validator_root`, `slashing_root`, `storage_proof_root` — plus the post-block `utxo_root`.
- The producer's BLS aggregate signs over the full header pre-image, so any post-seal tamper with the storage-proof set necessarily breaks the producer/committee aggregate.
- A light client holding only the header chain can verify the structural shape of every revenue event (storage-proof emit, slashing, validator-set composition) without ever downloading the block body. Verifying the *contents* still requires the body, but proving "the body that hashes to `block_id` has exactly this multiset of proofs" is now header-level.

This is the textbook end-state for "header binds every body element" — combined with M1's bonded, slashable validator set, it makes a long-range fork attacker's degrees of freedom equal to "regenerate consistent BLS aggregates for every divergent header on the alternate chain", which is the same hardness as the underlying BLS+VRF assumptions.

---

## Future work

- **TS-side reference port.** Rust-side byte-parity vectors are pinned in `storage_proof_root_wire_matches_cloonan_ts_smoke_reference` (covers both the 0-sibling boundary and a 2-sibling proof with mixed `right_side`). The matching TS smoke fixture in `cloonan-group` will mirror the same hex once the port is wired. See [`docs/interop/TS_STORAGE_PROOF_ROOT_GOLDEN_VECTORS.md`](./interop/TS_STORAGE_PROOF_ROOT_GOLDEN_VECTORS.md).
- **Light-client crate (`mfn-light`).** Now unblocked at the protocol layer — every header is self-describing. Implementation waits for the node daemon (M2.1) to expose a header-only RPC.
- **Storage-proof sparse-Merkle proofs.** A future sparse variant of `storage_proof_merkle_root` could let a light client verify "this specific commitment had a proof land in block X" with a log-size proof. Useful for SPoRA yield audits.

---

## Code map

- [`mfn-crypto/src/domain.rs`](../mfn-crypto/src/domain.rs) — `STORAGE_PROOF_LEAF` domain tag.
- [`mfn-storage/src/spora.rs`](../mfn-storage/src/spora.rs) — `storage_proof_leaf_hash`, `storage_proof_merkle_root` + unit tests + TS-parity vector.
- [`mfn-storage/src/lib.rs`](../mfn-storage/src/lib.rs) — exports `storage_proof_leaf_hash`, `storage_proof_merkle_root`.
- [`mfn-consensus/src/block.rs`](../mfn-consensus/src/block.rs) — `BlockHeader::storage_proof_root` field, header signing/serialization, `build_unsealed_header` commits the body root, `apply_block` Phase 1 check, `BlockError::StorageProofRootMismatch`.
- [`mfn-consensus/tests/integration.rs`](../mfn-consensus/tests/integration.rs) — `tampered_storage_proof_root_in_signed_block_is_rejected` adversarial test + storage-proof-flow positive path.
- [`docs/ARCHITECTURE.md`](./ARCHITECTURE.md) — header shape + Phase 1 description.
- [`docs/CONSENSUS.md § Storage-proof commitment`](./CONSENSUS.md) — protocol-level description.
- [`docs/ROADMAP.md § Milestone M2.0.2`](./ROADMAP.md) — roadmap entry.
