# TypeScript reference — storage-proof-root commitment golden vectors

This file pins the canonical bytes and hashes for the M2.0.2 storage-proof commitment so the Rust and TypeScript implementations stay byte-for-byte identical. The vector is deterministic — same hand-built proofs, same bytes, every time — and asserted in `mfn-storage` unit tests. Any drift here is a consensus-breaking change.

For the protocol-level rationale see [`docs/ROADMAP.md § Milestone M2.0.2`](../ROADMAP.md), [`docs/CONSENSUS.md § Storage-proof commitment`](../CONSENSUS.md), and the design note [`docs/M2_STORAGE_PROOF_ROOT.md`](../M2_STORAGE_PROOF_ROOT.md).

## Canonical leaf encoding

```text
storage_proof_leaf_hash(p) = dhash(MFBN-1/storage-proof-leaf, encode_storage_proof(p))
```

`encode_storage_proof(p)` is the canonical SPoRA proof wire form already in use across the chain (the same bytes the storage-proof verifier rehashes). It lays out the struct as:

```text
commit_hash(32)
‖ blob(chunk)                          // blob(x) = varint(x.len) ‖ x
‖ varint(index)
‖ varint(siblings.len)
‖ [ siblings[i](32) ‖ u8(right_side[i] ? 1 : 0) ]*
```

`varint` is the consensus-canonical LEB128-style varint shared by every wire codec in the workspace.

## Inputs (deterministic, hand-constructed)

We construct two proofs by hand so the vector pins the *encoding + hashing* surface without depending on the chunking pipeline. This is enough to lock down byte-for-byte parity across implementations because the rest of the SPoRA stack already has its own golden vectors.

| Proof | Field | Value |
|---|---|---|
| **p0 (0-sibling)** | `commit_hash` | `[0xaa; 32]` |
| | `chunk` | `[0, 1, 2, 3, 4, 5, 6, 7]` (8 bytes) |
| | `proof.index` | `0` |
| | `proof.siblings` | `[]` |
| | `proof.right_side` | `[]` |
| **p1 (2-sibling, mixed right_side)** | `commit_hash` | `[0xbb; 32]` |
| | `chunk` | `b"permawrite"` (10 bytes) |
| | `proof.index` | `1` |
| | `proof.siblings` | `[[0x11; 32], [0x22; 32]]` |
| | `proof.right_side` | `[true, false]` |

`p0` exercises the empty-sibling boundary (proof for a single-chunk commitment). `p1` exercises a non-trivial siblings list with a *mixed* `right_side` pattern so an encoder cannot accidentally swap the boolean column without breaking the vector.

## Reference bytes

| Field | Hex |
|-------|-----|
| `storage_proof_leaf_hash(p0)` (32 bytes) | `694b5a17a842c528d24f24e53cdd9a1601fff4018c365d8a7f448411daf4709d` |
| `storage_proof_leaf_hash(p1)` (32 bytes) | `00bc55e1545fa11184cd2aeb450173fdf8d940cb6f18e294d6f0be454b6c05f6` |
| `storage_proof_merkle_root([p0, p1])` (32 bytes) | `aaae83fcbc777d692c7fbc0f469213faae63082e8c040c163256ef751c889c6b` |

The root is computed by the binary Merkle root over the leaf hashes in **producer-emit order** (not sorted), using [`mfn-crypto::merkle::merkle_root_or_zero`](../../mfn-crypto/src/merkle.rs). The chain already rejects duplicate proofs per commitment in a single block (see `apply_block` storage-proof phase), so the only ordering choice left across distinct commitments is the producer's emit order — and that order *is* paid out (the first proof that lands accrues the slot's yield). Re-sorting in the commitment would force the applier to re-sort just to verify the header. Empty list folds to the all-zero sentinel, matching every other consensus root.

## Wire / hashing structure

```
storage_proof_leaf_hash(p) = dhash(MFBN-1/storage-proof-leaf, encode_storage_proof(p))

storage_proof_merkle_root(ps) = if ps.is_empty() { [0u8; 32] }
                                 else { binary_merkle(ps.map(storage_proof_leaf_hash)) }
```

## Rust assertion

`spora::tests::storage_proof_root_wire_matches_cloonan_ts_smoke_reference` in `mfn-storage`.

## Notes

- **Emit order is committed.** Unlike `slashing_leaf_hash`, the storage-proof leaf does not canonicalize its input — the SPoRA wire form is already canonical and the chain enforces "no duplicate proofs per commitment per block", so there's no reorder-ambiguity within a block.
- **Domain separation.** `MFBN-1/storage-proof-leaf` is distinct from every other consensus tag (`MFBN-1/slashing-leaf`, `MFBN-1/validator-leaf`, `MFBN-1/bond-op-leaf`, `MFBN-1/merkle-leaf`, etc.) — a leaked storage-proof leaf cannot collide with a SPoRA chunk leaf, a Merkle interior node, or any other consensus message.
- **Empty-sibling case.** `p0`'s proof has `siblings.len() == 0`; the varint for length is the single byte `0x00`, and no `(sibling, right_side)` pairs follow. This pins the zero-sibling boundary case explicitly.
- **Mixed `right_side`.** `p1`'s `right_side = [true, false]` is deliberately *not* uniform — an encoder that mistakenly serialises `right_side` as a packed bitfield (instead of one `u8` per sibling) would fail this vector immediately.
