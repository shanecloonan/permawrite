# TypeScript reference — slashing-root commitment golden vectors

This file pins the canonical bytes and hashes for the M2.0.1 slashing-evidence commitment so the Rust and TypeScript implementations stay byte-for-byte identical. The vector is deterministic — same seed inputs, same bytes, every time — and asserted in `mfn-consensus` unit tests. Any drift here is a consensus-breaking change.

For the protocol-level rationale see [`docs/ROADMAP.md § Milestone M2.0.1`](../ROADMAP.md) and [`docs/CONSENSUS.md § Slashing-evidence commitment`](../CONSENSUS.md).

## Canonical leaf encoding

```text
dhash(MFBN-1/slashing-leaf, encode_evidence(canonicalize(e)))
```

Where `canonicalize(e)` orders the conflicting `(header_hash_a, sig_a)` / `(header_hash_b, sig_b)` pair lexicographically by hash before encoding. Two reorderings of the same equivocation therefore hash to the same leaf — pair-swap tampering is structurally impossible.

`encode_evidence(e)` lays out the canonicalized struct as:

```text
height(u32, BE)
‖ slot(u32, BE)
‖ voter_index(u32, BE)
‖ header_hash_a(32)
‖ sig_a(96, BLS12-381 G2 compressed)
‖ header_hash_b(32)
‖ sig_b(96)
```

## Inputs (deterministic)

Two pieces of evidence under a shared keypair so the TS port can validate the same hash function across both branches of `canonicalize()`:

| Evidence | Field | Value |
|---|---|---|
| **shared** | `bls_keypair` | `bls_keygen_from_seed([1, 2, …, 48])` — same convention as `BondOp::{Register, Unbond}` |
| **e0 (no-swap branch)** | `height` | `10` |
| | `slot` | `11` |
| | `voter_index` | `7` |
| | `header_hash_a` | `[0xaa; 32]` |
| | `header_hash_b` | `[0xbb; 32]` |
| | order? | `a < b` already → `canonicalize` is a no-op |
| **e1 (swap branch)** | `height` | `12` |
| | `slot` | `13` |
| | `voter_index` | `8` |
| | `header_hash_a` | `[0xee; 32]` |
| | `header_hash_b` | `[0xcc; 32]` |
| | order? | `a > b` → `canonicalize` swaps the pair before hashing |

Both signatures are computed against the original `(header_hash_a, header_hash_b)` of the *unswapped* `SlashEvidence`; `canonicalize()` moves them along with the hashes.

## Reference bytes

| Field | Hex |
|-------|-----|
| `slashing_leaf_hash(e0)` (32 bytes) | `e58150a4f83124653f2d2ad1a54274fa5c3410dfaac3278df7c03d1db24141aa` |
| `slashing_leaf_hash(e1)` (32 bytes) | `d400dc0d29f652537d0fead9d400b2774fa6fde6c9f586067e5aab781a2a14d5` |
| `slashing_merkle_root([e0, e1])` (32 bytes) | `24670a15fe826c64880104caf7ca5a86c48e7532a40e5271d1b40d0198206480` |

The root is computed by the binary Merkle root over the leaf hashes in **producer-emit order** (not lexicographic), using [`mfn-crypto::merkle::merkle_root_or_zero`](../../mfn-crypto/src/merkle.rs). Empty list folds to the all-zero sentinel.

## Wire / hashing structure

```
slashing_leaf_hash(e) = dhash(MFBN-1/slashing-leaf, encode_evidence(canonicalize(e)))

slashing_merkle_root(evs) = if evs.is_empty() { [0u8; 32] }
                            else { binary_merkle(evs.map(slashing_leaf_hash)) }
```

## Rust assertion

`slashing::tests::slashing_root_wire_matches_cloonan_ts_smoke_reference` in `mfn-consensus`.

## Notes

- **Pair-order canonicalization is internal to the leaf.** Across distinct evidence pieces, the producer's emit order is committed — sorting across the list would force the block applier to re-sort just to verify the header.
- **Why canonicalize?** Without it, an adversarial producer could flip the pair ordering of a single evidence piece to produce a different `slashing_root` without changing what is being slashed. With it, the root is invariant under pair-swap and a light client doesn't have to guess which ordering the producer used.
- **Domain separation.** `MFBN-1/slashing-leaf` is distinct from every other consensus tag (`MFBN-1/bond-op-leaf`, `MFBN-1/validator-leaf`, `MFBN-1/register-op-sig`, `MFBN-1/unbond-op-sig`, etc.) — a leaked slashing leaf cannot collide with any other consensus message.
- **Same seed family.** The `[1..=48]` keygen seed is the canonical TS smoke fixture across `BondOp::Register`, `BondOp::Unbond`, and `SlashEvidence` — one keypair, all three vectors.
