# TypeScript reference — validator-set commitment golden vectors

This file pins the canonical bytes and hashes for the M2.0 validator-set commitment so the Rust and TypeScript implementations stay byte-for-byte identical. Both reference vectors are deterministic — same seed inputs, same bytes, every time — and asserted in `mfn-consensus` unit tests. Any drift here is a consensus-breaking change.

For the protocol-level rationale see [`docs/M2_VALIDATOR_ROOT.md`](../M2_VALIDATOR_ROOT.md) and [`docs/CONSENSUS.md § Validator-set commitment in the header`](../CONSENSUS.md).

## Canonical leaf encoding

```text
dhash(MFBN-1/validator-leaf,
      index(u32, BE) ‖ stake(u64, BE)
   ‖  vrf_pk(32) ‖ bls_pk(48)
   ‖  payout_flag(u8) ‖ [view_pub(32) ‖ spend_pub(32)]?)
```

Leaf length:
- **93 bytes** with `payout = None`
- **157 bytes** with `payout = Some(_)`

## Inputs (deterministic)

The same fixture is exercised at every consensus layer that touches the commitment, including the root over a two-validator set so the TS port can validate Merkle combination semantics in one shot.

| Validator | Field | Value |
|---|---|---|
| **v0** | `index` | `0` |
| | `stake` | `1_000_000` (`u64`, big-endian) |
| | `vrf_pk` | `vrf_keygen_from_seed([1; 32]).pk` (32 bytes) |
| | `bls_pk` | `bls_keygen_from_seed([101; 32]).pk` (48 bytes, BLS12-381 G1, compressed) |
| | `payout` | `None` |
| **v1** | `index` | `1` |
| | `stake` | `2_000_000` (`u64`, big-endian) |
| | `vrf_pk` | `vrf_keygen_from_seed([2; 32]).pk` |
| | `bls_pk` | `bls_keygen_from_seed([102; 32]).pk` |
| | `payout.view_pub` | `3 · G` (Ed25519 generator multiplied by scalar 3) |
| | `payout.spend_pub` | `5 · G` |

## Reference bytes

### v0 (no payout)

| Field | Hex |
|-------|-----|
| `validator_leaf_bytes(v0)` (93 bytes) | `0000000000000000000f42408a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5cb5a05f6d4ac7b5906f838f775da2c17d3b1f77aead8860b10922e816fb7419541642a9f70f2c101600554d315a8f6c5900` |
| `validator_leaf_hash(v0)` (32 bytes) | `00c034ee4366815b9dc13f4769e47090a86a5ab7f355477e67135fa7f958b605` |

### v1 (with payout)

| Field | Hex |
|-------|-----|
| `validator_leaf_bytes(v1)` (157 bytes) | `0000000100000000001e84808139770ea87d175f56a35466c34c7ecccb8d8a91b4ee37a25df60f5b8fc9b394ae5765f8aa19f64c622783fe27b225cb75d79b03c69178cc73e8f72ada2814436f9161cba5489be72448779e9786325001d4b4f5784868c3020403246717ec169ff79e26608ea126a1ab69ee77d1b16712edc876d6831fd2105d0b4389ca2e283166469289146e2ce06faefe98b22548df` |
| `validator_leaf_hash(v1)` (32 bytes) | `ee082d7d2df87805f7bc2058d87de8f149832bfedb8df11f3b66752d6af674c0` |

### Root over `[v0, v1]`

| Field | Hex |
|-------|-----|
| `validator_set_root([v0, v1])` (32 bytes) | `dad4793fd4c01fc2710792e5fe4afb5391b701f6ad3f884d7515c7f04d1445a7` |

The root is computed by the binary Merkle root over the leaf hashes (in canonical index order), using [`mfn-crypto::merkle::merkle_root_or_zero`](../../mfn-crypto/src/merkle.rs) — the same combinator that powers `tx_root`, `bond_root`, and `storage_root`. The empty set folds to the all-zero 32-byte sentinel, matching the other consensus roots.

## Wire / hashing structure

```
validator_leaf_bytes(v) =
    index           u32, big-endian
  ‖ stake           u64, big-endian
  ‖ vrf_pk          32 bytes (compressed Edwards point)
  ‖ bls_pk          48 bytes (compressed BLS12-381 G1)
  ‖ payout_flag     u8 (0 = no payout, 1 = payout follows)
  ‖ [view_pub       32 bytes (compressed Edwards point)]?
  ‖ [spend_pub      32 bytes (compressed Edwards point)]?

validator_leaf_hash(v) = dhash(MFBN-1/validator-leaf, validator_leaf_bytes(v))

validator_set_root(vs) = if vs.is_empty() { [0u8; 32] } else { binary_merkle(leaf_hashes(vs)) }
```

## Rust assertion

`consensus::tests::validator_root_wire_matches_cloonan_ts_smoke_reference` in `mfn-consensus`. The test asserts every line of the table above and also pins the canonical encoding length for both branches.

## Notes

- **`ValidatorStats` is intentionally excluded.** Liveness counters churn every block; reincluding them would force a re-hash of every leaf on otherwise-idle blocks. Light clients verifying a finality bitmap need `(index, stake, bls_pk)`; the other fields round out the canonical record for completeness.
- **Pre-block commitment.** Every header commits to the validator set the block was *produced against* (i.e., the set Phase 0's producer-proof + finality bitmap are verified against). Any rotation / slashing / unbond settlement applied *by* this block moves the **next** header's `validator_root`. Genesis header commits the all-zero sentinel; block at height 1 commits `validator_set_root(&cfg.validators)`.
- **Domain separation.** `MFBN-1/validator-leaf` is distinct from every other consensus dhash tag (`MFBN-1/bond-op-leaf`, `MFBN-1/register-op-sig`, `MFBN-1/unbond-op-sig`, `MFBN-1/utxo-leaf`, etc.) — a leaked leaf cannot collide with any other consensus message.
