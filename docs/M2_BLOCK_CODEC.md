# M2.0.10 — Canonical Transaction + Full-Block Codec

## Purpose

M2.0.9 made headers and light-client checkpoints byte-deterministic. M2.0.10 extends that property to finalized blocks. A `Block` now has a canonical, self-delimiting wire form that can be used for P2P gossip, disk persistence, RPC archival responses, and raw-byte light-client sync.

The key invariant:

```text
decode_block(encode_block(block)) == block'
encode_block(block') == encode_block(block)
block_id(block'.header) == block_id(block.header)
```

Consensus verification remains separate: decoding proves that bytes are structurally canonical; `verify_header`, `verify_block_body`, and `apply_block` prove that the block is valid.

## Wire layout

```text
block_header_bytes(header)
varint(txs.len)             || blob(encode_transaction(tx))*
varint(bond_ops.len)        || blob(encode_bond_op(op))*
varint(slashings.len)       || blob(encode_evidence(evidence))*
varint(storage_proofs.len)  || blob(encode_storage_proof(proof))*
```

The body order matches the root order verified by `verify_block_body`:

1. `tx_root`
2. `bond_root`
3. `slashing_root`
4. `storage_proof_root`

Each body element is wrapped in `blob(...)` even when its inner codec is self-delimiting. That gives the outer decoder a hard item boundary and lets future codec versions extend an item without confusing the surrounding block frame.

## Transaction codec

`encode_transaction` is lossless over `TransactionWire`:

```text
varint(version)
point(r_pub)
u64(fee)
blob(extra)
varint(inputs.len)
for each input:
  points(ring.p)
  points(ring.c)
  point(c_pseudo)
  blob(encode_clsag(sig))
varint(outputs.len)
for each output:
  point(one_time_addr)
  point(amount)
  blob(encode_bulletproof(range_proof))
  enc_amount[40]
  u8(storage_flag)
  if storage_flag == 1:
    blob(encode_storage_commitment(commitment))
```

The tx preimage remains unchanged: it still hashes the storage commitment hash, not the full commitment bytes. The new transaction codec carries the full `StorageCommitment` so the decoded transaction can be verified, applied, and re-encoded without losing information.

## Strictness

Decoders are intentionally strict:

- `decode_block_header` rejects any trailing bytes.
- `decode_transaction` rejects trailing bytes, invalid storage flags, mismatched CLSAG ring columns, and non-canonical nested CLSAG / Bulletproof blobs.
- `decode_storage_commitment` rejects trailing bytes.
- `decode_evidence` rejects trailing bytes.
- `decode_storage_proof` rejects trailing bytes and Merkle sibling-side flags outside `0` / `1`.
- `decode_block` rejects trailing bytes after the final storage-proof section.

This prevents two byte strings from representing the same logical object, which is essential for cross-implementation parity and safe content-addressed persistence.

## Allocation-hardening

Outer block section counts are peer-controlled. The decoder therefore does not allocate `Vec::with_capacity(declared_count)`. It grows vectors only as each length-prefixed item is successfully read. A malicious payload claiming `u64::MAX` transactions fails as a codec error against the finite buffer instead of causing a capacity overflow or process abort.

## Test matrix

- `mfn-storage::commitment`:
  - full round-trip
  - fixed 81-byte shape
  - every-prefix truncation rejection
  - trailing-byte rejection
  - hash preservation after decode
- `mfn-consensus::transaction`:
  - simple tx round-trip
  - multi-input storage-bearing tx round-trip
  - raw-output tx round-trip
  - every-prefix truncation rejection
  - trailing-byte rejection
  - invalid storage-flag rejection
  - exact storage-commitment preservation
- `mfn-consensus::block`:
  - empty-body block round-trip
  - block bytes start with `block_header_bytes(header)`
  - trailing-byte rejection
  - every-prefix truncation rejection
  - huge tx-count allocation-hardening
  - 278-byte empty-body golden shape
- `mfn-light::tests::follow_chain`:
  - real BLS-signed blocks encode → decode → apply to `mfn-node::Chain` and `LightChain::apply_block` with identical tips
  - real block bytes reject appended garbage

## What this unlocks

- P2P `Block` messages with a consensus-defined byte payload.
- Disk storage of canonical block bytes.
- RPC endpoints that serve verifiable raw blocks.
- Light clients that consume raw bytes from peers instead of trusted in-memory structs.
