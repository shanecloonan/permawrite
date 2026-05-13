# M2.0.15 — `ChainState` checkpoint codec (`mfn-consensus::chain_checkpoint`)

> Deterministic, IO-free byte serialisation of the full `ChainState` —
> the primitive a full node uses to survive a restart.

## Motivation

After M2.0.13 the mempool admits storage-anchoring transactions; after
M2.0.14 the wallet builds them. The chain itself, however, still lives
**entirely in memory** — every full-node process loses its tip on
shutdown.

The single-node daemon (M2.1.0) **cannot ship** without a way to:

1. Snapshot the chain to disk on graceful shutdown.
2. Restore the same `ChainState` byte-for-byte on next boot.
3. Resume block production / sync / RPC at the exact previous tip.

M2.0.15 is the codec that makes that possible. It is intentionally
**not** the storage layer (no file IO, no RocksDB, no fsync semantics).
That belongs in M2.1.0, where the daemon decides where to put the
bytes. M2.0.15 only fixes *what* the bytes are and *who* can decode
them.

## Goals

- **Deterministic.** Two `ChainState` values that are semantically
  equal must encode to byte-identical output, regardless of
  `HashMap` insertion order or platform. This is what enables
  byte-for-byte cross-node consensus on checkpoint hashes (future
  fast-sync primitive).
- **Round-trip exact.** `decode(encode(s)) == s` for every reachable
  `ChainState`. Verified by both a synthetic-state test and a
  full-pipeline integration test that advances original + restored
  chains in lockstep through real BLS-signed blocks.
- **Strict on decode.** Bad magic, wrong version, integrity tampering,
  truncation, duplicate keys, out-of-order maps, and disagreement with
  local genesis all surface as **typed errors** — never as silent
  partial decodes.
- **Domain-separated from `LightCheckpoint`.** A light-client checkpoint
  byte stream fed to the full-node decoder must fail the integrity
  check, not silently decode part of the way through.
- **No persistence policy.** No file paths, no fsync, no on-disk
  rotation. The daemon owns those decisions. M2.0.15 hands it bytes.

## Architecture

The codec lives in `mfn-consensus`, alongside `ChainState`; the glue
that connects it to a running chain lives in `mfn-node::chain`. This
is the same layering as the light client: `mfn-light::checkpoint`
defines the codec, `mfn-light::LightChain` exposes
`encode_checkpoint` / `decode_checkpoint` on the driver.

```
┌──────────────────────────────────────────────────────────────────┐
│ mfn-node::chain                                                    │
│                                                                    │
│   Chain::checkpoint()       ─►  ChainCheckpoint                    │
│   Chain::encode_checkpoint()─►  Vec<u8>                            │
│   Chain::from_checkpoint(cfg, ChainCheckpoint)                     │
│   Chain::from_checkpoint_bytes(cfg, &[u8])                         │
│                                                                    │
│   ChainError::CheckpointDecode(ChainCheckpointError)               │
│   ChainError::GenesisMismatch { expected, got }                    │
└────────────────────┬───────────────────────────────────────────────┘
                     │ delegates byte layout to ↓
┌────────────────────▼───────────────────────────────────────────────┐
│ mfn-consensus::chain_checkpoint                                     │
│                                                                     │
│   ChainCheckpoint { genesis_id, state }                             │
│   encode_chain_checkpoint(&ChainCheckpoint) -> Vec<u8>              │
│   decode_chain_checkpoint(&[u8]) -> Result<ChainCheckpoint, …>      │
│   ChainCheckpointError { BadMagic, UnsupportedVersion, Truncated,   │
│       IntegrityCheckFailed, DuplicateValidatorIndex,                │
│       StatsLengthMismatch, NextIndexBelowAssigned, UtxoNotSorted,   │
│       StorageNotSorted, SpentKeyImagesNotSorted, … }                │
│                                                                     │
│   CHAIN_CHECKPOINT_MAGIC = b"MFCC"                                  │
│   CHAIN_CHECKPOINT_VERSION = 1                                      │
└────────────────────┬────────────────────────────────────────────────┘
                     │ uses ↓
┌────────────────────▼────────────────────────────────────────────────┐
│ mfn-crypto                                                           │
│                                                                      │
│   utxo_tree::encode_utxo_tree_state / decode_utxo_tree_state         │
│   domain::CHAIN_CHECKPOINT (b"MFBN-1/chain-checkpoint")              │
│   codec::Writer / codec::Reader                                      │
│   hash::dhash                                                        │
└──────────────────────────────────────────────────────────────────────┘
```

## Wire layout

```text
  magic                       [4]   "MFCC" (MoneyFund Chain Checkpoint)
  version                      u32   currently 1

  genesis_id                  [32]
  height_flag                   u8   0 = pre-genesis, 1 = present
  height                       u32   only if height_flag == 1

  block_ids.len()           varint
    block_ids[i]              [32]

  ConsensusParams            (4×u32 + 1×u64-of-f64-bits)
  BondingParams              (1×u64 + 4×u32)
  EmissionParams             (4×u64 + 1×u32 + 1×u16)
  EndowmentParams            (4×u64 + 2×u8 + 2×u64)

  treasury                    u128

  bond_counters              (1×u64 + 3×u32)

  validators.len()          varint
    validator                (4-byte index + 8-byte stake + 32-byte vrf_pk
                              + 48-byte bls_pk + 1-byte payout_flag
                              + optional 64-byte payout addr)

  validator_stats.len()     varint   (== validators.len)
    ValidatorStats           (1×u32 + 2×u64 + 1×u32)

  pending_unbonds.len()     varint
    PendingUnbond            (3×u32 + 1×u64)

  utxo.len()                varint   (sorted ascending by 32-byte key)
    key                       [32]
    UtxoEntry                (32-byte commit + u32 height)

  spent_key_images.len()    varint   (sorted ascending by 32-byte key)
    key                       [32]

  storage.len()             varint   (sorted ascending by 32-byte key)
    key                       [32]
    StorageEntry             (length-prefixed StorageCommitment
                              + u32 last_proven_height
                              + u64 last_proven_slot
                              + u128 pending_yield_ppb)

  utxo_tree                 varint    nested-blob length
                            bytes     encode_utxo_tree_state(...) output

  tag                        [32]    dhash(CHAIN_CHECKPOINT, &[payload])
```

### Why per-field choices

| Field | Choice | Rationale |
|-------|--------|-----------|
| `height` | `Option<u32>` (1-byte flag + optional u32) | Mirrors the in-memory shape exactly. Pre-genesis is a valid encodable state (used by the daemon between boot and `apply_genesis`). |
| `block_ids` | `Vec<[u8; 32]>` in iteration order | The chain history *is* the ordered list; preserving the vector order is the canonical history. |
| Hash maps (`utxo`, `spent_key_images`, `storage`) | Sorted by 32-byte key | Determinism — `HashMap` iteration is unspecified. |
| `validators` | `Vec` in iteration order | Index order is consensus-relevant (`validator_set_root` is Merkle-rooted over iteration order). |
| `validator_stats` | `Vec` in iteration order (length must equal validators) | Index-aligned with `validators` — the STF invariant the codec preserves. |
| `pending_unbonds` | `BTreeMap` iteration (ascending by key), strict-increasing on decode | Already canonical; strict-increase rule catches duplicates and decoder bugs. |
| `utxo_tree` | Length-prefixed nested `encode_utxo_tree_state` blob | Keeps the accumulator codec colocated with the type that owns it (`mfn-crypto::utxo_tree`). `zeros` chain is *not* serialised — it's regenerated from `UTXO_TREE_DEPTH` (saves ≈ 1 KB and removes a redundancy-check obligation). |
| `f64` (`expected_proposers_per_slot`) | `f64::to_bits()` → `u64` big-endian | Cross-platform exact (including NaN bit patterns + sub-normals). Mirrors the M2.0.9 `LightCheckpoint` convention exactly. |
| `u128` (`treasury`, `pending_yield_ppb`) | 16 bytes big-endian | No varint — the field is dense and BE makes manual hex inspection trivial. |
| Integrity tag | `dhash(CHAIN_CHECKPOINT, &[payload])` trailing 32 bytes | One flip detects truncation, payload tamper, *and* tag tamper. Domain-separated from `LIGHT_CHECKPOINT` (`MFBN-1/chain-checkpoint` vs `MFBN-1/light-checkpoint`). |

## Decode discipline

The decoder rejects, with a **typed error**, every form of malformed
input:

| Error variant | Trigger |
|----------------|---------|
| `BadMagic { got }` | First 4 bytes ≠ `"MFCC"`. |
| `UnsupportedVersion { got }` | Version field ≠ `CHAIN_CHECKPOINT_VERSION`. |
| `Truncated { field, needed }` | Reader ran out of bytes mid-field. |
| `VarintOverflow { field }` | A length-prefix varint exceeded `u64`. |
| `LengthOverflow { got, field }` | A `u64` length didn't fit `usize`. |
| `InvalidHeightFlag { flag }` | `height_flag` was not 0 or 1. |
| `StatsLengthMismatch { validators, stats }` | Validator-stats length ≠ validators length. |
| `DuplicateValidatorIndex { index }` | Two validators sharing an `index`. |
| `NextIndexBelowAssigned { next, max_assigned }` | `next_validator_index` ≤ any present index. |
| `InvalidVrfPublicKey { index }` | A validator's `vrf_pk` failed Edwards-point decompression. |
| `InvalidBlsPublicKey { index, source }` | A validator's `bls_pk` failed G1 decode. |
| `InvalidPayoutViewPub { index }` / `InvalidPayoutSpendPub { index }` | A validator-payout point failed decompression. |
| `InvalidPayoutFlag { index, flag }` | Payout-presence flag was not 0 or 1. |
| `PendingUnbondsNotSorted { index }` | Pending unbonds not strictly ascending. |
| `UtxoNotSorted { index }` | UTXO map entries not strictly ascending. |
| `InvalidUtxoCommit { index }` | A UTXO's amount commitment failed decompression. |
| `SpentKeyImagesNotSorted { index }` | Spent-key-image set not strictly ascending. |
| `StorageNotSorted { index }` | Storage map entries not strictly ascending. |
| `InvalidStorageCommitment { index, source }` | A `StorageCommitment` failed structural decode. |
| `InvalidUtxoTree { source }` | The nested `utxo_tree` blob failed decode. |
| `IntegrityCheckFailed` | Trailing 32-byte tag didn't match `dhash(CHAIN_CHECKPOINT, &[payload])`. |
| `TrailingBytes { remaining }` | Bytes remained after a successful payload decode (reserved — most trailing-byte cases trip `IntegrityCheckFailed` first). |

## Driver glue (`mfn-node::Chain`)

```rust
pub fn checkpoint(&self) -> ChainCheckpoint;             // → owned bundle
pub fn encode_checkpoint(&self) -> Vec<u8>;              // → canonical bytes

pub fn from_checkpoint(cfg: ChainConfig, ck: ChainCheckpoint)
        -> Result<Self, ChainError>;
pub fn from_checkpoint_bytes(cfg: ChainConfig, bytes: &[u8])
        -> Result<Self, ChainError>;
```

`Chain::from_checkpoint*` re-derives the **local** `genesis_id` from
the caller-supplied `ChainConfig` and compares it byte-for-byte
against the checkpoint's `genesis_id`. Disagreement surfaces as
`ChainError::GenesisMismatch { expected, got }` — restoring with the
wrong genesis would silently swap the daemon onto a foreign chain.

`Chain::from_checkpoint_bytes` additionally surfaces decode failures
via `ChainError::CheckpointDecode(ChainCheckpointError)`.

## Test matrix

`mfn-crypto::utxo_tree` (9 new tests, brings utxo_tree to 25 total):

- `utxo_tree_codec_empty_round_trip` — empty tree round-trips.
- `utxo_tree_codec_many_leaves_round_trip` — 16-leaf tree round-trips; membership proofs match leaf-for-leaf against the restored root.
- `utxo_tree_codec_is_deterministic_independent_of_append_order` — two equivalent histories encode to identical bytes.
- `utxo_tree_codec_rejects_truncation` — every prefix of a valid blob fails decode.
- `utxo_tree_codec_rejects_trailing_bytes` — `TrailingBytes`.
- `utxo_tree_codec_rejects_unsorted_nodes` — strict-ascending key constraint.
- `utxo_tree_codec_rejects_depth_out_of_range` — `depth > UTXO_TREE_DEPTH`.
- `utxo_tree_codec_rejects_leaf_count_above_capacity` — `leaf_count > 2^32`.

`mfn-consensus::chain_checkpoint` (13 new tests):

- `pre_genesis_round_trip` — pre-genesis state (no height, empty maps).
- `rich_round_trip_preserves_every_field` — non-trivial state with 3 validators (mixed payouts), 1 pending unbond, 10 UTXOs, 5 spent key images, 4 storage anchors, populated `utxo_tree`; round-trips field-by-field + re-encoding determinism.
- `encode_is_independent_of_hashmap_iteration_order` — same logical state, inverse insertion order → identical bytes.
- `rejects_bad_magic` — flipped magic + recomputed tag → `BadMagic`.
- `rejects_unsupported_version` — version 9 → `UnsupportedVersion`.
- `detects_payload_tamper` — single-byte flip → `IntegrityCheckFailed`.
- `detects_tag_tamper` — flipped tag → `IntegrityCheckFailed`.
- `rejects_truncated_below_minimum` — < 40-byte payload → `Truncated`.
- `rejects_duplicate_validator_index` — `DuplicateValidatorIndex`.
- `rejects_stats_validators_mismatch` — `StatsLengthMismatch`.
- `rejects_next_index_at_or_below_max_assigned` — `NextIndexBelowAssigned`.
- `rejects_trailing_bytes_after_tag` — surfaces as `IntegrityCheckFailed` (every byte before the tag is part of the integrity-checked payload by definition).
- `light_checkpoint_bytes_fail_chain_decode` — bytes starting with `"MFLC"` magic fail the chain-checkpoint integrity check; the two codec families are fully domain-separated.

`mfn-node::chain` (5 new tests):

- `checkpoint_round_trip_at_genesis` — round-trip at height 0.
- `checkpoint_after_three_blocks_round_trips` — empty 3-block chain round-trips; original + restored both advance on the same block 4 to identical state.
- `from_checkpoint_rejects_foreign_genesis` — `GenesisMismatch` when the caller's genesis differs.
- `from_checkpoint_bytes_rejects_tamper` — payload tamper → `CheckpointDecode(IntegrityCheckFailed)`.

`mfn-node/tests/chain_checkpoint_integration.rs` (3 new integration tests):

- `checkpoint_round_trip_after_three_real_blocks_advances_in_lockstep` — drives the full producer pipeline: 3 real BLS-signed blocks with coinbase emission + validator stats, checkpoint, decode, then both chains accept an identical block 4 and end at byte-identical state.
- `encode_checkpoint_is_deterministic_on_non_trivial_chain` — re-encoding a non-trivial chain twice yields identical bytes.
- `from_checkpoint_rejects_foreign_genesis_through_real_chain` — `GenesisMismatch` on a non-trivial chain.

## Scope decisions — what M2.0.15 explicitly does **not** do

- **No file IO.** The codec is `&[u8] ↔ Vec<u8>`. M2.1.0 later added the first daemon-side file snapshot store (`mfn_node::ChainStore`); richer sled / RocksDB layouts remain future work.
- **No incremental persistence.** Encoder produces a full snapshot per call. A future M2.x can add delta/block-log persistence; the snapshot codec is the safety net that bounds replay cost in either case.
- **M2.0.16 follow-up completed.** M2.0.15 intentionally shipped with duplicated light/full-node sub-encoders to avoid broadening the persistence milestone. M2.0.16 subsequently lifted those shared pieces into `mfn_consensus::checkpoint_codec` (`Validator`, `ValidatorStats`, `PendingUnbond`, `ConsensusParams`, `BondingParams`, plus `CheckpointReadError` and assignment-invariant checks). The checkpoint v1 wire bytes are unchanged; only the Rust ownership of the helpers changed.
- **No `mfn-store` crate.** That naming is reserved for the future RocksDB/sled backend that consumes this codec.

## What this milestone unlocks

- **M2.1.0 single-node daemon.** Boot path: read snapshot from disk (or run genesis); shutdown path: encode + atomic-write. No more "chain dies with the process."
- **State-root-consistent fast sync.** Two nodes that have applied the same blocks produce byte-identical encoded checkpoints; their `dhash(CHAIN_CHECKPOINT, &[payload])` is a *checkpoint root* a future fast-sync RPC can verify against the network.
- **Long-running test harnesses.** Existing integration tests can now snapshot mid-run and resume, enabling chaos / restart-style tests in a future milestone.
- **Debuggability.** A faulty chain can be encoded and diffed against a known-good twin byte-by-byte; the typed decode errors localise drift to a single field name.

## API surface

Public re-exports from `mfn-consensus`:

- `ChainCheckpoint`, `ChainCheckpointError`.
- `encode_chain_checkpoint`, `decode_chain_checkpoint`.
- `CHAIN_CHECKPOINT_MAGIC`, `CHAIN_CHECKPOINT_VERSION`.

Public re-exports from `mfn-crypto`:

- `encode_utxo_tree_state`, `decode_utxo_tree_state`, `UtxoTreeDecodeError`.
- `UtxoTreeState::nodes_iter`, `UtxoTreeState::from_parts` (codec accessors).

New `ChainError` variants in `mfn-node`:

- `CheckpointDecode(ChainCheckpointError)`.
- `GenesisMismatch { expected, got }`.

New `Chain` methods in `mfn-node`:

- `checkpoint`, `encode_checkpoint`, `from_checkpoint`, `from_checkpoint_bytes`.

New domain tag in `mfn-crypto`:

- `domain::CHAIN_CHECKPOINT = b"MFBN-1/chain-checkpoint"`.
