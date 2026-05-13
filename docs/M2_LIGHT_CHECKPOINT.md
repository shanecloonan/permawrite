# Milestone M2.0.9 — Canonical header codec + LightChain checkpoint

> **Status:** ✓ Shipped. Tests: 440 passing (workspace), 1 ignored.
> Code:
> - `mfn-crypto/src/domain.rs` — new `LIGHT_CHECKPOINT` domain tag.
> - `mfn-consensus/src/block.rs` — `decode_block_header`, `HeaderDecodeError`.
> - `mfn-light/src/checkpoint.rs` (new module) — `LightCheckpointError`,
>   `LIGHT_CHECKPOINT_MAGIC`, `LIGHT_CHECKPOINT_VERSION`,
>   `CheckpointParts`, `encode_checkpoint_bytes`, `decode_checkpoint_bytes`.
> - `mfn-light/src/chain.rs` — `LightChain::encode_checkpoint`,
>   `LightChain::decode_checkpoint`.

## TL;DR

After M2.0.8 a light client can follow the chain indefinitely from a
single genesis bootstrap. **M2.0.9 makes a light client survive a
restart** — without re-fetching, re-verifying, or re-evolving every
header from height 0.

Two related pieces ship together:

1. **`BlockHeader` wire codec is now round-trippable.** Until now
   `mfn-consensus::block_header_bytes` only encoded a header (for hashing
   under `BLOCK_ID` / for BLS signing). M2.0.9 adds the inverse,
   `decode_block_header`, and proves the codec has no dead bytes via
   property tests. This is foundation for every wire-format consumer
   that needs to *receive* a header — P2P "Headers" messages, RPC,
   inclusion proofs, dump-and-replay tooling.

2. **`LightChain` checkpoint serialization.** `LightChain::encode_checkpoint`
   produces a self-contained binary blob carrying every byte of the
   light chain's observable state: tip identity, genesis identity,
   consensus + bonding params, the trusted validator set, per-validator
   liveness stats, the in-flight unbond queue, and the four bond-epoch
   counters. `LightChain::decode_checkpoint` is the inverse: the
   restored chain accepts the next block exactly like the original
   would have. A trailing 32-byte `dhash(LIGHT_CHECKPOINT, payload)`
   tag makes tampering detectable.

## Why this matters for the project's goals

Permawrite's privacy + permanence promise hinges on **anyone, anywhere,
being able to verify the chain** — including resource-constrained
clients that go offline and come back hours or days later. A light
client that has to replay from genesis on every cold start isn't
practical for:

- **Mobile + browser wallets** that need to resume in milliseconds.
- **Embedded clients** with bounded compute + storage budgets.
- **Federated archival / index nodes** that want
  content-addressable snapshots they can ship to peers.
- **Disaster recovery** — operators want to pin a known-good light
  state to disk so a crash never costs them re-verification time.

M2.0.9 makes all four scenarios work. The same `decode_block_header`
plumbing also unblocks the next milestone slice: real-network P2P
header propagation.

## Architecture

### Header codec — `mfn-consensus::block`

The existing `block_header_bytes` encoder remains the canonical
encoding (it's used to derive `block_id` and as the BLS-signing
preimage — both consensus-critical). M2.0.9 adds the inverse:

```rust
pub fn decode_block_header(bytes: &[u8]) -> Result<BlockHeader, HeaderDecodeError>;

pub enum HeaderDecodeError {
    Truncated { field: &'static str, needed: usize },
    VarintOverflow { field: &'static str },
    VersionOutOfRange { got: u64 },
    ProducerProofTooLarge { got: u64 },
    TrailingBytes { remaining: usize },
}
```

Contract:

- `decode_block_header(&block_header_bytes(h)) == Ok(h)` byte-for-byte.
- Trailing bytes are a hard reject (headers are self-delimiting; a
  non-empty tail is a framing bug, never a benign forward-compat
  signal).
- The "no dead bytes" property test flips every byte in a real
  encoded header and confirms either a decode rejection or a
  materially-different `block_id`.

### LightChain checkpoint — `mfn-light::checkpoint`

A *checkpoint* is the small amount of state a `LightChain` carries
that is not derivable from headers + the original genesis: tip
pointer, the four bond-epoch counters, per-validator liveness stats,
the pending-unbond queue. Plus the chain's "identity" fields
(`genesis_id`) and "frozen-at-genesis" params (`ConsensusParams`,
`BondingParams`). Plus the trusted validator set itself.

**Single-codec design**: a free-function pair
(`encode_checkpoint_bytes` / `decode_checkpoint_bytes`) operates on a
public `CheckpointParts` bundle, and the `LightChain` exposes thin
methods (`encode_checkpoint`, `decode_checkpoint`) that marshal its
private state through `CheckpointParts`. Two wins:

- The codec is testable independently of the `LightChain` (the
  `checkpoint::tests` module exercises edge cases without spinning
  up a real chain — fast, deterministic).
- `CheckpointParts` is a stable boundary type for future
  consumers — e.g. a future `mfn-checkpointer` daemon that wants
  to inspect / cross-validate checkpoints without holding a
  `LightChain` instance.

### Wire layout (format version 1)

Big-endian everywhere. `varint` is LEB128 matching `mfn-crypto`'s
canonical codec.

```text
magic          : 4 bytes = b"MFLC"
version        : u32 (currently 1)
tip_height     : u32
tip_id         : [u8; 32]
genesis_id     : [u8; 32]
params:
  expected_proposers_per_slot : u64 (f64::to_bits)
  quorum_stake_bps            : u32
  liveness_max_consecutive_missed : u32
  liveness_slash_bps          : u32
bonding_params:
  min_validator_stake        : u64
  unbond_delay_heights       : u32
  max_entry_churn_per_epoch  : u32
  max_exit_churn_per_epoch   : u32
  slots_per_epoch            : u32
validators: varint N
  repeated N times:
    index   : u32
    stake   : u64
    vrf_pk  : 32 bytes (compressed ed25519)
    bls_pk  : 48 bytes (BLS G1 compressed)
    payout_flag : u8 (0 = None, 1 = Some)
    if Some:
      view_pub  : 32 bytes
      spend_pub : 32 bytes
validator_stats: varint N      -- MUST equal validators count
  repeated N times:
    consecutive_missed : u32
    total_signed       : u64
    total_missed       : u64
    liveness_slashes   : u32
pending_unbonds: varint M      -- ascending `validator_index`
  repeated M times:
    validator_index   : u32
    unlock_height     : u32
    stake_at_request  : u64
    request_height    : u32
bond_counters:
  bond_epoch_id           : u64
  bond_epoch_entry_count  : u32
  bond_epoch_exit_count   : u32
  next_validator_index    : u32
checksum : 32 bytes = dhash(LIGHT_CHECKPOINT, all bytes above)
```

#### f64 encoding

The single non-integer field is `ConsensusParams::expected_proposers_per_slot`.
It's encoded as `f64::to_bits()` → big-endian u64. `f64::from_bits`
reconstructs the exact bit pattern (verified by the
`checkpoint_f64_bits_round_trip` test — including NaN, ±∞,
subnormals, and π). The consensus-critical computation
(`eligibility_threshold`) already discretises `f64 → u64` via a
`floor(f * 2^30)` fixed-point reduction, so the f64 itself isn't
load-bearing for chain identity — but byte-exact round-trip is the
right contract for any deterministic codec.

#### Integrity tag

The trailing 32 bytes are `dhash(LIGHT_CHECKPOINT, &[payload])` where
payload = every byte from `magic` through `bond_counters` inclusive.
Decode verifies this tag *first* (before any field-level parsing) so
arbitrary corruption surfaces as a single typed error
(`IntegrityCheckFailed`) rather than as a misleading mid-decode panic.

The domain tag (`MFBN-1/light-checkpoint`) is dedicated so a
tampered payload cannot be made to collide with any other hash in
the protocol — including `BLOCK_ID`, `TX_ID`, or any of the Merkle
leaf domain tags.

### Cross-field invariants enforced on decode

Beyond raw bytes-in / bytes-out, the decoder enforces every
invariant the encoder upholds:

1. **`validator_stats.len() == validators.len()`** —
   `StatsLengthMismatch`. The in-memory invariant is 1:1; honest
   encoders can't violate it.
2. **No duplicate `validator.index`** — `DuplicateValidatorIndex`.
   The chain enforces unique indices.
3. **`pending_unbonds` strictly ascending by `validator_index`**,
   and each entry's stored `validator_index` matches its key —
   `PendingUnbondsNotSorted` / `PendingUnbondIndexMismatch`. Honest
   encoders walk a `BTreeMap` in ascending order; this guarantees a
   single canonical encoding per chain state.
4. **`bond_counters.next_validator_index > max(validator.index)`** —
   `NextIndexBelowAssigned`. The chain only ever monotonically
   advances `next_validator_index`; an old checkpoint can't masquerade
   as a newer one with conflicting state.

Any single byte flipped inside the payload is also caught by the
trailing tag (which dominates the byte-level checks above on a
per-byte basis), so the in-decoder invariant checks are a
defence-in-depth layer for callers who chose to verify the tag
separately (e.g. validators with a fast-path content-addressable
storage layer that already hashed the payload upstream).

## Tests

### `mfn-consensus` (7 new unit tests in `block::tests`)

- `block_header_codec_round_trip` — encode→decode equality.
- `block_header_codec_round_trip_empty_producer_proof` — genesis /
  no-validator chains.
- `block_header_codec_rejects_truncation` — every prefix of a valid
  encoding fails.
- `block_header_codec_rejects_trailing_bytes` — non-empty tail
  rejected.
- `block_header_codec_rejects_oversized_version` — `version > u32::MAX`.
- `block_header_codec_has_no_dead_bytes` — single-byte tamper either
  fails decode or materially changes `block_id`.
- `block_header_codec_golden_vector` — fixed input → pinned 274-byte
  output (TS-parity vector for the genesis-shaped header).

### `mfn-light::checkpoint` (13 new unit tests)

- `checkpoint_empty_round_trips` — degenerate empty case.
- `checkpoint_round_trip_with_validators_and_pending` — full surface.
- `checkpoint_f64_bits_round_trip` — exhaustive f64 edge cases
  (including NaN, ±∞, subnormals, π).
- `checkpoint_rejects_bad_magic` — typed `BadMagic`.
- `checkpoint_rejects_unknown_version` — typed `UnsupportedVersion`.
- `checkpoint_detects_payload_tamper_via_integrity_tag` — any inner
  byte flip → `IntegrityCheckFailed`.
- `checkpoint_detects_tag_tamper` — flipping the tag itself →
  `IntegrityCheckFailed`.
- `checkpoint_rejects_truncation_before_minimum_length`.
- `checkpoint_rejects_duplicate_validator_indices` →
  `DuplicateValidatorIndex`.
- `checkpoint_rejects_next_index_at_or_below_max_assigned` →
  `NextIndexBelowAssigned`.
- `checkpoint_rejects_invalid_bls_pk` — typed `InvalidBlsPublicKey`.
- `checkpoint_rejects_invalid_payout_flag` — typed `InvalidPayoutFlag`.
- `checkpoint_size_grows_linearly` — guards against quadratic codec
  surprises.

### `mfn-light::chain` (5 new unit tests)

- `checkpoint_round_trips_at_genesis` — fresh-from-genesis LightChain.
- `checkpoint_resumes_chain_after_apply_block` — apply 3 blocks,
  snapshot, restore, continue. Restored chain accepts block 4 with
  the same `AppliedBlock` outcome as the live chain.
- `checkpoint_decode_rejects_any_single_byte_tamper` — broader
  property scan across the encoded blob.
- `checkpoint_decode_preserves_all_public_accessors` — every public
  accessor matches across the round-trip, including the
  canonical `validator_set_root`.
- `checkpoint_encoded_length_is_deterministic_and_state_sensitive` —
  same chain → same bytes; different chain → different bytes.

### `mfn-light::tests::follow_chain` (3 new integration tests)

- `light_chain_checkpoint_round_trips_mid_chain_and_resumes` —
  **the headline.** Two parallel `LightChain` instances follow a
  real `Chain` for 2 blocks. One gets snapshotted to bytes and
  restored. Both then follow the chain for 3 more blocks. At every
  block the `AppliedBlock` outcome, tip, validator stats,
  bond-counters, and validator-set root agree byte-for-byte.
- `light_chain_checkpoint_integrity_detects_real_tamper` — end-to-end
  variant of the integrity-tag test using a real evolved chain.
- `light_chain_checkpoint_carries_genesis_id` — checkpoints round-trip
  the chain identity for "what chain is this?" callers.

## Out of scope for M2.0.9

Each of these is its own clean follow-on slice:

- **Full `Block` codec (`encode_block` / `decode_block`).** Requires
  a `TransactionWire` round-trip codec (CLSAG sigs +
  bulletproofs decode), which is its own non-trivial slice. The
  M2.0.9 header codec is already enough for header-only sync.
- **Persistent storage adapter for checkpoints.** This crate
  produces bytes; whether a caller writes them to disk / S3 /
  IPFS / Arweave is intentionally outside `mfn-light`'s remit.
- **Multi-version codec.** Today version 1 is the only known
  version. When we bump it (e.g. to add a new shadow field), the
  decode switch on `version` is the natural extension point.
- **TS reference port.** The TS reference doesn't carry a
  light-client today; the checkpoint format is Rust-only. When TS
  catches up, this doc's wire-layout section is the spec.

## What's next

M2.0.10 candidate: **`TransactionWire` round-trip codec** —
followed by full `Block::encode` / `Block::decode`, unblocking the
first real P2P "Block" message and end-to-end snapshot+replay of
arbitrary blocks. After that: M2.1 single-node tx-pool +
networking surface.
