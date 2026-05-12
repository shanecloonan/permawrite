//! Domain-separation tags (MFBN-1).
//!
//! Every hash in the protocol is prefixed with one of these tags so that an
//! attacker cannot cause a hash computed for purpose A to collide with one
//! computed for purpose B. Adding a new domain is backwards-incompatible by
//! design — once a chain is running, this set is frozen.
//!
//! Mirrors the `DOMAIN` constant in `lib/network/codec.ts`.

/// A domain tag is a static byte string. We model it as a `&'static [u8]` so
/// callers can pass it directly into the [`crate::codec::Writer::blob`] API.
pub type Domain = &'static [u8];

/// Canonical transaction identifier.
pub const TX_ID: Domain = b"MFBN-1/tx-id";

/// Transaction preimage hashed for ring-signature messages.
pub const TX_PREIMAGE: Domain = b"MFBN-1/tx-preimage";

/// Block identifier.
pub const BLOCK_ID: Domain = b"MFBN-1/block-id";

/// Block header preimage.
pub const BLOCK_HEADER: Domain = b"MFBN-1/block-header";

/// Storage commitment.
pub const STORAGE_COMMIT: Domain = b"MFBN-1/storage-commit";

/// Per-chunk content hash.
pub const CHUNK_HASH: Domain = b"MFBN-1/chunk-hash";

/// Merkle tree leaf hash (data side).
pub const MERKLE_LEAF: Domain = b"MFBN-1/merkle-leaf";

/// Merkle tree internal node hash.
pub const MERKLE_NODE: Domain = b"MFBN-1/merkle-node";

/// VRF input transcript.
pub const VRF_INPUT: Domain = b"MFBN-1/vrf-input";

/// VRF Fiat-Shamir challenge.
pub const VRF_CHALLENGE: Domain = b"MFBN-1/vrf-challenge";

/// VRF output expansion.
pub const VRF_OUTPUT: Domain = b"MFBN-1/vrf-output";

/// BLS aggregate signature transcript.
pub const BLS_SIG: Domain = b"MFBN-1/bls-sig";

/// KZG setup transcript.
pub const KZG_SETUP: Domain = b"MFBN-1/kzg-setup";

/// KZG Fiat-Shamir transcript.
pub const KZG_TRANSCRIPT: Domain = b"MFBN-1/kzg-transcript";

/// Bulletproof inner-product transcript.
pub const BP_INNER_PROD: Domain = b"MFBN-1/bp-inner-product";

/// Bulletproof range-proof transcript.
pub const BP_RANGE: Domain = b"MFBN-1/bp-range";

/// Consensus slot transcript.
pub const CONSENSUS_SLOT: Domain = b"MFBN-1/consensus-slot";

/// Consensus vote transcript.
pub const CONSENSUS_VOTE: Domain = b"MFBN-1/consensus-vote";

/// CLSAG aggregated-P challenge.
pub const CLSAG_AGG_P: Domain = b"MFBN-1/clsag-agg-P";

/// CLSAG aggregated-C challenge.
pub const CLSAG_AGG_C: Domain = b"MFBN-1/clsag-agg-C";

/// CLSAG ring challenge.
pub const CLSAG_RING: Domain = b"MFBN-1/clsag-ring";

/// Range-proof per-bit transcript.
pub const RANGE_BIT: Domain = b"MFBN-1/range-bit";

/// Range-proof final challenge.
pub const RANGE_FINAL: Domain = b"MFBN-1/range-final";

/// Amount-mask for the value half of an encrypted-amount blob.
pub const AMT_MASK_V: Domain = b"MFBN-1/amount-mask-v";

/// Amount-mask for the blinding half of an encrypted-amount blob.
pub const AMT_MASK_B: Domain = b"MFBN-1/amount-mask-b";

/// Coinbase transaction key derivation.
pub const COINBASE_TX_KEY: Domain = b"MFBN-1/coinbase-tx-key";

/// Coinbase blinding-factor derivation.
pub const COINBASE_BLIND: Domain = b"MFBN-1/coinbase-blind";

/// UTXO accumulator leaf hash.
pub const UTXO_LEAF: Domain = b"MFBN-1/utxo-leaf";

/// UTXO accumulator internal node hash.
pub const UTXO_NODE: Domain = b"MFBN-1/utxo-node";

/// UTXO accumulator empty-subtree precomputation.
pub const UTXO_EMPTY: Domain = b"MFBN-1/utxo-empty";

/// One-out-of-Many Fiat-Shamir challenge.
pub const OOM_CHALLENGE: Domain = b"MFBN-1/oom-challenge";

/// Merkle leaf for a validator bond operation (M1 rotation).
pub const BOND_OP_LEAF: Domain = b"MFBN-1/bond-op-leaf";

/// BLS-signed authorization payload for an [`BondOp::Unbond`](../../../mfn-consensus/src/bond_wire.rs) op (M1).
pub const UNBOND_OP_SIG: Domain = b"MFBN-1/unbond-op-sig";

/// BLS-signed authorization payload for an [`BondOp::Register`](../../../mfn-consensus/src/bond_wire.rs) op (M1).
/// Binds the operator's BLS public key (the same key used to sign `Unbond`)
/// to the rest of the register payload, blocking permissionless replay of
/// a serialized `Register` op for any operator's keys.
pub const REGISTER_OP_SIG: Domain = b"MFBN-1/register-op-sig";

/// Merkle leaf for a validator record committed under the block header's
/// `validator_root` (M2.0). Canonical encoding includes the validator's
/// index, stake, VRF + BLS public keys, and optional stealth payout —
/// the minimal data a light client needs to verify a finality bitmap and
/// quorum threshold against this validator set without holding the full
/// chain state.
pub const VALIDATOR_LEAF: Domain = b"MFBN-1/validator-leaf";

/// Merkle leaf for a piece of equivocation [`SlashEvidence`] committed
/// under the block header's `slashing_root` (M2.0.1). The leaf hashes
/// the canonicalized (sorted-pair) form of the evidence so two
/// reorderings of the same conflict produce the same leaf and the
/// Merkle root is reorder-stable.
pub const SLASHING_LEAF: Domain = b"MFBN-1/slashing-leaf";
