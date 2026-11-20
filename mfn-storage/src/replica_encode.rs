//! Per-replica sealing: a slow, operator-salted encoding of one copy.
//!
//! `replica_seal_root` hashes an operator id and a data root. It does not
//! look at bytes, so one disk can still answer for many keys. This module
//! encodes the plaintext so that operator A's sealed bytes are not operator
//! B's sealed bytes. Opening checks a MAC and then walks a hash chain: each
//! 32-byte block's keystream depends on the previous ciphertext, and each
//! block repeats that hash `rounds` times. Copying A's encoding and
//! presenting it as B fails the MAC. Unsealing A's bytes under B's id does
//! not return the plaintext.
//!
//! Off consensus. Path A and F-A are unchanged. `rounds` is operator policy,
//! not a genesis field.

use mfn_crypto::hash::dhash;

const SEAL_INIT: &[u8] = b"MFBN-1/replica-encode-init-v1";
const SEAL_ROUND: &[u8] = b"MFBN-1/replica-encode-round-v1";
const SEAL_CHAIN: &[u8] = b"MFBN-1/replica-encode-chain-v1";
const SEAL_MAC: &[u8] = b"MFBN-1/replica-encode-mac-v1";
const SEAL_ID: &[u8] = b"MFBN-1/replica-encode-id-v1";

const MAGIC: &[u8; 4] = b"MFSL";
const VERSION: u8 = 1;
const HEADER_LEN: usize = 16;
const MAC_LEN: usize = 32;
const BLOCK: usize = 32;

/// Recommended sequential rounds per 32-byte block.
///
/// Eight SHA-512 passes per block is enough that sealing a 256 KiB chunk is
/// real work and still finishes on a laptop. Raise it in operator config to
/// widen the gap versus on-demand encoding. Not a consensus constant.
pub const RECOMMENDED_SEAL_ROUNDS: u16 = 8;

/// Why a seal could not be built or opened.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SealError {
    /// `rounds` was 0. A seal with no sequential work is not a seal.
    RoundsZero,
    /// The blob is shorter than a header plus a MAC.
    Truncated,
    /// Magic or version is not this encoding.
    BadHeader,
    /// The MAC does not match this operator and data root.
    MacMismatch,
    /// The length prefix does not fit the ciphertext.
    LengthMismatch,
}

/// Operator-salted encoding of one replica.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReplicaSeal {
    /// Operator identity mixed into the keystream and the MAC.
    pub operator_id: [u8; 32],
    /// File the plaintext belongs to.
    pub data_root: [u8; 32],
    /// Which replica this encoding is.
    pub replica_index: u8,
    /// Sequential hash passes per 32-byte block.
    pub rounds: u16,
    /// Header, ciphertext, and MAC.
    pub bytes: Vec<u8>,
}

/// Encode `plaintext` so this operator's bytes are not another operator's.
///
/// # Errors
///
/// [`SealError::RoundsZero`] when `rounds` is 0.
pub fn seal_replica(
    plaintext: &[u8],
    operator_id: &[u8; 32],
    data_root: &[u8; 32],
    replica_index: u8,
    rounds: u16,
) -> Result<ReplicaSeal, SealError> {
    if rounds == 0 {
        return Err(SealError::RoundsZero);
    }
    let padded_len = plaintext.len().div_ceil(BLOCK) * BLOCK;
    let mut padded = vec![0u8; padded_len];
    padded[..plaintext.len()].copy_from_slice(plaintext);
    let mut state = init_state(operator_id, data_root, replica_index, rounds);
    let mut ciphertext = vec![0u8; padded_len];
    for (i, block) in padded.chunks(BLOCK).enumerate() {
        let key = keystream(&state, u32::try_from(i).unwrap_or(u32::MAX), rounds);
        for (out, (src, k)) in ciphertext[i * BLOCK..(i + 1) * BLOCK]
            .iter_mut()
            .zip(block.iter().zip(key.iter()))
        {
            *out = src ^ k;
        }
        state = dhash(
            SEAL_CHAIN,
            &[&state, &ciphertext[i * BLOCK..(i + 1) * BLOCK]],
        );
    }
    let mut bytes = Vec::with_capacity(HEADER_LEN + padded_len + MAC_LEN);
    bytes.extend_from_slice(MAGIC);
    bytes.push(VERSION);
    bytes.push(replica_index);
    bytes.extend_from_slice(&rounds.to_be_bytes());
    bytes.extend_from_slice(
        &u64::try_from(plaintext.len())
            .unwrap_or(u64::MAX)
            .to_be_bytes(),
    );
    debug_assert_eq!(bytes.len(), HEADER_LEN);
    bytes.extend_from_slice(&ciphertext);
    let mac = mac(operator_id, data_root, &bytes);
    bytes.extend_from_slice(&mac);
    Ok(ReplicaSeal {
        operator_id: *operator_id,
        data_root: *data_root,
        replica_index,
        rounds,
        bytes,
    })
}

/// Open a seal. The MAC must match `operator_id` and `data_root`.
///
/// # Errors
///
/// [`SealError`] when the blob is truncated, the header is foreign, the MAC
/// does not match, or the length prefix does not fit.
pub fn open_replica_seal(
    sealed: &[u8],
    operator_id: &[u8; 32],
    data_root: &[u8; 32],
) -> Result<Vec<u8>, SealError> {
    if sealed.len() < HEADER_LEN + MAC_LEN {
        return Err(SealError::Truncated);
    }
    let (body, mac_bytes) = sealed.split_at(sealed.len() - MAC_LEN);
    if body.len() < HEADER_LEN || &body[..4] != MAGIC || body[4] != VERSION {
        return Err(SealError::BadHeader);
    }
    let expect = mac(operator_id, data_root, body);
    if !mac_eq(mac_bytes, &expect) {
        return Err(SealError::MacMismatch);
    }
    let replica_index = body[5];
    let rounds = u16::from_be_bytes([body[6], body[7]]);
    if rounds == 0 {
        return Err(SealError::RoundsZero);
    }
    let original_len = u64::from_be_bytes(body[8..16].try_into().unwrap_or([0; 8]));
    let ciphertext = &body[HEADER_LEN..];
    if ciphertext.len() % BLOCK != 0 {
        return Err(SealError::LengthMismatch);
    }
    let mut state = init_state(operator_id, data_root, replica_index, rounds);
    let mut plain = vec![0u8; ciphertext.len()];
    for i in 0..(ciphertext.len() / BLOCK) {
        let ct = &ciphertext[i * BLOCK..(i + 1) * BLOCK];
        let key = keystream(&state, u32::try_from(i).unwrap_or(u32::MAX), rounds);
        for (out, (src, k)) in plain[i * BLOCK..(i + 1) * BLOCK]
            .iter_mut()
            .zip(ct.iter().zip(key.iter()))
        {
            *out = src ^ k;
        }
        state = dhash(SEAL_CHAIN, &[&state, ct]);
    }
    let len = usize::try_from(original_len).unwrap_or(usize::MAX);
    if len > plain.len() {
        return Err(SealError::LengthMismatch);
    }
    plain.truncate(len);
    Ok(plain)
}

/// Id of this encoded replica. Different operators, roots, or bytes differ.
#[must_use]
pub fn sealed_replica_id(seal: &ReplicaSeal) -> [u8; 32] {
    let index = [seal.replica_index];
    dhash(
        SEAL_ID,
        &[&seal.operator_id, &seal.data_root, &index, &seal.bytes],
    )
}

/// `true` when both seals open to `plaintext` and their bytes differ.
#[must_use]
pub fn seals_are_distinct_copies(a: &ReplicaSeal, b: &ReplicaSeal, plaintext: &[u8]) -> bool {
    if a.bytes == b.bytes || a.operator_id == b.operator_id {
        return false;
    }
    let Ok(pa) = open_replica_seal(&a.bytes, &a.operator_id, &a.data_root) else {
        return false;
    };
    let Ok(pb) = open_replica_seal(&b.bytes, &b.operator_id, &b.data_root) else {
        return false;
    };
    pa == plaintext && pb == plaintext
}

fn init_state(
    operator_id: &[u8; 32],
    data_root: &[u8; 32],
    replica_index: u8,
    rounds: u16,
) -> [u8; 32] {
    let index = [replica_index];
    let rounds_be = rounds.to_be_bytes();
    dhash(SEAL_INIT, &[operator_id, data_root, &index, &rounds_be])
}

fn keystream(state: &[u8; 32], block_index: u32, rounds: u16) -> [u8; 32] {
    let idx = block_index.to_be_bytes();
    let mut block_key = *state;
    for _ in 0..rounds {
        block_key = dhash(SEAL_ROUND, &[&block_key, &idx]);
    }
    block_key
}

fn mac(operator_id: &[u8; 32], data_root: &[u8; 32], body: &[u8]) -> [u8; 32] {
    dhash(SEAL_MAC, &[operator_id, data_root, body])
}

fn mac_eq(got: &[u8], expect: &[u8; 32]) -> bool {
    if got.len() != expect.len() {
        return false;
    }
    let mut diff = 0u8;
    for (a, b) in got.iter().zip(expect.iter()) {
        diff |= a ^ b;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(byte: u8) -> [u8; 32] {
        [byte; 32]
    }

    #[test]
    fn two_operators_seal_one_plaintext_into_two_copies() {
        let plain = b"one disk must not pass for two operators".to_vec();
        let root = id(9);
        let a = seal_replica(&plain, &id(1), &root, 0, 2).expect("seal a");
        let b = seal_replica(&plain, &id(2), &root, 1, 2).expect("seal b");
        assert_ne!(a.bytes, b.bytes);
        assert_ne!(sealed_replica_id(&a), sealed_replica_id(&b));
        assert!(seals_are_distinct_copies(&a, &b, &plain));
        assert_eq!(
            open_replica_seal(&a.bytes, &a.operator_id, &root).expect("open"),
            plain
        );
    }

    #[test]
    fn copied_seal_fails_under_a_different_operator() {
        let plain = b"copied bytes are not a second replica";
        let root = id(4);
        let a = seal_replica(plain, &id(1), &root, 0, 2).expect("seal");
        assert_eq!(
            open_replica_seal(&a.bytes, &id(2), &root),
            Err(SealError::MacMismatch)
        );
    }

    #[test]
    fn flipped_ciphertext_fails_the_mac() {
        let root = id(5);
        let mut a = seal_replica(b"intact seal", &id(1), &root, 0, 2).expect("seal");
        let flip_at = HEADER_LEN;
        a.bytes[flip_at] ^= 0x01;
        assert_eq!(
            open_replica_seal(&a.bytes, &id(1), &root),
            Err(SealError::MacMismatch)
        );
    }

    #[test]
    fn keystream_depends_on_the_previous_block() {
        let root = id(6);
        let p1 = vec![0u8; 64];
        let mut p2 = vec![0u8; 64];
        p2[0] = 1;
        let a = seal_replica(&p1, &id(1), &root, 0, 2).expect("a");
        let b = seal_replica(&p2, &id(1), &root, 0, 2).expect("b");
        let block1 = HEADER_LEN + BLOCK;
        assert_ne!(
            &a.bytes[block1..block1 + BLOCK],
            &b.bytes[block1..block1 + BLOCK]
        );
    }

    #[test]
    fn zero_rounds_is_rejected_and_empty_plaintext_round_trips() {
        assert_eq!(
            seal_replica(b"x", &id(1), &id(2), 0, 0).unwrap_err(),
            SealError::RoundsZero
        );
        let root = id(7);
        let seal = seal_replica(b"", &id(1), &root, 3, RECOMMENDED_SEAL_ROUNDS).expect("empty");
        assert_eq!(
            open_replica_seal(&seal.bytes, &id(1), &root).expect("open"),
            b""
        );
    }

    #[test]
    fn same_inputs_are_deterministic() {
        let root = id(8);
        let a = seal_replica(b"again", &id(1), &root, 2, 3).expect("a");
        let b = seal_replica(b"again", &id(1), &root, 2, 3).expect("b");
        assert_eq!(a.bytes, b.bytes);
        assert_eq!(sealed_replica_id(&a), sealed_replica_id(&b));
    }

    #[test]
    fn truncated_blob_is_rejected() {
        assert_eq!(
            open_replica_seal(&[0, 1, 2], &id(1), &id(2)),
            Err(SealError::Truncated)
        );
    }
}
