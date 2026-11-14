//! Client-side encryption for bytes that will be anchored.
//!
//! The chain stores a `data_root` of whatever the wallet uploads. This
//! module encrypts first, so the anchored bytes are ciphertext. The 32-byte
//! key is not in the blob and must stay in the uploader's wallet. A wrong
//! key or a flipped ciphertext byte fails the MAC.
//!
//! The stream is domain-separated SHA-512 in counter mode. It is not a
//! consensus encoding. Path A and F-A are unchanged.

use mfn_crypto::hash::{dhash, dhash64};

const UPLOAD_STREAM: &[u8] = b"MFBN-1/upload-encrypt-stream-v1";
const UPLOAD_MAC: &[u8] = b"MFBN-1/upload-encrypt-mac-v1";

const MAGIC: &[u8; 4] = b"MFUP";
const VERSION: u8 = 1;
const HEADER_LEN: usize = 4 + 1 + 16;
const MAC_LEN: usize = 32;

/// Local filename for the upload key. Never served as a chunk.
pub const UPLOAD_KEY_FILE: &str = "upload.key";

/// Why an upload blob could not be sealed or opened.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum UploadCryptError {
    /// The blob is not this encryption format.
    #[error("upload ciphertext header is not MFUP v1")]
    BadHeader,
    /// The blob is shorter than a header plus a MAC.
    #[error("upload ciphertext is truncated")]
    Truncated,
    /// The MAC does not match the key.
    #[error("upload ciphertext MAC does not match the key")]
    MacMismatch,
}

/// Encrypt `plaintext` under `key` and `nonce`. The key is not written into the blob.
#[must_use]
pub fn encrypt_upload(plaintext: &[u8], key: &[u8; 32], nonce: &[u8; 16]) -> Vec<u8> {
    let mut body = Vec::with_capacity(HEADER_LEN + plaintext.len());
    body.extend_from_slice(MAGIC);
    body.push(VERSION);
    body.extend_from_slice(nonce);
    body.extend(plaintext.iter().copied());
    apply_keystream(&mut body[HEADER_LEN..], key, nonce);
    let mac = upload_mac(key, &body);
    body.extend_from_slice(&mac);
    body
}

/// Open a blob produced by [`encrypt_upload`].
///
/// # Errors
///
/// [`UploadCryptError`] when the header is foreign, the blob is truncated,
/// or the MAC does not match `key`.
pub fn decrypt_upload(blob: &[u8], key: &[u8; 32]) -> Result<Vec<u8>, UploadCryptError> {
    if blob.len() < HEADER_LEN + MAC_LEN {
        return Err(UploadCryptError::Truncated);
    }
    let (body, mac_bytes) = blob.split_at(blob.len() - MAC_LEN);
    if body.len() < HEADER_LEN || &body[..4] != MAGIC || body[4] != VERSION {
        return Err(UploadCryptError::BadHeader);
    }
    let expect = upload_mac(key, body);
    if !mac_eq(mac_bytes, &expect) {
        return Err(UploadCryptError::MacMismatch);
    }
    let mut plain = body[HEADER_LEN..].to_vec();
    let mut nonce = [0u8; 16];
    nonce.copy_from_slice(&body[5..21]);
    apply_keystream(&mut plain, key, &nonce);
    Ok(plain)
}

/// `true` when `blob` starts with the upload-encryption magic.
#[must_use]
pub fn upload_blob_is_encrypted(blob: &[u8]) -> bool {
    blob.len() >= 5 && &blob[..4] == MAGIC && blob[4] == VERSION
}

fn apply_keystream(buf: &mut [u8], key: &[u8; 32], nonce: &[u8; 16]) {
    let mut offset = 0usize;
    let mut counter = 0u64;
    while offset < buf.len() {
        let block = keystream_block(key, nonce, counter);
        let n = (buf.len() - offset).min(block.len());
        for (dst, src) in buf[offset..offset + n].iter_mut().zip(block.iter()) {
            *dst ^= src;
        }
        offset += n;
        counter = counter.saturating_add(1);
    }
}

fn keystream_block(key: &[u8; 32], nonce: &[u8; 16], counter: u64) -> [u8; 64] {
    let c = counter.to_be_bytes();
    dhash64(UPLOAD_STREAM, &[key, nonce, &c])
}

fn upload_mac(key: &[u8; 32], body: &[u8]) -> [u8; 32] {
    dhash(UPLOAD_MAC, &[key, body])
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
    use crate::spora::build_storage_commitment;

    fn key(byte: u8) -> [u8; 32] {
        [byte; 32]
    }

    fn nonce(byte: u8) -> [u8; 16] {
        [byte; 16]
    }

    #[test]
    fn round_trip_hides_plaintext_and_rejects_a_wrong_key() {
        let plain = b"this file must not sit in the clear on an operator disk";
        let blob = encrypt_upload(plain, &key(1), &nonce(2));
        assert!(upload_blob_is_encrypted(&blob));
        assert!(!blob.windows(plain.len()).any(|w| w == plain));
        assert_eq!(decrypt_upload(&blob, &key(1)).expect("decrypt"), plain);
        assert_eq!(
            decrypt_upload(&blob, &key(9)),
            Err(UploadCryptError::MacMismatch)
        );
    }

    #[test]
    fn a_flipped_ciphertext_byte_fails_the_mac() {
        let mut blob = encrypt_upload(b"permanent", &key(3), &nonce(4));
        blob[HEADER_LEN] ^= 0x01;
        assert_eq!(
            decrypt_upload(&blob, &key(3)),
            Err(UploadCryptError::MacMismatch)
        );
    }

    #[test]
    fn the_chain_commits_to_ciphertext_not_plaintext() {
        let plain = b"private archive";
        let blob = encrypt_upload(plain, &key(5), &nonce(6));
        let plain_root = build_storage_commitment(plain, 1, Some(64), 3, None)
            .expect("plain")
            .commit
            .data_root;
        let cipher_root = build_storage_commitment(&blob, 1, Some(64), 3, None)
            .expect("cipher")
            .commit
            .data_root;
        assert_ne!(plain_root, cipher_root);
    }

    #[test]
    fn empty_plaintext_round_trips_and_truncated_blobs_fail() {
        let blob = encrypt_upload(b"", &key(7), &nonce(8));
        assert_eq!(decrypt_upload(&blob, &key(7)).expect("open"), b"");
        assert_eq!(
            decrypt_upload(&[0, 1, 2], &key(7)),
            Err(UploadCryptError::Truncated)
        );
    }
}
