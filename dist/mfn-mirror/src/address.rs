//! CID, magnet, and chain root for one file.

use mfn_storage::{chunk_data, merkle_tree_from_chunks, DEFAULT_CHUNK_SIZE};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::sha1::sha1;

/// BitTorrent piece length. Files here are release binaries, not the chain log.
pub const PIECE_LENGTH: usize = 16 * 1024;

/// One file, named three ways.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MirrorRecord {
    /// Single path segment. No slash.
    pub name: String,
    /// Byte length.
    pub bytes: u64,
    /// Lower-case SHA-256.
    pub sha256_hex: String,
    /// CIDv1, raw leaves, SHA-256, base32 multibase.
    pub cid: String,
    /// `magnet:?xt=urn:btih:` link.
    pub magnet: String,
    /// Chunk-Merkle root, lower-case hex.
    pub data_root_hex: String,
}

/// Why a name or a check failed.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum MirrorError {
    /// The file name is not a single safe segment.
    #[error("name must be one path segment: {0}")]
    BadName(String),
    /// The bytes do not match the record.
    #[error("bytes do not match the mirror record")]
    Mismatch,
}

/// Describe `bytes` so they can be fetched without a domain name.
pub fn describe(name: &str, bytes: &[u8]) -> Result<MirrorRecord, MirrorError> {
    let name = check_name(name)?;
    let digest = Sha256::digest(bytes);
    let sha256_hex = hex::encode(digest);
    let cid = cid_v1_raw(&digest);
    let info = bencode_info(&name, bytes);
    let infohash = hex::encode(sha1(&info));
    let magnet = format!("magnet:?xt=urn:btih:{infohash}&dn={name}");
    let chunks = chunk_data(bytes, DEFAULT_CHUNK_SIZE).expect("default chunk size");
    let root = merkle_tree_from_chunks(&chunks).expect("non-empty chunk list");
    Ok(MirrorRecord {
        name,
        bytes: bytes.len() as u64,
        sha256_hex,
        cid,
        magnet,
        data_root_hex: hex::encode(root.root()),
    })
}

/// True only when every address in `record` is the address of `bytes`.
pub fn verify(bytes: &[u8], record: &MirrorRecord) -> Result<(), MirrorError> {
    let again = describe(&record.name, bytes)?;
    if again != *record {
        return Err(MirrorError::Mismatch);
    }
    Ok(())
}

impl MirrorRecord {
    /// Stable text form. One field per line.
    pub fn render(&self) -> String {
        format!(
            "\
permawrite-mirror v1
name {}
bytes {}
sha256 {}
cid {}
magnet {}
data_root {}
",
            self.name, self.bytes, self.sha256_hex, self.cid, self.magnet, self.data_root_hex
        )
    }

    /// Parse [`Self::render`].
    pub fn parse(text: &str) -> Result<Self, MirrorError> {
        let mut name = None;
        let mut bytes = None;
        let mut sha256_hex = None;
        let mut cid = None;
        let mut magnet = None;
        let mut data_root_hex = None;
        let mut lines = text.lines().filter(|l| !l.trim().is_empty());
        if lines.next().map(str::trim) != Some("permawrite-mirror v1") {
            return Err(MirrorError::Mismatch);
        }
        for line in lines {
            let (key, value) = line.split_once(' ').ok_or(MirrorError::Mismatch)?;
            match key {
                "name" => name = Some(value.to_string()),
                "bytes" => {
                    bytes = Some(value.parse::<u64>().map_err(|_| MirrorError::Mismatch)?);
                }
                "sha256" => sha256_hex = Some(value.to_string()),
                "cid" => cid = Some(value.to_string()),
                "magnet" => magnet = Some(value.to_string()),
                "data_root" => data_root_hex = Some(value.to_string()),
                _ => return Err(MirrorError::Mismatch),
            }
        }
        Ok(Self {
            name: name.ok_or(MirrorError::Mismatch)?,
            bytes: bytes.ok_or(MirrorError::Mismatch)?,
            sha256_hex: sha256_hex.ok_or(MirrorError::Mismatch)?,
            cid: cid.ok_or(MirrorError::Mismatch)?,
            magnet: magnet.ok_or(MirrorError::Mismatch)?,
            data_root_hex: data_root_hex.ok_or(MirrorError::Mismatch)?,
        })
    }
}

fn check_name(name: &str) -> Result<String, MirrorError> {
    if name.is_empty()
        || name.len() > 64
        || !name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'_' || b == b'-')
    {
        return Err(MirrorError::BadName(name.to_string()));
    }
    Ok(name.to_string())
}

fn cid_v1_raw(sha256_digest: &[u8]) -> String {
    let mut bin = Vec::with_capacity(36);
    bin.extend_from_slice(&[0x01, 0x55, 0x12, 0x20]);
    bin.extend_from_slice(sha256_digest);
    format!("b{}", base32_lower(&bin))
}

fn base32_lower(data: &[u8]) -> String {
    const ALPH: &[u8] = b"abcdefghijklmnopqrstuvwxyz234567";
    let mut out = String::new();
    let mut buffer: u64 = 0;
    let mut bits: u32 = 0;
    for &byte in data {
        buffer = (buffer << 8) | u64::from(byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            let idx = ((buffer >> bits) & 0x1f) as usize;
            out.push(ALPH[idx] as char);
        }
    }
    if bits > 0 {
        let idx = ((buffer << (5 - bits)) & 0x1f) as usize;
        out.push(ALPH[idx] as char);
    }
    out
}

fn bencode_info(name: &str, data: &[u8]) -> Vec<u8> {
    let mut pieces = Vec::new();
    if !data.is_empty() {
        for chunk in data.chunks(PIECE_LENGTH) {
            pieces.extend_from_slice(&sha1(chunk));
        }
    }
    let mut out = Vec::new();
    out.push(b'd');
    push_kv_int(&mut out, "length", data.len() as u64);
    push_kv_bytes(&mut out, "name", name.as_bytes());
    push_kv_int(&mut out, "piece length", PIECE_LENGTH as u64);
    push_kv_bytes(&mut out, "pieces", &pieces);
    out.push(b'e');
    out
}

fn push_kv_int(out: &mut Vec<u8>, key: &str, value: u64) {
    push_bytes(out, key.as_bytes());
    out.push(b'i');
    out.extend_from_slice(value.to_string().as_bytes());
    out.push(b'e');
}

fn push_kv_bytes(out: &mut Vec<u8>, key: &str, value: &[u8]) {
    push_bytes(out, key.as_bytes());
    push_bytes(out, value);
}

fn push_bytes(out: &mut Vec<u8>, value: &[u8]) {
    out.extend_from_slice(value.len().to_string().as_bytes());
    out.push(b':');
    out.extend_from_slice(value);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_file_cid_is_the_well_known_raw_cid() {
        let record = describe("empty", b"").unwrap();
        assert_eq!(
            record.sha256_hex,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            record.cid,
            "bafkreihdwdcefgh4dqkjv67uzcmw7ojee6xedzdetojuzjevtenxquvyku"
        );
        assert!(record.magnet.starts_with("magnet:?xt=urn:btih:"));
        assert_eq!(record.bytes, 0);
        verify(b"", &record).unwrap();
    }

    #[test]
    fn tamper_and_bad_names_fail_and_the_text_round_trips() {
        let record = describe("mfnd", b"permawrite").unwrap();
        assert!(verify(b"permawrite", &record).is_ok());
        assert_eq!(verify(b"permawritE", &record), Err(MirrorError::Mismatch));
        assert!(describe("../mfnd", b"x").is_err());
        assert!(describe("a/b", b"x").is_err());
        let parsed = MirrorRecord::parse(&record.render()).unwrap();
        assert_eq!(parsed, record);
        assert_ne!(record.data_root_hex, record.sha256_hex);
    }

    #[test]
    fn two_descriptions_of_the_same_bytes_match() {
        let a = describe("mfnd", b"same-bytes").unwrap();
        let b = describe("mfnd", b"same-bytes").unwrap();
        assert_eq!(a.cid, b.cid);
        assert_eq!(a.magnet, b.magnet);
        assert_eq!(a.data_root_hex, b.data_root_hex);
    }
}
