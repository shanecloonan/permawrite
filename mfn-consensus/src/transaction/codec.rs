//! Transaction wire codec.

#![allow(unused_imports)]

use super::internal::*;
use super::wire::{TransactionWire, TxInputWire, TxOutputWire};

/* ----------------------------------------------------------------------- *
 *  Wire codec (M2.0.10) — full transaction encode / decode                *
 * ----------------------------------------------------------------------- */

/// Lossless canonical byte encoding of a [`TransactionWire`].
///
/// Mirrors [`tx_preimage`]'s field order for every "shape" field, then
/// appends the inputs' signatures and the outputs' full bulletproof and
/// (optionally) full storage commitment. Round-trips byte-for-byte
/// through [`decode_transaction`].
///
/// Wire layout (every length-variable item is length-prefixed via
/// [`mfn_crypto::codec::Writer`]'s `varint` / `blob` / `points` /
/// `scalars` helpers):
///
/// ```text
/// varint(version)
/// point(r_pub)
/// u64(fee)
/// blob(extra)
/// varint(inputs.len)
/// for each input:
///   points(ring.p)           // length-prefixed
///   points(ring.c)           // length-prefixed
///   point(c_pseudo)
///   blob(encode_clsag(sig))  // length-prefixed
/// varint(outputs.len)
/// for each output:
///   point(one_time_addr)
///   point(amount)            // == bulletproof.v
///   blob(encode_bulletproof(range_proof))
///   push(enc_amount)         // raw 40 bytes (fixed width)
///   u8(0|1)                  // storage-some flag
///   if 1: blob(encode_storage_commitment(c))
/// ```
#[must_use]
pub fn encode_transaction(tx: &TransactionWire) -> Vec<u8> {
    let mut w = Writer::new();
    w.varint(u64::from(tx.version));
    w.point(&tx.r_pub);
    w.u64(tx.fee);
    w.blob(&tx.extra);

    w.varint(tx.inputs.len() as u64);
    for inp in &tx.inputs {
        w.points(&inp.ring.p);
        w.points(&inp.ring.c);
        w.point(&inp.c_pseudo);
        w.blob(&encode_clsag(&inp.sig));
    }

    w.varint(tx.outputs.len() as u64);
    for out in &tx.outputs {
        w.point(&out.one_time_addr);
        w.point(&out.amount);
        w.blob(&encode_bulletproof(&out.range_proof));
        w.push(&out.enc_amount);
        match &out.storage {
            None => {
                w.u8(0);
            }
            Some(c) => {
                w.u8(1);
                w.blob(&encode_storage_commitment(c));
            }
        }
    }

    w.into_bytes()
}

/// Typed errors produced by [`decode_transaction`].
#[derive(Debug, thiserror::Error)]
pub enum TxDecodeError {
    /// Underlying codec layer hit a short read, invalid point, varint
    /// overflow, etc.
    #[error("transaction codec: {0}")]
    Codec(#[from] mfn_crypto::CryptoError),
    /// `version` decoded as a varint but didn't fit in the 32-bit
    /// transaction-version field.
    #[error("transaction version {got} does not fit in u32")]
    VersionOutOfRange {
        /// The raw varint value that overflowed.
        got: u64,
    },
    /// A declared input or output count overflowed `usize`. Defensive
    /// guard for 32-bit targets; unreachable on 64-bit hosts.
    #[error("{field} count {got} exceeds usize")]
    CountTooLarge {
        /// Which collection's count tripped the guard.
        field: &'static str,
        /// The raw varint value that overflowed.
        got: u64,
    },
    /// The `storage` flag on an output was neither `0` nor `1`.
    #[error("output {index}: invalid storage flag {got} (expected 0 or 1)")]
    InvalidStorageFlag {
        /// Index of the offending output.
        index: usize,
        /// The flag byte that was read.
        got: u8,
    },
    /// One of the input ring's `(P, C)` columns disagreed on length.
    /// CLSAG signs over a structured ring of `(P_i, C_i)` pairs, so
    /// the two columns must always be the same length.
    #[error("input {index}: ring P-column length {p_len} != C-column length {c_len}")]
    RingColumnLenMismatch {
        /// Index of the offending input.
        index: usize,
        /// Length of the P column.
        p_len: usize,
        /// Length of the C column.
        c_len: usize,
    },
    /// A nested length-prefixed blob decoded successfully but did not
    /// re-encode to the exact same bytes. This catches trailing bytes
    /// inside nested cryptographic objects whose standalone decoders are
    /// intentionally permissive for legacy call sites.
    #[error("{field}[{index}] is not canonical")]
    NonCanonicalBlob {
        /// Which nested blob failed canonical round-trip.
        field: &'static str,
        /// Index of the input / output containing the blob.
        index: usize,
    },
    /// Bytes remained in the buffer after a full transaction had been
    /// parsed.
    #[error("{remaining} trailing byte(s) after transaction")]
    TrailingBytes {
        /// Number of bytes left in the buffer.
        remaining: usize,
    },
}

/// Decode a [`TransactionWire`] from its canonical wire encoding produced
/// by [`encode_transaction`].
///
/// `decode_transaction(&encode_transaction(t)) == Ok(t')` where `t'` is
/// structurally equal to `t` and `tx_id(t') == tx_id(t)` (byte-for-byte
/// round-trip).
///
/// Strict: any trailing byte after the last field is a hard reject.
/// Transactions are self-delimiting, so a non-empty tail always indicates
/// a caller-side framing bug or corruption.
///
/// # Errors
///
/// Returns [`TxDecodeError`] on truncation, invalid point compression,
/// varint overflow, unexpected storage flag, ring-column length mismatch,
/// or trailing bytes.
pub fn decode_transaction(bytes: &[u8]) -> Result<TransactionWire, TxDecodeError> {
    let mut r = Reader::new(bytes);
    let tx = read_transaction(&mut r)?;
    if !r.end() {
        return Err(TxDecodeError::TrailingBytes {
            remaining: r.remaining(),
        });
    }
    Ok(tx)
}

/// Streaming variant of [`decode_transaction`] — reads one transaction
/// from a [`Reader`] without enforcing trailing-byte rejection. Used
/// by the block codec (M2.0.10) where transactions are length-prefixed
/// blobs in a larger stream.
pub(crate) fn read_transaction(r: &mut Reader<'_>) -> Result<TransactionWire, TxDecodeError> {
    let version_raw = r.varint()?;
    let version: u32 = u32::try_from(version_raw)
        .map_err(|_| TxDecodeError::VersionOutOfRange { got: version_raw })?;

    let r_pub = r.point()?;
    let fee = r.u64()?;
    let extra = r.blob()?.to_vec();

    let n_in_raw = r.varint()?;
    let n_in: usize = usize::try_from(n_in_raw).map_err(|_| TxDecodeError::CountTooLarge {
        field: "inputs",
        got: n_in_raw,
    })?;
    let mut inputs: Vec<TxInputWire> = Vec::new();
    for idx in 0..n_in {
        let p = r.points()?;
        let c = r.points()?;
        if p.len() != c.len() {
            return Err(TxDecodeError::RingColumnLenMismatch {
                index: idx,
                p_len: p.len(),
                c_len: c.len(),
            });
        }
        let c_pseudo = r.point()?;
        let sig_bytes = r.blob()?;
        let sig = decode_clsag(sig_bytes)?;
        if encode_clsag(&sig) != sig_bytes {
            return Err(TxDecodeError::NonCanonicalBlob {
                field: "input.sig",
                index: idx,
            });
        }
        inputs.push(TxInputWire {
            ring: ClsagRing { p, c },
            c_pseudo,
            sig,
        });
    }

    let n_out_raw = r.varint()?;
    let n_out: usize = usize::try_from(n_out_raw).map_err(|_| TxDecodeError::CountTooLarge {
        field: "outputs",
        got: n_out_raw,
    })?;
    let mut outputs: Vec<TxOutputWire> = Vec::new();
    for idx in 0..n_out {
        let one_time_addr = r.point()?;
        let amount = r.point()?;
        let bp_bytes = r.blob()?;
        let range_proof = decode_bulletproof(amount, bp_bytes)?;
        if encode_bulletproof(&range_proof) != bp_bytes {
            return Err(TxDecodeError::NonCanonicalBlob {
                field: "output.range_proof",
                index: idx,
            });
        }
        let enc_slice = r.bytes(ENC_AMOUNT_BYTES)?;
        let mut enc_amount = [0u8; ENC_AMOUNT_BYTES];
        enc_amount.copy_from_slice(enc_slice);
        let storage_flag = r.u8()?;
        let storage = match storage_flag {
            0 => None,
            1 => {
                let sc_bytes = r.blob()?;
                Some(decode_storage_commitment(sc_bytes)?)
            }
            got => {
                return Err(TxDecodeError::InvalidStorageFlag { index: idx, got });
            }
        };
        outputs.push(TxOutputWire {
            one_time_addr,
            amount,
            range_proof,
            enc_amount,
            storage,
        });
    }

    Ok(TransactionWire {
        version,
        r_pub,
        inputs,
        outputs,
        fee,
        extra,
    })
}
