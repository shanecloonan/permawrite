//! Content-addressed release mirrors.
//!
//! A binary can be named by an IPFS CIDv1, a BitTorrent infohash, and the
//! chain's chunk-Merkle `data_root`. None of those names needs GitHub.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod address;
mod sha1;

pub use address::{describe, verify, MirrorError, MirrorRecord, PIECE_LENGTH};
