//! Deterministic source archives.
//!
//! The archive is a ustar. Names are sorted, the owner is uid 0, and the
//! timestamp is the caller’s `SOURCE_DATE_EPOCH`. Two packs of the same
//! files are the same bytes. `.git` and `..` never enter the archive.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod tar;

pub use tar::{bundle_sha256, pack, unpack, BundleError, SourceFile};
