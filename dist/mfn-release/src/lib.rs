//! Signed release manifests.
//!
//! A published binary is accepted only when a threshold of maintainer
//! keys sign the same canonical manifest. One maintainer, or a key that
//! has been revoked, is not enough. This crate does not change consensus.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod keys;
pub mod manifest;

pub use keys::{generate_key, KeyError, Keyring, MaintainerKey, Revocation};
pub use manifest::{
    hash_bytes, sign_manifest, verify_manifest, Artifact, ManifestError, ReleaseManifest, VerifyOk,
};
