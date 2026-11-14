//! Reproducible release builds for Permawrite.
//!
//! A release is reproducible when a second machine, given the same source
//! commit and the plan from [`plan`], produces byte-identical binaries.
//! [`compare`] then checks the two SHA-256 manifests. Nothing here changes
//! consensus, Path A, or F-A.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod compare;
pub mod inventory;
pub mod plan;

pub use compare::{compare_manifests, hash_bytes, parse_manifest, CompareReport, ManifestError};
pub use inventory::{source_inventory, InventoryError, SourceInventory};
pub use plan::{rustflags_for, ReproPlan, BINARIES, PINNED_RUSTC};
