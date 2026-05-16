//! Persistence errors and save metadata.

use std::path::PathBuf;

use mfn_runtime::ChainError;

/// Result metadata returned after a successful checkpoint save.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoreSave {
    /// Number of bytes written to the primary checkpoint file.
    pub bytes_written: usize,
    /// Path to the primary checkpoint file that now contains the saved chain state.
    pub checkpoint_path: PathBuf,
    /// Path to the backup checkpoint file (may not exist after the first save).
    pub backup_path: PathBuf,
}

/// Errors produced by chain persistence backends.
#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    /// A filesystem operation failed.
    #[error("store io `{op}` failed for `{}`: {source}", path.display())]
    Io {
        /// Short operation label, useful for logs and tests.
        op: &'static str,
        /// Path involved in the failing operation.
        path: PathBuf,
        /// Underlying OS error.
        #[source]
        source: std::io::Error,
    },

    /// Checkpoint bytes decoded but could not be restored against the caller's genesis.
    #[error("chain restore failed: {0}")]
    Chain(#[from] ChainError),

    /// Append-only block log framing / decode failure.
    #[error("block log: {0}")]
    BlockLog(String),
}
