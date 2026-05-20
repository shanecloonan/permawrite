//! # `mfn-storage-operator`
//!
//! Storage-operator daemon and libraries for Permawrite (**M6**):
//!
//! - Persisted upload artifacts ([`upload_artifact_store`], **M3.24**)
//! - SPoRA proof construction + `submit_storage_proof` ([`prove`])
//! - Long-running prove loop ([`daemon`], optional `--chunk-listen` **M6.4**)
//! - HTTP chunk replication from wallet artifacts ([`chunk_http`], **M6.2**)
//!
//! The `mfn-storage-operator` binary polls `mfnd` and every local upload
//! artifact, submitting proofs into the node's proof pool (**M3.22** / **M3.23**).
//!
//! On Unix, the binary installs a Ctrl+C handler; on Windows use `--once` or
//! stop the process externally.

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(clippy::all)]

pub mod chunk_client;
pub mod chunk_http;
pub mod daemon;
pub mod prove;
pub mod rpc;
pub mod upload_artifact_store;

pub use chunk_client::{fetch_chunk_http, ChunkFetchError};
pub use chunk_http::{serve_chunks, ChunkServeConfig, ChunkServeError};
pub use daemon::{
    run_daemon, run_prove_cycle, OperatorDaemonConfig, ProveAttempt, ProveAttemptStatus,
    ProveCycleSummary,
};
pub use prove::{prove_from_file, prove_from_wallet_artifact, ProveError, ProveSuccess};
pub use rpc::{RpcClient, RpcError, DEFAULT_RPC_ADDR};
pub use upload_artifact_store::{
    list_upload_artifacts, load_upload_artifact, save_upload_artifact, upload_artifacts_root,
    LoadedUploadArtifact, UploadArtifactSaveMeta, UploadArtifactStoreError, UploadArtifactSummary,
};
