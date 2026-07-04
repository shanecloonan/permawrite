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

pub mod backfill;
pub mod chunk_client;
pub mod chunk_http;
pub mod chunk_push;
pub mod daemon;
pub mod inbox_backfill;
pub mod prove;
pub mod rpc;
pub mod upload_artifact_store;

pub use backfill::{
    backfill_upload_artifact_from_challenge, fetch_payload_from_peer, fetch_payload_from_peers,
    persist_backfill_artifact, BackfillError, BackfillResult,
};
pub use chunk_client::{fetch_chunk_http, fetch_chunk_http_quorum, ChunkFetchError};
pub use chunk_http::{serve_chunks, ChunkServeConfig, ChunkServeError};
pub use chunk_push::{
    push_wallet_artifact_chunks_to_peer, push_wallet_artifact_chunks_to_peer_with_handshake,
    push_wallet_artifact_chunks_to_peers, push_wallet_artifact_chunks_to_peers_with_handshake,
    ChunkPushError, ChunkPushPeerResult,
};
pub use daemon::{
    run_daemon, run_prove_cycle, OperatorDaemonConfig, ProveAttempt, ProveAttemptStatus,
    ProveCycleSummary,
};
pub use inbox_backfill::{
    backfill_upload_artifact_from_inbox, fetch_payload_from_inbox, inbox_chunk_status,
    InboxBackfillError, InboxChunkStatus,
};
pub use prove::{prove_from_file, prove_from_wallet_artifact, ProveError, ProveSuccess};
pub use rpc::{load_network_manifest, NetworkManifest, RpcClient, RpcError, DEFAULT_RPC_ADDR};
pub use upload_artifact_store::{
    list_upload_artifacts, load_upload_artifact, save_upload_artifact, upload_artifacts_root,
    LoadedUploadArtifact, UploadArtifactSaveMeta, UploadArtifactStoreError, UploadArtifactSummary,
};
