//! Permawrite operator CLI library (**M3.0** / **M3.1**).
//!
//! - [`rpc::RpcClient`] — newline-delimited JSON-RPC 2.0 over TCP to `mfnd serve`.
//! - [`cli`] — command-line driver for `mfn-cli` binary.
//! - [`wallet_store`] / [`wallet_cmd`] — on-disk wallet file, scan, send, upload, claim (**M3.1**–**M3.4**).
//! - [`claims_cmd`] — query authorship claims index via RPC (**M3.8**).
//! - [`uploads_cmd`] — query storage upload index via RPC (**M3.9**).

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(clippy::all)]

pub mod claims_cmd;
pub mod cli;
pub mod light_follow_quorum;
pub mod light_subjectivity;
pub mod light_wallet;
pub mod rpc;
pub mod uploads_cmd;
pub mod wallet_cmd;
pub mod wallet_store;

pub use claims_cmd::ClaimsListParams;
pub use cli::{cli_main, run_cli, CliError};
pub use light_subjectivity::{
    load_trusted_summary_file, save_trusted_summary_file, wallet_export_trusted_summary,
    ExportTrustedSummaryParams,
};
pub use light_wallet::LightScanParams;
pub use rpc::{BlockHeaderInfo, ChainTip, MempoolSummary, RpcClient, RpcError, SubmitTxResult};
pub use uploads_cmd::UploadsListParams;
pub use wallet_cmd::{
    ClaimParams, SendParams, UploadParams, DEFAULT_CLAIM_FEE, DEFAULT_RING_SIZE,
    DEFAULT_TRANSFER_FEE, DEFAULT_UPLOAD_REPLICATION,
};
pub use wallet_store::{KeyDerivation, WalletFile, WalletStoreError, DEFAULT_WALLET_PATH};
