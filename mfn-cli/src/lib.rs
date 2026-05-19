//! Permawrite operator CLI library (**M3.0** / **M3.1**).
//!
//! - [`rpc::RpcClient`] — newline-delimited JSON-RPC 2.0 over TCP to `mfnd serve`.
//! - [`cli`] — command-line driver for `mfn-cli` binary.
//! - [`wallet_store`] / [`wallet_cmd`] — on-disk wallet file, scan, and send (**M3.1** / **M3.2**).

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(clippy::all)]

pub mod cli;
pub mod rpc;
pub mod wallet_cmd;
pub mod wallet_store;

pub use cli::{cli_main, run_cli, CliError};
pub use rpc::{
    BlockHeaderInfo, ChainTip, MempoolSummary, RpcClient, RpcError, SubmitTxResult,
};
pub use wallet_cmd::{
    SendParams, UploadParams, DEFAULT_RING_SIZE, DEFAULT_TRANSFER_FEE, DEFAULT_UPLOAD_REPLICATION,
};
pub use wallet_store::{KeyDerivation, WalletFile, WalletStoreError, DEFAULT_WALLET_PATH};
