//! Permawrite operator CLI library (**M3.0**).
//!
//! - [`rpc::RpcClient`] — newline-delimited JSON-RPC 2.0 over TCP to `mfnd serve`.
//! - [`cli`] — minimal command-line driver for `mfn-cli` binary.

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(clippy::all)]

pub mod cli;
pub mod rpc;

pub use cli::{cli_main, run_cli, CliError};
pub use rpc::{
    BlockHeaderInfo, ChainTip, MempoolSummary, RpcClient, RpcError,
};
