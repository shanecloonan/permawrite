//! Tor-only node setup.
//!
//! The generated unit binds RPC and P2P to loopback, dials only through a
//! loopback Tor SOCKS port, and asks systemd to deny every non-localhost
//! address. A clearnet peer is rejected before a file is written.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod setup;

pub use setup::{render, Listen, NodePlan, SetupError, SetupFiles};
