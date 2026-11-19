//! Air-gapped boot checklist.
//!
//! Read the env file and the systemd unit before the node starts. The check
//! passes only when dials are onion, binds are loopback, and the unit denies
//! every address that is not localhost.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod check;

pub use check::{check_boot, BootError};
