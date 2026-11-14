//! Read-only gateway for permanent files.
//!
//! A file is stored under the chunk-Merkle root the chain already uses as
//! `data_root`. The HTTP server is GET-only. It recomputes that root before
//! it sends bytes, and the access line has no client address.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod http;
mod store;

pub use http::{bind_loopback, format_access, respond, serve_one, AccessRecord, HttpError};
pub use store::{data_root, ingest, load_verified, onion_snippet, GatewayError, Store};
