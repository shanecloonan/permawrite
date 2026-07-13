//! # `mfn-rpc`
//!
//! JSON-RPC 2.0 request parsing and method dispatch for `mfnd serve`: chain,
//! mempool, checkpoint, block log, and authorship discovery views.
//!
//! ## Crate boundaries
//!
//! | Crate | Role |
//! |-------|------|
//! | `mfn-consensus` | Pure STF + wire formats |
//! | `mfn-runtime` | In-memory chain + mempool |
//! | `mfn-store` | Checkpoint + block log reads/writes |
//! | **`mfn-rpc`** | JSON-RPC dispatch (no sockets) |
//! | `mfn-net` | P2P framing + handshakes |
//! | `mfn-node` | RPC TCP loop + `mfnd` binary |
//!
//! ## Safety
//!
//! - `#![forbid(unsafe_code)]`.
//! - No TCP listeners and no background threads in this crate.

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(clippy::all)]

mod dispatch;

pub use dispatch::rpc_codes;
pub use dispatch::{
    light_follow_v1_to_json, parse_and_dispatch_serve, parse_and_dispatch_serve_opts, rpc_error,
    rpc_success, FraudContestsHook, P2pAnchorPeersHook, P2pLightFollowHook,
    P2pLightFollowQuorumHook, P2pStatusHook, ProofPoolPersistHook, ServeDispatchOpts,
};
