//! # `mfn-node`
//!
//! Node-side glue around [`mfn_consensus`]. This crate is the future home
//! of the mempool, P2P stack, persistent storage, RPC server, and producer
//! / voter loops — the things that turn a state-transition function into
//! a **running chain**.
//!
//! ## What this crate provides today (M2.0.3 + M2.0.4 + M2.0.12 + M2.1.0 + M2.1.1 + M2.1.2 + M2.1.3 + M2.1.4 + M2.1.5 + M2.1.6 + M2.1.6.1 + M2.1.7 + M2.1.8 + M2.1.8.1 + M2.1.9 + M2.1.10 + M2.1.11 + M2.1.12 + M2.1.13 + M2.1.14 + M2.1.15 + M2.1.16 + M2.1.17 + M2.1.18 + M2.2.8 + M2.2.10 + **M2.3.0 `network` scaffold** + **M2.3.1 P2P length-prefix framing** + **M2.3.2 `HelloV1` TCP handshake** + **M2.3.3 `mfnd serve --p2p-listen`** + **M2.3.4 `tcp_connect_hello_v1_handshake`** + **M2.3.5 `PingV1` / `PongV1` + `tcp_connect_peer_v1_handshake`** + **M2.3.6 `mfnd serve --p2p-dial`** + **M2.3.7 `P2P_HANDSHAKE_IO_TIMEOUT` on dial streams** + **M2.3.8 `ChainTipV1` P2P tip exchange** + **M2.3.9 `mfnd_p2p_peer_tip` stdout** + **M2.3.10 `GoodbyeV1` after tip on full peer handshake** + **M2.3.11 `mfnd_p2p_height_cmp` stdout** + **M2.3.12 `mfnd_p2p_handshake_ms` stdout** + **M2.3.13 P2P stdout `hid=` correlation** + **M2.3.14 sequential inbound `hid` smoke (`mfnd_smoke`)** + **M2.3.15 inbound `mfnd_p2p_handshake_abort` stderr**)
//!
//! - [`Chain`] — an in-memory chain driver that owns a [`ChainState`],
//!   exposes ergonomic queries (`tip_id`, `tip_height`, `validators`,
//!   `treasury`, …), and applies blocks sequentially through
//!   [`mfn_consensus::apply_block`].
//! - [`ChainError`] — typed wrapper around [`mfn_consensus::BlockError`]
//!   plus higher-level "chain hasn't reached genesis yet" guards.
//! - [`producer`] — block-production helpers. Wraps the consensus
//!   layer's `build_unsealed_header` / `try_produce_slot` /
//!   `cast_vote` / `finalize` / `seal_block` into a three-stage
//!   protocol ([`producer::build_proposal`] →
//!   [`producer::vote_on_proposal`] → [`producer::seal_proposal`]),
//!   with a one-call [`producer::produce_solo_block`] for the
//!   single-validator case.
//! - [`mempool`] (M2.0.12) — in-memory transaction pool. Admits
//!   txs after replicating every per-tx gate `apply_block` runs
//!   (`verify_transaction` + ring-membership + commit match +
//!   key-image dedup against chain + mempool). Implements
//!   replace-by-fee on key-image conflict, size-cap eviction of
//!   the lowest-fee entry, and `drain(max)` for highest-fee-first
//!   block inclusion. M2.0.13 adds storage-anchoring admission gates
//!   that mirror `apply_block`'s permanence checks.
//! - [`network`] (**M2.3.0** scaffold + **M2.3.1** [`network::frame`] + **M2.3.2** [`network::handshake`])
//!   — length-prefixed frames, [`network::hello_v1_handshake`], **M2.3.5** [`network::PingV1`] / [`network::PongV1`],
//!   [`network::tcp_connect_peer_v1_handshake`], and **M2.3.4** [`network::tcp_connect_hello_v1_handshake`];
//!   **M2.3.3** optional **`serve --p2p-listen`** (hello + listener pong) and **M2.3.6** optional **`serve --p2p-dial`**;
//!   **M2.3.7** [`network::P2P_HANDSHAKE_IO_TIMEOUT`] on outbound TCP dials matches accept-side timeouts;
//!   **M2.3.8** [`network::ChainTipV1`] exchange after ping/pong on P2P streams; **M2.3.9** **`mfnd_p2p_peer_tip`** line on stdout after each successful exchange; **M2.3.10** [`network::GoodbyeV1`] after the tip on the full [`network::tcp_connect_peer_v1_handshake_with_tip_exchange`] path; **M2.3.11** **`mfnd_p2p_height_cmp`** (local vs remote height) on stdout after **`mfnd_p2p_peer_tip`**; **M2.3.12** **`mfnd_p2p_handshake_ms`** (wall-clock through that same success point); **M2.3.13** matching **`hid=`** on those three stdout lines (**M2.3.15**: on **`--p2p-listen`**, **`hid`** is taken immediately after each **`accept`**); **M2.3.14** integration smoke for sequential accepts advancing **`hid`**; **M2.3.15** stderr **`mfnd_p2p_handshake_abort`** on inbound failures. [`NetworkConfig`] holds listener/dial defaults for future full gossip.
//! - [`genesis_spec`] (M2.1.2) — versioned JSON → [`mfn_consensus::GenesisConfig`] for
//!   operator-controlled devnets and tests (`--genesis` on `mfnd`).
//! - [`store`] (M2.1.0) — filesystem checkpoint store over
//!   [`Chain::encode_checkpoint`] / [`Chain::from_checkpoint_bytes`].
//!   **M2.1.7** adds `chain.blocks`: append-only `encode_block` records after
//!   each successful `mfnd step` apply (length-prefixed) plus
//!   [`ChainStore::read_block_log`] for wallet replay in tests.
//!   **M2.1.9** adds [`ChainStore::read_block_log_validated`] so tooling can
//!   reject truncated or mismatched `chain.blocks` against the checkpoint tip.
//! - **`mfnd`** (M2.1.1 + M2.1.2 + M2.1.3 + M2.1.4 + M2.1.5 + M2.1.6 + M2.1.6.1 + M2.1.7 + M2.1.8 + M2.1.8.1 + M2.1.9 + M2.1.10 + M2.1.11 + M2.1.12 + M2.1.13 + M2.1.14 + M2.1.15 + M2.1.16 + M2.1.17 + M2.1.18 + M2.2.8 + M2.2.10) — the `mfnd` reference binary (`status` /
//!   `save` / `run` / `step` / **`serve`**) wired through [`mfnd_main`]. Boots from
//!   [`demo_genesis::empty_local_dev_genesis`] by default, or from a JSON
//!   file via `--genesis` using [`genesis_config_from_json_path`]. The `step`
//!   command runs [`produce_solo_block`] + [`Chain::apply`] + checkpoint
//!   save for a single-validator genesis (devnet operator seeds via env vars);
//!   each block prepends a mempool [`Mempool::drain`] pass; **`step`** also
//!   appends canonical block bytes to `chain.blocks` after every successful
//!   apply (M2.1.7). **`serve`** keeps
//!   chain + mempool in-process and answers **JSON-RPC 2.0** (one UTF-8 line per
//!   connection; methods `get_tip`, `submit_tx`, **`get_block`**, **`get_block_header`**, **`get_mempool`**, **`get_mempool_tx`**, **`remove_mempool_tx`**, **`clear_mempool`**, **`get_checkpoint`**, **`save_checkpoint`**, **`list_methods`**, **`get_claims_for`**, **`get_claims_by_pubkey`**, **`list_recent_uploads`**, **`list_recent_claims`**, **`list_data_roots_with_claims`**) on `--rpc-listen` (default
//!   `127.0.0.1:18731`). **M2.3.3** / **M2.3.5** / **M2.3.6** / **M2.3.8** / **M2.3.9** / **M2.3.10** / **M2.3.11** / **M2.3.12** / **M2.3.13** / **M2.3.14** / **M2.3.15**: optional **`--p2p-listen ADDR`** binds a second TCP port, prints
//!   `mfnd_p2p_listening=…`, and spawns a background accept thread that runs [`network::hello_v1_handshake`] then
//!   [`network::recv_ping_send_pong`] then [`network::exchange_chain_tip_v1_as_listener`] then [`network::exchange_goodbye_v1_as_listener`] per peer (tip snapshot refreshed after each successful JSON-RPC); optional **`--p2p-dial ADDR`** spawns a background thread that runs
//!   [`network::tcp_connect_peer_v1_handshake_with_tip_exchange`] and prints `mfnd_p2p_dial_ok=…` then **`mfnd_p2p_peer_tip`** then **`mfnd_p2p_height_cmp`** then **`mfnd_p2p_handshake_ms`** on success (each line shares the same **`hid=`**; **M2.3.13**; outbound **`hid`** allocation unchanged by **M2.3.15**). JSON-RPC stays on the main thread. Requests may omit `jsonrpc` (legacy); responses always
//!   include `"jsonrpc":"2.0"` and echo `id` (or `null`). **`get_block`** (M2.1.10) returns
//!   `block_hex` for heights `1..=tip_height` via [`ChainStore::read_block_log_validated`].
//!   **`get_block_header`** (M2.1.11) returns `header_hex` ([`mfn_consensus::block_header_bytes`])
//!   and `block_id` for the same heights without shipping full block bodies.
//!   **`get_mempool`** (M2.1.12) returns `mempool_len` and sorted lowercase-hex **`tx_ids`**; `params` must be omitted, `null`, `{}`, or `[]`.
//!   **`get_mempool_tx`** (M2.1.13) returns `tx_hex` for one pending tx by **`tx_id`** (`params`: `{"tx_id":"…"}` or `["…"]`, 64 hex digits).
//!   **`remove_mempool_tx`** (M2.1.14) evicts one pending tx by **`tx_id`** if present; same **`params`** as **`get_mempool_tx`**; result includes **`removed`** and **`pool_len`**.
//!   **`clear_mempool`** (M2.1.15) drops every pending tx (`Mempool::clear`); same empty-only **`params`** rule as **`get_mempool`**; result includes **`cleared_count`** and **`pool_len`**.
//!   **`get_checkpoint`** (M2.1.16) returns canonical [`Chain::encode_checkpoint`](crate::Chain::encode_checkpoint) bytes as **`checkpoint_hex`** plus **`byte_len`**; same empty-only **`params`** as **`get_mempool`** (in-memory state, not a fresh disk read).
//!   **`save_checkpoint`** (M2.1.17) calls [`ChainStore::save`](crate::ChainStore::save) (same rotation as **`mfnd save`**); same empty-only **`params`**; success returns **`bytes_written`**, **`checkpoint_path`**, **`backup_path`**; IO errors use **`-32004`** (`CHECKPOINT_SAVE`).
//!   **`list_methods`** (M2.1.18) returns **`methods`**: every implemented method name as a JSON string, sorted lexicographically (includes **`list_methods`**); same empty-only **`params`** as **`get_mempool`**.
//!   **`get_claims_for`** (M2.2.8) returns **`claims`** for a **`data_root`** (`params`: `{"data_root":"…"}` or `[hex]`); **`get_claims_by_pubkey`** returns up to **`limit`** matches for a compressed pubkey (`params` object or `[pub, limit]`); **`list_recent_uploads`** pages **`ChainState.storage`** (`params` object: **`limit`**, **`offset`**, **`include_claims`**). **M2.2.10** adds derived views: **`list_recent_claims`** (flattened claims, same sort as pubkey discovery, paged) and **`list_data_roots_with_claims`** (`roots` with **`claim_count`** / **`max_claim_height`**, paged).
//!   **`submit_tx`** accepts
//!   `params` as `{"tx_hex":"…"}` or a one-element array `["…"]` (**M2.1.8.1**).
//!   Integration tests
//!   (`tests/mfnd_smoke.rs`, M2.1.6.1 + M2.1.7 + M2.1.8 + M2.1.8.1 + M2.1.9 + M2.1.10 + M2.1.11 + M2.1.12 + M2.1.13 + M2.1.14 + M2.1.15 + M2.1.16 + M2.1.17 + M2.1.18 + M2.2.8 + M2.2.10 + M2.3.3 + M2.3.4 + M2.3.5 + M2.3.6 + M2.3.7 + M2.3.8 + M2.3.9 + M2.3.10 + M2.3.11 + M2.3.12 + M2.3.13 + M2.3.14 + M2.3.15) drive `serve` over TCP
//!   including `submit_tx` error paths, a signed-transfer happy path, **`get_mempool`**, **`get_mempool_tx`**, **`remove_mempool_tx`**, **`clear_mempool`**, **`get_checkpoint`**, **`save_checkpoint`**, **`list_methods`**, **`get_claims_for`** / **`get_claims_by_pubkey`** / **`list_recent_uploads`** / **`list_recent_claims`** / **`list_data_roots_with_claims`** (empty pool + nonempty + wire round-trip + evict).
//!   `--blocks N` applies N blocks per `step` run; `--checkpoint-each` persists after every block.
//!
//! Everything below `Chain` / `producer` / `mempool` / `network` remains
//! deterministic and synchronous at the consensus boundary. `store` is intentionally the first
//! narrow IO boundary; `mfnd serve` adds a minimal blocking TCP loop on
//! localhost only by default; async runtimes and wide-area P2P remain later
//! M2.x sub-milestones.
//!
//! ## Design — why a separate crate from `mfn-consensus`?
//!
//! `mfn-consensus` is the **specification**: the state-transition function
//! and every byte format that goes on the wire. It must remain
//! library-pure (no IO, no async, no clock) so it can be ported to a
//! light-client crate, a wasm binding, and any number of independent
//! implementations without dragging in a runtime.
//!
//! `mfn-node` is the **first orchestration layer**. It tracks the live
//! chain tip, owns `ChainState`, and is where mempool / P2P / RPC will
//! eventually attach. Even at the skeleton stage that separation matters:
//! a light-client crate (`mfn-light`, future) wants `apply_block` but
//! *not* a `Chain` driver — and a daemon wants a `Chain` driver but
//! shouldn't be reimplementing one against the spec.
//!
//! ## Safety
//!
//! - `#![forbid(unsafe_code)]`.
//! - No background threads in the core chain/mempool/store APIs; no clocks, no async runtime.
//!   `mfnd serve` runs JSON-RPC on a blocking `std::net::TcpListener` loop on the main thread.
//!   **M2.3.3** `serve --p2p-listen` additionally spawns one `std::thread` for P2P accepts (**M2.3.5**: hello + ping/pong; **M2.3.7**: per-socket read/write timeouts; **M2.3.8**: [`ChainTipV1`] exchange) only; **M2.3.6** `serve --p2p-dial` may spawn one more for outbound dials (**M2.3.7** + **M2.3.8**: same timeout + tip wire as accepts).
//! - The filesystem IO lives in [`store`] and in [`genesis_spec::genesis_config_from_json_path`]
//!   (used by `mfnd --genesis`), isolated behind typed errors and deterministic
//!   consensus inputs elsewhere.

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(clippy::all)]

pub mod chain;
pub mod demo_genesis;
pub mod genesis_spec;
pub mod mempool;
pub mod network;
pub mod producer;
pub mod store;

mod mfnd_cli;
mod mfnd_serve;

pub use chain::{Chain, ChainConfig, ChainError, ChainStats};
pub use genesis_spec::{
    genesis_config_from_json_bytes, genesis_config_from_json_path, hex_seed32, GenesisSpecError,
    MAX_SYNTHETIC_DECOY_UTXOS,
};
pub use mempool::{AdmitError, AdmitOutcome, Mempool, MempoolConfig, MempoolEntry};
pub use network::NetworkConfig;
pub use producer::{
    build_proposal, produce_solo_block, seal_proposal, vote_on_proposal, BlockInputs,
    BlockProposal, ProducerError,
};
pub use store::{ChainStore, StoreError, StoreSave};

/// Entry point for the `mfnd` binary (`cargo run -p mfn-node --bin mfnd`).
#[must_use]
pub fn mfnd_main() -> std::process::ExitCode {
    mfnd_cli::mfnd_main()
}
