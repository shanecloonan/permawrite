# `mfn-node`

`mfn-node` is the Permawrite daemon composition crate. It builds the `mfnd` binary and wires together the extracted runtime, persistence, RPC, and networking crates:

- [`mfn-runtime`](../mfn-runtime/README.md) provides `Chain`, `Mempool`, JSON genesis parsing, and producer helpers.
- [`mfn-store`](../mfn-store/README.md) provides filesystem and `redb` persistence, replay validation, mempool/proof-pool persistence, peer persistence, and chunk inbox helpers.
- [`mfn-rpc`](../mfn-rpc/README.md) provides JSON-RPC method parsing and dispatch without owning sockets.
- [`mfn-net`](../mfn-net/README.md) provides P2P frames, handshakes, gossip, block sync, light-follow fetches, production messages, and chunk fan-out wire types.
- `mfn-node` owns the `mfnd` CLI, blocking RPC TCP accept loop, P2P serve threads, node store selection, boot/dial orchestration, and public daemon-facing glue.

Public runtime and store types are re-exported from `mfn-node` for compatibility, but new code should prefer the owning crates when it does not need daemon composition.

---

## Status

`mfnd` is an experimental testnet daemon, not production software. It supports:

- `status`, `save`, `run`, `step`, and `serve`.
- Versioned JSON genesis files.
- Filesystem or `redb` store selection.
- JSON-RPC 2.0 line protocol over TCP.
- Mempool, block/header, checkpoint, upload, claims, operator, and light-follow RPC surfaces.
- P2P boot dials, peer persistence, reconnect caps, genesis mismatch quarantine, block sync, tx/block gossip, production messages, and chunk fan-out/inbox flows.

The security posture is the same as the repo: pre-audit, experimental, and intended for testnet / controlled-devnet operation only.

---

## Main Modules

| Path | Responsibility |
| --- | --- |
| [`src/bin/mfnd.rs`](src/bin/mfnd.rs) | Process entry point. |
| [`src/lib.rs`](src/lib.rs) | Re-exports and daemon-facing crate boundary. |
| [`src/mfnd_cli.rs`](src/mfnd_cli.rs) | CLI parsing and command dispatch. |
| [`src/mfnd_serve.rs`](src/mfnd_serve.rs) | Blocking RPC TCP loop and P2P listener/dial orchestration. |
| [`src/node_store.rs`](src/node_store.rs) | Store backend selection between filesystem and `redb`. |
| [`src/p2p_boot.rs`](src/p2p_boot.rs) | Boot peer parsing, dedupe, self-dial filtering, and quarantine-aware planning. |
| [`src/p2p_fanout.rs`](src/p2p_fanout.rs) | Peer set and outbound fan-out accounting. |
| [`src/p2p_block_sync.rs`](src/p2p_block_sync.rs) | Sequential block catch-up and sync validation. |
| [`src/p2p_gossip.rs`](src/p2p_gossip.rs) | Tx/block gossip helpers around `mfn-net`. |
| [`src/p2p_chunk_fanout.rs`](src/p2p_chunk_fanout.rs) / [`src/p2p_chunk_inbox.rs`](src/p2p_chunk_inbox.rs) | Storage chunk fan-out and replica inbox assembly support. |
| [`src/p2p_light_follow_fetch.rs`](src/p2p_light_follow_fetch.rs) | Light-follow fetch integration. |
| [`src/runner.rs`](src/runner.rs) | Production engine configuration and loop glue. |

Runtime internals that used to be documented here now live in:

- [`mfn-runtime/src/chain.rs`](../mfn-runtime/src/chain.rs)
- [`mfn-runtime/src/mempool.rs`](../mfn-runtime/src/mempool.rs)
- [`mfn-runtime/src/producer.rs`](../mfn-runtime/src/producer.rs)
- [`mfn-store/src/lib.rs`](../mfn-store/src/lib.rs)
- [`mfn-rpc/src/dispatch.rs`](../mfn-rpc/src/dispatch.rs)
- [`mfn-net/src/lib.rs`](../mfn-net/src/lib.rs)

---

## Public API

```rust
use mfn_node::{mfnd_main, Chain, ChainStore, NetworkConfig, NodeStore, StoreBackend};

let _entrypoint = mfnd_main;
let _store_backend = StoreBackend::Redb;
```

The `Chain` and `ChainStore` names above are compatibility re-exports. Prefer `mfn_runtime::Chain` and `mfn_store::ChainStore` in library code that does not need the daemon crate.

---

## Dependencies

Runtime dependencies mirror `mfn-node/Cargo.toml`:

- First-party crates: `mfn-runtime`, `mfn-store`, `mfn-rpc`, `mfn-net`, `mfn-crypto`, `mfn-bls`, `mfn-storage`, `mfn-consensus`.
- Workspace utilities: `thiserror`, `serde`, `serde_json`, `hex`.
- Unix only: `ctrlc` for shutdown handling.

Dev-dependencies include `curve25519-dalek`, `hex`, `mfn-light`, `mfn-wallet`, and `serde_json` for end-to-end daemon tests.

---

## See Also

- [`docs/JOIN_TESTNET.md`](../docs/JOIN_TESTNET.md) — join the live testnet.
- [`docs/TESTNET.md`](../docs/TESTNET.md) — full operator / local-mesh runbook.
- [`scripts/public-devnet-v1/OPERATORS.md`](../scripts/public-devnet-v1/OPERATORS.md) — operator commands and launch gates.
- [`IMPLEMENTATION_STATUS.md`](../IMPLEMENTATION_STATUS.md) — repository-wide implementation status.
- [`docs/ROADMAP.md`](../docs/ROADMAP.md) — milestone history and next work.
