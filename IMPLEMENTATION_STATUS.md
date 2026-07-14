# Rust Implementation Status

This file tracks the Rust crates and modules that make up Permawrite. The repository's docs, Rust code, and protocol golden vectors are the source of truth.

Mark `[x]` only when the Rust module is implemented, documented, and covered by deterministic tests or protocol vectors where consensus bytes are involved.

## Release posture

Permawrite is an **experimental public testnet** implementation, not production software. The Rust stack includes the reference daemon, JSON-RPC control plane, P2P sync/gossip paths, wallet CLI flows, storage-operator tooling, launch helper scripts, health checks, support bundles, and operator runbooks. A live mesh is reachable on the public internet; new participants start at [`docs/JOIN_TESTNET.md`](docs/JOIN_TESTNET.md). It remains **pre-audit** with test-only economic value; public RPC exposure, public deterministic validator seeds, wallet seed handling, storage artifact backup, and operator mistakes are still critical risks.

Use these status levels when publishing or reviewing a release candidate:

| Level | Status | Required evidence |
| --- | --- | --- |
| Public testnet | [x] live | Boot peers published, VPS soak + participant rehearsal evidence, [`docs/JOIN_TESTNET.md`](docs/JOIN_TESTNET.md), green CI on release commit, private RPC posture. |
| Local developer mesh | [x] live | `docs/TESTNET.md`, `scripts/public-devnet-v1/OPERATORS.md`, local health checks, support/recovery helpers, and green local CI mirror. |
| Incentivized/adversarial testnet | [ ] not ready | Requires deeper threat modeling, broader adversarial testing, external security review, rehearsed incident response, and production-grade operator custody procedures. |

## Crates and modules

### `mfn-crypto` — discrete-log primitives (ed25519)

| Area | Rust module (`mfn-crypto/src/`) | Status |
| --- | --- | --- |
| Scalar and point helpers | `scalar.rs`, `point.rs` | [x] live |
| Hashing and domain separation | `hash.rs`, `domain.rs` | [x] live |
| Canonical codec | `codec.rs` | [x] live |
| Schnorr and authorship claims | `schnorr.rs`, `authorship.rs` | [x] live |
| Pedersen, stealth, encrypted amounts | `pedersen.rs`, `stealth.rs`, `encrypted_amount.rs` | [x] live |
| Ring signatures and range proofs | `lsag.rs`, `clsag.rs`, `range.rs`, `bulletproofs.rs`, `oom.rs` | [x] live |
| VRF, decoys, accumulators, Merkle trees | `vrf.rs`, `decoy.rs`, `utxo_tree.rs`, `merkle.rs` | [x] live |

### `mfn-bls` — BLS12-381 signatures

| Area | Rust module | Status |
| --- | --- | --- |
| BLS signatures and aggregation | `sig.rs` | [x] live |
| KZG commitments | `kzg.rs` | [ ] pending |

### `mfn-wire` — canonical binary codec

| Area | Rust module | Status |
| --- | --- | --- |
| Dedicated wire crate | `lib.rs` | [ ] pending |

### `mfn-storage` — SPoRA and endowment math

| Area | Rust module | Status |
| --- | --- | --- |
| Storage commitments and SPoRA | `commitment.rs`, `spora.rs` | [x] live |
| Endowment math | `endowment.rs` | [x] live |

### `mfn-consensus` — state transition function

| Area | Rust module | Status |
| --- | --- | --- |
| Bonding defaults and wire ops | `bonding.rs`, `bond_wire.rs` | [x] live |
| Emission and coinbase | `emission.rs`, `coinbase.rs` | [x] live |
| Transactions and storage commitments | `transaction.rs`, `storage.rs` | [x] live |
| Consensus, slashing, and validator roots | `consensus.rs`, `slashing.rs`, `validator_evolution.rs` | [x] live |
| Block state transition and codecs | `block/` | [x] live |
| Authorship claims | `claims.rs`, `extra_codec.rs`, `block.rs` | [x] live |

### Runtime, node, wallet, and network crates

| Crate | Rust module(s) | Status |
| --- | --- | --- |
| `mfn-runtime` | `chain.rs`, `mempool.rs`, `producer.rs` | [x] live |
| `mfn-store` | `fs.rs`, `redb_store.rs`, `trait.rs` | [x] live |
| `mfn-rpc` | `dispatch.rs` | [x] live |
| `mfn-net` | `frame.rs`, `handshake.rs`, `gossip.rs`, `serve.rs` | [x] live |
| `mfn-node` | `bin/mfnd.rs`, `mfnd_serve.rs`, `p2p_gossip.rs` | [x] live |
| `mfn-wallet` | wallet library and CLI-facing primitives | [x] live |
| `mfn-storage-operator` | storage proof and chunk replication helpers | [x] live |
| `mfn-cli` | RPC client, wallet, upload, claim, operator, and support-record commands | [x] live |
| `mfn-wasm` | WebAssembly packaging and bindings | [x] devnet-grade |

## Verification

Consensus-critical encodings are protected by Rust unit tests, integration tests, and checked-in protocol golden vectors under `docs/interop/`.

```bash
cargo test --workspace
```

When a protocol vector changes, update the Rust implementation, the tests, and the relevant docs in the same change. Treat unplanned byte drift as a consensus bug.