# TS → Rust Porting Tracker

Source of truth: the TypeScript reference implementation in the sibling repo
[`cloonan-group/lib/network/*.ts`](https://github.com/shanecloonan/cloonan-group/tree/main/lib/network).
Each module below maps a TypeScript file to its Rust counterpart. Mark `[x]`
only when the Rust impl is **byte-for-byte compatible** with the TS reference
(verified by shared test vectors).

## Crates and modules

### `mfn-crypto` — discrete-log primitives (ed25519)

| TS file (`lib/network/`)   | Rust module (`mfn-crypto/src/`) | Status      |
| -------------------------- | ------------------------------- | ----------- |
| `primitives.ts` (encoding) | `scalar.rs`, `point.rs`         | [x] live    |
| `primitives.ts` (hashes)   | `hash.rs`                       | [x] live    |
| `primitives.ts` (Schnorr)  | `schnorr.rs`                    | [x] live    |
| `primitives.ts` (Pedersen) | `pedersen.rs`                   | [x] live    |
| `primitives.ts` (stealth)  | `stealth.rs`                    | [x] live    |
| `primitives.ts` (enc amt)  | `encrypted_amount.rs`           | [x] live    |
| `primitives.ts` (LSAG)     | `lsag.rs`                       | [x] live    |
| `codec.ts` (Writer/Reader) | `codec.rs`                      | [x] live    |
| `codec.ts` (DOMAIN tags)   | `domain.rs`                     | [x] live    |
| `clsag.ts`                 | `clsag.rs`                      | [x] live    |
| `range.ts`                 | `range.rs`                      | [x] live    |
| `bulletproofs.ts`          | `bulletproofs.rs`               | [x] live    |
| `oom.ts`                   | `oom.rs`                        | [x] live    |
| `vrf.ts`                   | `vrf.rs`                        | [x] live    |
| `decoy.ts`                 | `decoy.rs`                      | [x] live    |
| `utxo-tree.ts`             | `utxo_tree.rs`                  | [x] live    |
| `storage.ts` (merkle subset) | `merkle.rs`                   | [x] live    |

### `mfn-bls` — BLS12-381 signatures (planned crate)

| TS file       | Rust module     | Status      |
| ------------- | --------------- | ----------- |
| `bls.ts`      | `sig.rs`        | [x] live    |
| `kzg.ts`      | `kzg.rs`        | [ ] pending |

### `mfn-wire` — canonical binary codec (planned crate)

| TS file   | Rust module | Status      |
| --------- | ----------- | ----------- |
| `wire.ts` | `lib.rs`    | [ ] pending |

### `mfn-storage` — SPoRA + endowment math

| TS file        | Rust module       | Status      |
| -------------- | ----------------- | ----------- |
| `storage.ts` (commitment + SPoRA) | `commitment.rs`, `spora.rs` | [x] live |
| `endowment.ts` | `endowment.rs`    | [x] live    |

### `mfn-consensus` — state transition function

| TS file          | Rust module       | Status      |
| ---------------- | ----------------- | ----------- |
| `bonding.ts`     | `bonding.rs`      | [ ] pending (defaults + pure checks live; wire + `apply_block` next) |
| `emission.ts`    | `emission.rs`     | [x] live    |
| `storage.ts` (commitment) | `storage.rs` | [x] live (thin re-export of `mfn-storage::commitment`) |
| `transaction.ts` | `transaction.rs`  | [x] live    |
| `coinbase.ts`    | `coinbase.rs`     | [x] live    |
| `consensus.ts`   | `consensus.rs`    | [x] live    |
| `slashing.ts`    | `slashing.rs`     | [x] live    |
| `block.ts`       | `block/` (module) | [x] live (full state-transition: txs, slashing, finality, storage-proof verification, endowment-burden enforcement, two-sided treasury settlement) |
| — (authorship / `MFEX` / `claims_root`) | `claims.rs`, `extra_codec.rs`, `block.rs` (claims index + header) | [x] live — see [`docs/AUTHORSHIP.md`](./docs/AUTHORSHIP.md) |

### `mfn-runtime` — in-process chain + mempool (extracted crate)

| TS file (`lib/node/`) | Rust module (`mfn-runtime/src/`) | Status      |
| --------------------- | -------------------------------- | ----------- |
| — (chain driver)      | `chain.rs`                       | [x] live    |
| `mempool.ts`          | `mempool.rs`                     | [x] live    |
| — (producer)          | `producer.rs`                    | [x] live    |

### `mfn-store` — checkpoint + block-log persistence (extracted crate)

| TS file (`lib/node/`) | Rust module (`mfn-store/src/`) | Status      |
| --------------------- | ------------------------------ | ----------- |
| `store.ts` (subset)   | `fs.rs`, `redb_store.rs`, `trait.rs` (`ChainPersistence`) | [x] live (filesystem + `redb`; RocksDB TBD) |

### `mfn-rpc` — JSON-RPC dispatch (extracted crate)

| TS file (`lib/node/`) | Rust module (`mfn-rpc/src/`) | Status      |
| --------------------- | ---------------------------- | ----------- |
| `rpc.ts` (subset)     | `dispatch.rs`                | [x] live (TCP line server in `mfnd serve`; HTTP/WebSocket TBD) |

### `mfn-net` — P2P framing + handshakes + gossip (extracted crate)

| TS file (`lib/node/`) | Rust module (`mfn-net/src/`) | Status      |
| --------------------- | ---------------------------- | ----------- |
| — (wire framing)      | `frame.rs`                   | [x] live (`HelloV1` … `GossipEndV1`) |
| — (handshake)         | `handshake.rs`               | [x] live    |
| — (gossip)            | `gossip.rs`                  | [x] live (**M2.3.16** `TxV1` / `BlockV1` post-goodbye) |
| — (serve threads)     | `serve.rs`                   | [x] live (`mfnd serve` P2P accept/dial loops) |

### `mfn-node` — daemon binary (thin composition crate)

| TS file (`lib/node/`) | Rust impl                   | Status      |
| --------------------- | --------------------------- | ----------- |
| `rpc.ts` (HTTP/WS)    | —                           | [ ] pending (line JSON-RPC lives in **`mfn-rpc`** + `mfnd serve`) |
| `store.ts` (RocksDB)  | —                           | [ ] pending (**`mfn-store`**: fs + `redb` shipped) |
| `mempool.ts`          | re-export **`mfn-runtime`** | [x] live    |
| —                     | re-export **`mfn-net`** (`network` module) | [x] live (**M2.3.16** gossip wired via `p2p_gossip.rs`) |
| —                     | `bin/mfnd.rs` + `mfnd_serve.rs` + `p2p_gossip.rs` | [x] live |

### `mfn-wallet` — wallet binary (planned crate)

| TS file (`lib/wallet/`) | Rust impl       | Status      |
| ----------------------- | --------------- | ----------- |
| `wallet.ts`             | `wallet.rs`     | [ ] pending |
| `rpc-client.ts`         | `rpc_client.rs` | [ ] pending |
| —                       | `bin/mfn-cli.rs`| [ ] pending |

### `mfn-wasm` — WebAssembly bindings (planned crate)

WASM-bindgen wrappers so the Next.js `/blockchain` page can call the
real Rust primitives instead of the TS reference. Same UI, faster +
real crypto.

## Verification: shared test vectors

Each Rust module ships unit tests that include known test vectors
produced by the TS reference. The TS smoke suites live in
[`cloonan-group/scripts/smoke-*.ts`](https://github.com/shanecloonan/cloonan-group/tree/main/scripts);
the Rust suite is in this repo.

```bash
cargo test --workspace         # Rust unit + integration tests
```

When a vector diverges, the TS reference is wrong; fix it before
merging.
