# `mfn-store`

Checkpoint and append-only block-log persistence for `mfnd`.

- **`ChainPersistence`** — trait implemented by filesystem [`ChainStore`](src/fs.rs) and embedded [`RedbChainStore`](src/redb_store.rs).
- **`load_or_genesis`**, **`save`**, **`append_block`**, **`read_block_log_validated`**.

RocksDB / fork-choice replay remain future work.
