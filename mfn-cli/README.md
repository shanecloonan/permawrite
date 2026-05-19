# `mfn-cli`

Operator CLI for Permawrite (**M3.0** / **M3.1**): talks to a running [`mfnd`](../mfn-node) node over newline-delimited JSON-RPC 2.0 and drives [`mfn-wallet`](../mfn-wallet) for local key material + chain scanning.

`upload` is planned in **M3.3**.

## Build

```bash
cargo build -p mfn-cli --release
```

## Usage

```bash
# Chain tip (same fields as mfnd get_tip RPC)
mfn-cli --rpc 127.0.0.1:18731 tip

# Discover server methods
mfn-cli methods

# Block header at height 1
mfn-cli block-header 1

# Mempool tx ids
mfn-cli mempool

# Arbitrary call (pretty-printed JSON result)
mfn-cli call get_tip
mfn-cli call get_block_header --params '{"height":1}'

# Wallet (writes wallet.json in cwd by default)
mfn-cli wallet new
mfn-cli wallet address
mfn-cli --wallet ./alice.json wallet scan
mfn-cli wallet balance

# Send (CLSAG transfer + submit_tx; mine with `mfnd step` after stopping serve)
mfn-cli --rpc 127.0.0.1:<PORT> wallet send <VIEW_PUB_HEX> <SPEND_PUB_HEX> <AMOUNT> \
  --fee 10000 --ring-size 8
```

Default RPC address: `127.0.0.1:18731` (mfnd default `--rpc-listen`).

Default wallet file: `wallet.json` (override with `--wallet PATH`). The file stores a 32-byte `seed_hex` and optional `scan_height`. **Back it up** — it is the only recovery path for funds.

`wallet scan` / `wallet balance` fetch every block from height `1` through the node tip via `get_block`, decode with `mfn-consensus`, and feed [`Wallet::ingest_block`](../mfn-wallet/src/wallet.rs). This is correct but O(chain height) per invocation; persistent UTXO snapshots are a later optimization.

`wallet send` syncs the chain, loads UTXO set + `get_checkpoint` for decoys, builds a CLSAG transfer with [`Wallet::build_transfer`](../mfn-wallet/src/wallet.rs), and broadcasts via `submit_tx`. Locally spent inputs are recorded in `pending_spent_utxo_keys` until the tx mines. To include the tx in a block: stop `mfnd serve` (so `mempool.bytes` is flushed), then run `mfnd step --blocks 1` (which reloads the durable mempool per **M2.3.21**).

## Library

```rust
use mfn_cli::RpcClient;

let mut client = RpcClient::new("127.0.0.1:18731");
let tip = client.get_tip()?;
```

## Tests

```bash
cargo test -p mfn-cli
```

Integration tests spawn `mfnd serve` on an ephemeral port.
