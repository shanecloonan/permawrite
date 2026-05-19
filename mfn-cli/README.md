# `mfn-cli`

Operator CLI for Permawrite (**M3.0**): talks to a running [`mfnd`](../mfn-node) node over newline-delimited JSON-RPC 2.0.

Wallet commands (`send`, `upload`, `scan`) will layer on [`mfn-wallet`](../mfn-wallet) in later M3 milestones.

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
```

Default RPC address: `127.0.0.1:18731` (mfnd default `--rpc-listen`).

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
