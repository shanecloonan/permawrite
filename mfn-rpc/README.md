# `mfn-rpc`

JSON-RPC 2.0 method dispatch for `mfnd serve` (no TCP/HTTP).

- **`parse_and_dispatch_serve`** / **`parse_and_dispatch_serve_opts`** — `get_tip`, **`get_chain_params`** (emission / endowment / bonding + treasury), `submit_tx`, `get_block`, mempool methods, checkpoint I/O, **`list_utxos`** (public decoy pool rows), authorship discovery (**M2.2.8** / **M2.2.10**); optional **`ServeDispatchOpts::on_fresh_tx`** for P2P mempool fan-out (**M2.3.20**).

`mfn-node` binds a blocking TCP listener and passes one request line per connection.
