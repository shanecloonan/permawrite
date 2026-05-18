# `mfn-rpc`

JSON-RPC 2.0 method dispatch for `mfnd serve` (no TCP/HTTP).

- **`parse_and_dispatch_serve`** — `get_tip`, `submit_tx`, `get_block`, mempool methods, checkpoint I/O, authorship discovery (**M2.2.8** / **M2.2.10**).

`mfn-node` binds a blocking TCP listener and passes one request line per connection.
