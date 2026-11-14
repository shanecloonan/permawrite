# Read-only content gateway

`mfn-gateway` serves a file by the hex chunk-Merkle root of its bytes. That is the same root a storage commitment uses (`chunk_hash` then the binary Merkle tree). The gateway reads the local file and recomputes the root. If a byte changed, the response is `409` and the body is empty.

The access line is:

```text
gateway status=200 bytes=13 id=<64 hex>
```

There is no field for the requester. The accept loop drops the peer address before the request is parsed. Tor's snippet sets `SafeLogging 1` and forwards the hidden service to `127.0.0.1` only.

```bash
cargo run -p mfn-gateway -- /var/lib/permawrite/gateway 8080
```

`GET /health` returns `ok`. `GET /content/<64 hex>` returns the file when the root matches.

This is a local reader. It does not fetch from the public network, and it does not change consensus.
