# Read-only content gateway

People can read a permanent file by its content id without running a full
node, and without the gateway learning who asked.

`mfn-gateway` stores a file under the chunk-Merkle root the chain already
calls `data_root`. On every request it hashes the bytes again. If the root
does not match the id in the URL, it does not send the file.

The HTTP server accepts `GET /content/<64 hex>` and nothing else. The only
log line is:

```text
status=200 root=<id> bytes=<n>
```

There is no field for the client address, and the server does not print the
socket it accepted. Bind is loopback (`127.0.0.1` or `::1`). `0.0.0.0` is
refused. A Tor hidden service forwards to that loopback port:

```bash
mfn-gateway ingest --store ./objects --file paper.pdf
mfn-gateway onion --listen 127.0.0.1:8788
mfn-gateway serve --store ./objects --listen 127.0.0.1:8788
```

This does not change consensus, Path A, or F-A. It does not upload, and it
does not start a public listener.
