# Retrieving a file

`mfn-cli uploads get` fetches a file by its content id. The content id is the Merkle root of the shard stripe, the same `data_root` the node stores on the commitment.

```text
mfn-cli uploads get ROOT COMMIT out.bin --peer HOST:PORT --peer HOST:PORT --key upload.key
```

The command asks the node for that commitment and refuses to continue when the node's `data_root` is not `ROOT`. It then connects to each `--peer` through Tor's SOCKS proxy at `127.0.0.1:9050` and requests `GET /chunk/COMMIT/INDEX`. `--socks ADDR` picks another proxy. `--direct` dials the peers with no proxy.

Operators that only hold some `shard-NN.bin` files still serve those indexes. The client keeps the shard bytes most peers agree on, rebuilds the file from any four of the twelve shards, and drops the result if the rebuilt root is not `ROOT`. An `MFUP` payload is opened with the 32-byte `--key` file.

A three-operator test serves disjoint shard sets through a local SOCKS proxy, drops the third operator, and still decrypts the file.
