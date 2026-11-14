# Content-addressed mirrors

`mfn-mirror` names a directory three ways that do not depend on GitHub:

| Name | What it is |
| --- | --- |
| `bundle_sha256` | SHA-256 of a canonical bundle. This is the blob an operator uploads into chain storage. |
| `ipfs_cid` | CIDv1, raw codec, sha2-256, base32. |
| `bittorrent_v2` | SHA-256 of a v2 info dictionary. The piece root hashes a 16 KiB zero-padded block. |

Fetch URLs may be `ipfs://`, `magnet:?`, `file://`, or `http(s)://<v3>.onion/…`. A clearnet URL, including the public testnet address, is refused.

```bash
cargo run --manifest-path distribution/mirror/Cargo.toml -- ./dist
```

The bundle format is `permawrite-bundle-v1`, then each file's name, size, SHA-256, and bytes. Two directories with the same files produce the same three names. This checksum is not a consensus root and does not change Path A or F-A.
