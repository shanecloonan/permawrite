# Deterministic source archives

`mfn-source-archive` packs a tree as ustar. Names are sorted. The timestamp is zero. The owner and group are zero. Two people who pack the same files get the same bytes and the same SHA-256.

Paths that contain `..`, a symlink, or more than 100 characters are refused. A header whose checksum does not match is refused on read.

```bash
cargo run --manifest-path distribution/source-archive/Cargo.toml -- ./src archive.tar
```

The digest is an application checksum of the tarball. It is not a consensus root and does not change Path A or F-A.
