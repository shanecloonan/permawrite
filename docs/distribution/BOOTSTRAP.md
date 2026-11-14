# Offline bootstrap check

`mfn-bootstrap` reads a bootstrap document and checks a directory you already have. It does not open a socket.

The document lists each file's SHA-256 and one or more fetch URLs. Allowed URLs are `ipfs://`, `magnet:?`, `file://`, and `http(s)://*.onion/`. A clearnet URL, including GitHub and the public testnet address, refuses the whole document. A document with no fetch URL is also refused: there is nowhere to get the bytes from except a channel that can survive a takedown.

```bash
cargo run --manifest-path distribution/bootstrap/Cargo.toml -- bootstrap.txt ./unpacked
```

`bootstrap ok` means every listed file matches. This is an application check. It does not change consensus, Path A, or F-A.
