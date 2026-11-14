# Release catalog

`mfn-catalog` picks a release only when enough independent mirrors report the same bundle hash.

`threshold` is at least 2. One mirror is never enough. If two different hashes each reach the threshold, that version is a split and is skipped. Among the versions that agree, the newest dotted version wins.

Mirror names are short labels (`alice`, `bob`). A URL is not a mirror name, so a catalog cannot quietly point at GitHub or a clearnet host.

```bash
cargo run --manifest-path distribution/catalog/Cargo.toml -- catalog.txt
```

This is an application choice about which bytes to fetch. It does not change consensus, Path A, or F-A.
