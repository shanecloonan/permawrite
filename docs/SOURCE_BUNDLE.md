# Deterministic source bundle

The source of a release can be packed without `git archive` and without a
timestamp from the machine that packed it.

`mfn-source-bundle` writes a ustar:

- paths are sorted, so the order you pass files does not matter
- uid and gid are 0
- the timestamp is the `SOURCE_DATE_EPOCH` you pass (the commit time)
- `.git`, `target`, and `..` are refused

Two packs of the same files at the same epoch are the same bytes. The
SHA-256 of that archive is a content address for the source. It can sit next
to a CID or a magnet from the mirror tool.

```bash
mfn-source-bundle pack --epoch "$(git log -1 --format=%ct)" \
  --file Cargo.toml=./Cargo.toml --out source.tar
```

This does not change consensus, Path A, or F-A.
