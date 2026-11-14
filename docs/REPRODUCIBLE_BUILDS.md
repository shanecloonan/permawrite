# Reproducible builds

A Permawrite release binary can be checked by rebuilding it. The check does
not trust the person who published the file: it trusts that two builds of the
same commit, with the same pinned compiler, produce the same bytes.

This is packaging only. It does not change consensus, Path A, or F-A.

## What is pinned

| Input | Value |
| --- | --- |
| rustc | `1.83.0` (not the floating `stable` channel) |
| `SOURCE_DATE_EPOCH` | Unix time of the commit (`git log -1 --format=%ct`) |
| `CARGO_INCREMENTAL` | `0` |
| `RUSTFLAGS` | path remap to `/permawrite`, `target-cpu=generic`, no debug info, one codegen unit |
| Linux linker | `--build-id=none` so the GNU build id does not change between machines |

The tool is `mfn-repro` (`dist/mfn-repro`). The wrapper is
[`scripts/reproducible-build.sh`](../scripts/reproducible-build.sh). The tag
workflow [`.github/workflows/release-binaries.yml`](../.github/workflows/release-binaries.yml)
uses the same pin and flags.

## Check a published manifest

```bash
scripts/reproducible-build.sh --plan-only --epoch "$(git log -1 --format=%ct)" \
  --target x86_64-unknown-linux-gnu
cargo run -p mfn-repro -- compare published.sha256 rebuilt.sha256
```

`compare` exits 0 only when every artifact name and SHA-256 agree. Names that
escape the directory (`..`, absolute paths) are rejected.

## What this does not prove

A matching hash shows the binaries came from this source and this compiler. It
does not show that the source itself is honest. Sign the manifest as well
(next unit: multi-maintainer release signatures) before treating a download as
the project.
