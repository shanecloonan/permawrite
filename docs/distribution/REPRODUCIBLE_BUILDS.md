# Reproducible release builds

Permawrite binaries must be rebuildable by someone who does not trust the
machine that uploaded them. The profile lives in `distribution/repro` and
does not change consensus, genesis, or the default node.

## Pin

| | |
| --- | --- |
| Toolchain | Rust **1.83.0** (`distribution/repro/rust-toolchain.toml`) |
| Clock | `SOURCE_DATE_EPOCH=0` |
| Paths | `--remap-path-prefix=$PWD=/permawrite` so a home directory or CI runner path is not in the binary |
| Symbols | `-C symbol-mangling-version=v0` |
| Linux linker | `-C link-arg=-Wl,--build-id=none` (omitted on macOS and Windows; those linkers reject it) |
| Cargo | incremental off, one codegen unit, thin LTO, no debug info |

`mfnd`, `mfn-cli`, and `mfn-storage-operator` are the release set.

## Check

Print the profile without compiling:

```bash
bash scripts/distribution/repro-build.sh --plan-only
```

Hash a directory, or fail if two directories differ:

```bash
cargo run --manifest-path distribution/repro/Cargo.toml -- hash release-staging/linux
cargo run --manifest-path distribution/repro/Cargo.toml -- compare dir-a dir-b
```

A real double build (slow, local only):

```bash
bash scripts/distribution/repro-build.sh --build
```

That compiles twice into separate target directories and exits non-zero if any byte differs. Symlinks are rejected. Checksum names may not contain `..`.

## Release workflow

`.github/workflows/release-binaries.yml` pins `1.83.0`, sets the same clock and remap, and writes checksums with `sha256sum` or `shasum -a 256`. macOS images do not ship `sha256sum`. The workflow still runs only on tags and `workflow_dispatch`. Pull requests do not build release binaries.
