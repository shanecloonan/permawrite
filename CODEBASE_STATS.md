# Codebase stats

Auto-generated snapshot of this repository (Rust sources, docs, diagrams, and config-like text; `target/`, `.git`, and common binary formats are excluded).

**Generated (UTC):** 2026-05-21T08:34:12.189Z

**Regenerate:** `node scripts/codebase-stats.mjs`

## Summary

| Metric | Value |
| --- | ---: |
| Source-like files scanned | 299 |
| Total lines (all scanned source-like files) | 88,062 |
| Non-empty lines | 78,401 |
| UTF-8 bytes (source-like) | 3,530,705 |
| Paths visited (before binary/huge skip) | 317 |
| Skipped (binary / non-UTF8 / over 4 MiB) | 1 |

## Lines of code by top-level directory

The first path segment (crate name, `docs`, etc.). Only source-like extensions are included.

| Directory | Files | Lines | Non-empty lines |
| --- | ---: | ---: | ---: |
| `mfn-consensus` | 56 | 16,901 | 15,596 |
| `mfn-cli` | 28 | 10,858 | 10,008 |
| `docs` | 35 | 10,726 | 7,614 |
| `mfn-node` | 33 | 8,611 | 7,981 |
| `mfn-crypto` | 23 | 7,292 | 6,565 |
| `mfn-wallet` | 15 | 4,931 | 4,522 |
| `mfn-runtime` | 14 | 4,323 | 4,001 |
| `mfn-light` | 6 | 3,895 | 3,556 |
| `mfn-rpc` | 4 | 3,565 | 3,384 |
| `mfn-net` | 11 | 3,502 | 3,207 |
| `mfn-storage-operator` | 14 | 2,679 | 2,453 |
| `demo` | 12 | 2,478 | 2,292 |
| `mfn-wasm` | 10 | 2,029 | 1,845 |
| `mfn-storage` | 6 | 1,960 | 1,782 |
| `mfn-store` | 12 | 1,814 | 1,573 |
| `mfn-bls` | 4 | 865 | 757 |
| `(root)` | 5 | 739 | 530 |
| `scripts` | 9 | 738 | 591 |
| `.github` | 2 | 156 | 144 |

## Lines of code by file extension

| Extension | Files | Lines | Non-empty lines | Bytes |
| --- | ---: | ---: | ---: | ---: |
| `.rs` | 199 | 70,893 | 65,405 | 2,542,107 |
| `.md` | 51 | 12,827 | 9,047 | 838,262 |
| `.js` | 7 | 1,980 | 1,856 | 62,125 |
| `.mjs` | 5 | 697 | 609 | 19,201 |
| `.toml` | 15 | 522 | 439 | 14,387 |
| `.svg` | 3 | 520 | 462 | 35,170 |
| `.json` | 10 | 244 | 234 | 7,105 |
| `.sh` | 7 | 223 | 205 | 7,562 |
| `.yml` | 2 | 156 | 144 | 4,786 |

## Largest source files (by line count)

| Lines | File |
| ---: | --- |
| 3,493 | `mfn-rpc/src/dispatch.rs` |
| 2,261 | `docs/ROADMAP.md` |
| 1,952 | `mfn-node/tests/mfnd_smoke.rs` |
| 1,916 | `mfn-cli/src/cli.rs` |
| 1,684 | `mfn-consensus/tests/block_apply.rs` |
| 1,661 | `mfn-consensus/tests/integration.rs` |
| 1,634 | `mfn-light/src/chain.rs` |
| 1,551 | `mfn-runtime/src/mempool.rs` |
| 1,128 | `mfn-consensus/tests/apply_block_proptest.rs` |
| 1,089 | `mfn-light/tests/follow_chain.rs` |
| 986 | `mfn-wallet/src/upload.rs` |
| 982 | `mfn-wallet/src/wallet.rs` |
| 972 | `mfn-node/src/mfnd_cli.rs` |
| 959 | `docs/ARCHITECTURE.md` |
| 921 | `mfn-consensus/src/consensus/engine.rs` |
| 870 | `mfn-crypto/src/utxo_tree.rs` |
| 816 | `mfn-light/src/checkpoint.rs` |
| 804 | `mfn-storage/src/spora.rs` |
| 801 | `demo/web/main.js` |
| 783 | `mfn-consensus/src/block/apply.rs` |

## Notes

- **Lines** include blank lines and comments; **non-empty** ignores lines that are only whitespace.
- **Source-like** extensions: `.cjs`, `.js`, `.json`, `.jsx`, `.md`, `.mjs`, `.rs`, `.sh`, `.sql`, `.svg`, `.toml`, `.ts`, `.tsx`, `.yaml`, `.yml`.
- **`Cargo.lock`** and other `*.lock` files are excluded so totals emphasize authored source.
- Requires **Node.js** only to regenerate this file; the Rust workspace does not depend on Node for builds.
