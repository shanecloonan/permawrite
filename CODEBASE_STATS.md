# Codebase stats

Auto-generated snapshot of this repository (Rust sources, docs, diagrams, and config-like text; `target/`, `.git`, and common binary formats are excluded).

**Generated (UTC):** 2026-05-18T05:08:43.831Z

**Regenerate:** `node scripts/codebase-stats.mjs`

## Summary

| Metric | Value |
| --- | ---: |
| Source-like files scanned | 182 |
| Total lines (all scanned source-like files) | 56,121 |
| Non-empty lines | 49,191 |
| UTF-8 bytes (source-like) | 2,405,750 |
| Paths visited (before binary/huge skip) | 187 |
| Skipped (binary / non-UTF8 / over 4 MiB) | 1 |

## Lines of code by top-level directory

The first path segment (crate name, `docs`, etc.). Only source-like extensions are included.

| Directory | Files | Lines | Non-empty lines |
| --- | ---: | ---: | ---: |
| `mfn-consensus` | 51 | 14,736 | 13,601 |
| `docs` | 32 | 9,714 | 6,915 |
| `mfn-crypto` | 23 | 7,289 | 6,563 |
| `mfn-node` | 15 | 4,425 | 4,068 |
| `mfn-wallet` | 13 | 4,255 | 3,895 |
| `mfn-light` | 6 | 3,692 | 3,369 |
| `mfn-runtime` | 9 | 3,242 | 3,003 |
| `mfn-rpc` | 3 | 2,234 | 2,110 |
| `mfn-storage` | 6 | 1,960 | 1,782 |
| `mfn-net` | 6 | 1,527 | 1,361 |
| `mfn-store` | 7 | 1,135 | 974 |
| `mfn-bls` | 4 | 862 | 755 |
| `(root)` | 5 | 699 | 498 |
| `scripts` | 1 | 261 | 214 |
| `.github` | 1 | 90 | 83 |

## Lines of code by file extension

| Extension | Files | Lines | Non-empty lines | Bytes |
| --- | ---: | ---: | ---: | ---: |
| `.rs` | 121 | 43,614 | 40,122 | 1,607,003 |
| `.md` | 40 | 11,201 | 7,938 | 742,534 |
| `.svg` | 3 | 520 | 462 | 35,170 |
| `.toml` | 12 | 357 | 298 | 9,658 |
| `.mjs` | 1 | 261 | 214 | 7,024 |
| `.yml` | 1 | 90 | 83 | 2,361 |
| `.json` | 4 | 78 | 74 | 2,000 |

## Largest source files (by line count)

| Lines | File |
| ---: | --- |
| 2,178 | `mfn-rpc/src/dispatch.rs` |
| 1,804 | `docs/ROADMAP.md` |
| 1,684 | `mfn-consensus/tests/block_apply.rs` |
| 1,661 | `mfn-consensus/tests/integration.rs` |
| 1,553 | `mfn-runtime/src/mempool.rs` |
| 1,499 | `mfn-light/src/chain.rs` |
| 1,381 | `mfn-node/tests/mfnd_smoke.rs` |
| 1,022 | `mfn-light/tests/follow_chain.rs` |
| 1,011 | `mfn-consensus/src/consensus.rs` |
| 986 | `mfn-wallet/src/upload.rs` |
| 959 | `docs/ARCHITECTURE.md` |
| 870 | `mfn-crypto/src/utxo_tree.rs` |
| 836 | `mfn-node/src/mfnd_cli.rs` |
| 816 | `mfn-light/src/checkpoint.rs` |
| 814 | `mfn-wallet/src/wallet.rs` |
| 804 | `mfn-storage/src/spora.rs` |
| 783 | `mfn-consensus/src/block/apply.rs` |
| 715 | `mfn-node/tests/mempool_integration.rs` |
| 708 | `mfn-wallet/tests/end_to_end.rs` |
| 705 | `mfn-consensus/src/checkpoint_codec.rs` |

## Notes

- **Lines** include blank lines and comments; **non-empty** ignores lines that are only whitespace.
- **Source-like** extensions: `.cjs`, `.js`, `.json`, `.jsx`, `.md`, `.mjs`, `.rs`, `.sh`, `.sql`, `.svg`, `.toml`, `.ts`, `.tsx`, `.yaml`, `.yml`.
- **`Cargo.lock`** and other `*.lock` files are excluded so totals emphasize authored source.
- Requires **Node.js** only to regenerate this file; the Rust workspace does not depend on Node for builds.
