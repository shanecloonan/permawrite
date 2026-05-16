# Codebase stats

Auto-generated snapshot of this repository (Rust sources, docs, diagrams, and config-like text; `target/`, `.git`, and common binary formats are excluded).

**Generated (UTC):** 2026-05-15T18:39:51.729Z

**Regenerate:** `node scripts/codebase-stats.mjs`

## Summary

| Metric | Value |
| --- | ---: |
| Source-like files scanned | 130 |
| Total lines (all scanned source-like files) | 52,210 |
| Non-empty lines | 45,814 |
| UTF-8 bytes (source-like) | 2,278,348 |
| Paths visited (before binary/huge skip) | 135 |
| Skipped (binary / non-UTF8 / over 4 MiB) | 1 |

## Lines of code by top-level directory

The first path segment (crate name, `docs`, etc.). Only source-like extensions are included.

| Directory | Files | Lines | Non-empty lines |
| --- | ---: | ---: | ---: |
| `mfn-consensus` | 19 | 14,298 | 13,267 |
| `docs` | 32 | 9,522 | 6,796 |
| `mfn-node` | 20 | 9,396 | 8,696 |
| `mfn-crypto` | 23 | 7,182 | 6,465 |
| `mfn-wallet` | 13 | 4,252 | 3,893 |
| `mfn-light` | 6 | 3,692 | 3,369 |
| `mfn-storage` | 6 | 1,960 | 1,782 |
| `mfn-bls` | 4 | 862 | 755 |
| `(root)` | 5 | 696 | 494 |
| `scripts` | 1 | 261 | 214 |
| `.github` | 1 | 90 | 83 |

## Lines of code by file extension

| Extension | Files | Lines | Non-empty lines | Bytes |
| --- | ---: | ---: | ---: | ---: |
| `.rs` | 75 | 40,034 | 36,984 | 1,501,445 |
| `.md` | 40 | 11,049 | 7,856 | 726,301 |
| `.svg` | 3 | 480 | 425 | 32,915 |
| `.mjs` | 1 | 261 | 214 | 7,024 |
| `.toml` | 8 | 257 | 215 | 7,302 |
| `.yml` | 1 | 90 | 83 | 2,361 |
| `.json` | 2 | 39 | 37 | 1,000 |

## Largest source files (by line count)

| Lines | File |
| ---: | --- |
| 3,776 | `mfn-consensus/src/block.rs` |
| 2,289 | `mfn-node/src/mfnd_serve.rs` |
| 1,663 | `docs/ROADMAP.md` |
| 1,661 | `mfn-consensus/tests/integration.rs` |
| 1,553 | `mfn-node/src/mempool.rs` |
| 1,499 | `mfn-light/src/chain.rs` |
| 1,372 | `mfn-consensus/src/chain_checkpoint.rs` |
| 1,353 | `mfn-consensus/src/transaction.rs` |
| 1,022 | `mfn-light/tests/follow_chain.rs` |
| 1,011 | `mfn-consensus/src/consensus.rs` |
| 980 | `mfn-wallet/src/upload.rs` |
| 968 | `docs/ARCHITECTURE.md` |
| 906 | `mfn-node/tests/mfnd_smoke.rs` |
| 870 | `mfn-crypto/src/utxo_tree.rs` |
| 823 | `mfn-wallet/src/wallet.rs` |
| 816 | `mfn-light/src/checkpoint.rs` |
| 810 | `mfn-consensus/src/header_verify.rs` |
| 804 | `mfn-storage/src/spora.rs` |
| 730 | `mfn-consensus/src/validator_evolution.rs` |
| 715 | `mfn-node/tests/mempool_integration.rs` |

## Notes

- **Lines** include blank lines and comments; **non-empty** ignores lines that are only whitespace.
- **Source-like** extensions: `.cjs`, `.js`, `.json`, `.jsx`, `.md`, `.mjs`, `.rs`, `.sh`, `.sql`, `.svg`, `.toml`, `.ts`, `.tsx`, `.yaml`, `.yml`.
- **`Cargo.lock`** and other `*.lock` files are excluded so totals emphasize authored source.
- Requires **Node.js** only to regenerate this file; the Rust workspace does not depend on Node for builds.
