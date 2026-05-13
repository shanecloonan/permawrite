# Codebase stats

Auto-generated snapshot of this repository (Rust sources, docs, diagrams, and config-like text; `target/`, `.git`, and common binary formats are excluded).

**Generated (UTC):** 2026-05-13T19:42:20.024Z

**Regenerate:** `node scripts/codebase-stats.mjs`

## Summary

| Metric | Value |
| --- | ---: |
| Source-like files scanned | 114 |
| Total lines (all scanned source-like files) | 44,609 |
| Non-empty lines | 39,014 |
| UTF-8 bytes (source-like) | 1,936,571 |
| Paths visited (before binary/huge skip) | 120 |
| Skipped (binary / non-UTF8 / over 4 MiB) | 1 |

## Lines of code by top-level directory

The first path segment (crate name, `docs`, etc.). Only source-like extensions are included.

| Directory | Files | Lines | Non-empty lines |
| --- | ---: | ---: | ---: |
| `mfn-consensus` | 16 | 13,234 | 12,278 |
| `docs` | 31 | 8,616 | 6,228 |
| `mfn-crypto` | 22 | 6,625 | 5,950 |
| `mfn-node` | 10 | 4,393 | 4,034 |
| `mfn-wallet` | 12 | 3,995 | 3,662 |
| `mfn-light` | 6 | 3,915 | 3,571 |
| `mfn-storage` | 6 | 1,960 | 1,782 |
| `mfn-bls` | 4 | 862 | 755 |
| `(root)` | 5 | 691 | 490 |
| `scripts` | 1 | 261 | 214 |
| `.github` | 1 | 57 | 50 |

## Lines of code by file extension

| Extension | Files | Lines | Non-empty lines | Bytes |
| --- | ---: | ---: | ---: | ---: |
| `.rs` | 62 | 33,445 | 30,853 | 1,253,531 |
| `.md` | 39 | 10,122 | 7,268 | 634,874 |
| `.svg` | 3 | 480 | 425 | 32,915 |
| `.mjs` | 1 | 261 | 214 | 7,024 |
| `.toml` | 8 | 244 | 204 | 6,884 |
| `.yml` | 1 | 57 | 50 | 1,343 |

## Largest source files (by line count)

| Lines | File |
| ---: | --- |
| 3,690 | `mfn-consensus/src/block.rs` |
| 1,661 | `mfn-consensus/tests/integration.rs` |
| 1,552 | `mfn-node/src/mempool.rs` |
| 1,515 | `mfn-consensus/src/chain_checkpoint.rs` |
| 1,499 | `mfn-light/src/chain.rs` |
| 1,353 | `mfn-consensus/src/transaction.rs` |
| 1,039 | `mfn-light/src/checkpoint.rs` |
| 1,022 | `mfn-light/tests/follow_chain.rs` |
| 1,020 | `docs/ROADMAP.md` |
| 1,011 | `mfn-consensus/src/consensus.rs` |
| 949 | `mfn-wallet/src/upload.rs` |
| 929 | `docs/ARCHITECTURE.md` |
| 870 | `mfn-crypto/src/utxo_tree.rs` |
| 804 | `mfn-storage/src/spora.rs` |
| 774 | `mfn-consensus/src/header_verify.rs` |
| 773 | `mfn-wallet/src/wallet.rs` |
| 729 | `mfn-consensus/src/validator_evolution.rs` |
| 715 | `mfn-node/tests/mempool_integration.rs` |
| 703 | `mfn-crypto/src/bulletproofs.rs` |
| 695 | `docs/CONSENSUS.md` |

## Notes

- **Lines** include blank lines and comments; **non-empty** ignores lines that are only whitespace.
- **Source-like** extensions: `.cjs`, `.js`, `.json`, `.jsx`, `.md`, `.mjs`, `.rs`, `.sh`, `.sql`, `.svg`, `.toml`, `.ts`, `.tsx`, `.yaml`, `.yml`.
- **`Cargo.lock`** and other `*.lock` files are excluded so totals emphasize authored source.
- Requires **Node.js** only to regenerate this file; the Rust workspace does not depend on Node for builds.
