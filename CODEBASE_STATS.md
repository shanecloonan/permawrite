# Codebase stats

Auto-generated snapshot of this repository (Rust sources, docs, diagrams, and config-like text; `target/`, `.git`, and common binary formats are excluded).

**Generated (UTC):** 2026-05-15T02:19:31.661Z

**Regenerate:** `node scripts/codebase-stats.mjs`

## Summary

| Metric | Value |
| --- | ---: |
| Source-like files scanned | 124 |
| Total lines (all scanned source-like files) | 49,589 |
| Non-empty lines | 43,474 |
| UTF-8 bytes (source-like) | 2,162,345 |
| Paths visited (before binary/huge skip) | 129 |
| Skipped (binary / non-UTF8 / over 4 MiB) | 1 |

## Lines of code by top-level directory

The first path segment (crate name, `docs`, etc.). Only source-like extensions are included.

| Directory | Files | Lines | Non-empty lines |
| --- | ---: | ---: | ---: |
| `mfn-consensus` | 17 | 13,639 | 12,655 |
| `docs` | 31 | 9,177 | 6,578 |
| `mfn-node` | 19 | 8,564 | 7,905 |
| `mfn-crypto` | 22 | 6,656 | 5,979 |
| `mfn-wallet` | 12 | 3,995 | 3,662 |
| `mfn-light` | 6 | 3,692 | 3,369 |
| `mfn-storage` | 6 | 1,960 | 1,782 |
| `mfn-bls` | 4 | 862 | 755 |
| `(root)` | 5 | 693 | 492 |
| `scripts` | 1 | 261 | 214 |
| `.github` | 1 | 90 | 83 |

## Lines of code by file extension

| Extension | Files | Lines | Non-empty lines | Bytes |
| --- | ---: | ---: | ---: | ---: |
| `.rs` | 70 | 37,761 | 34,865 | 1,416,497 |
| `.md` | 39 | 10,701 | 7,635 | 695,260 |
| `.svg` | 3 | 480 | 425 | 32,915 |
| `.mjs` | 1 | 261 | 214 | 7,024 |
| `.toml` | 8 | 257 | 215 | 7,288 |
| `.yml` | 1 | 90 | 83 | 2,361 |
| `.json` | 2 | 39 | 37 | 1,000 |

## Largest source files (by line count)

| Lines | File |
| ---: | --- |
| 3,690 | `mfn-consensus/src/block.rs` |
| 1,661 | `mfn-consensus/tests/integration.rs` |
| 1,580 | `mfn-node/src/mfnd_serve.rs` |
| 1,552 | `mfn-node/src/mempool.rs` |
| 1,543 | `docs/ROADMAP.md` |
| 1,499 | `mfn-light/src/chain.rs` |
| 1,353 | `mfn-consensus/src/transaction.rs` |
| 1,204 | `mfn-consensus/src/chain_checkpoint.rs` |
| 1,022 | `mfn-light/tests/follow_chain.rs` |
| 1,011 | `mfn-consensus/src/consensus.rs` |
| 961 | `docs/ARCHITECTURE.md` |
| 949 | `mfn-wallet/src/upload.rs` |
| 870 | `mfn-crypto/src/utxo_tree.rs` |
| 831 | `mfn-node/tests/mfnd_smoke.rs` |
| 816 | `mfn-light/src/checkpoint.rs` |
| 804 | `mfn-storage/src/spora.rs` |
| 774 | `mfn-consensus/src/header_verify.rs` |
| 773 | `mfn-wallet/src/wallet.rs` |
| 729 | `mfn-consensus/src/validator_evolution.rs` |
| 715 | `mfn-node/tests/mempool_integration.rs` |

## Notes

- **Lines** include blank lines and comments; **non-empty** ignores lines that are only whitespace.
- **Source-like** extensions: `.cjs`, `.js`, `.json`, `.jsx`, `.md`, `.mjs`, `.rs`, `.sh`, `.sql`, `.svg`, `.toml`, `.ts`, `.tsx`, `.yaml`, `.yml`.
- **`Cargo.lock`** and other `*.lock` files are excluded so totals emphasize authored source.
- Requires **Node.js** only to regenerate this file; the Rust workspace does not depend on Node for builds.
