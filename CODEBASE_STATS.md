# Codebase stats

Auto-generated snapshot of this repository (Rust sources, docs, diagrams, and config-like text; `target/`, `.git`, and common binary formats are excluded).

**Generated (UTC):** 2026-05-14T16:47:38.406Z

**Regenerate:** `node scripts/codebase-stats.mjs`

## Summary

| Metric | Value |
| --- | ---: |
| Source-like files scanned | 215 |
| Total lines (all scanned source-like files) | 48,529 |
| Non-empty lines | 42,532 |
| UTF-8 bytes (source-like) | 2,163,624 |
| Paths visited (before binary/huge skip) | 2,916 |
| Skipped (binary / non-UTF8 / over 4 MiB) | 2,455 |

## Lines of code by top-level directory

The first path segment (crate name, `docs`, etc.). Only source-like extensions are included.

| Directory | Files | Lines | Non-empty lines |
| --- | ---: | ---: | ---: |
| `mfn-consensus` | 17 | 13,639 | 12,655 |
| `docs` | 31 | 9,050 | 6,507 |
| `mfn-node` | 19 | 7,540 | 6,943 |
| `mfn-crypto` | 22 | 6,656 | 5,979 |
| `mfn-wallet` | 12 | 3,995 | 3,662 |
| `mfn-light` | 6 | 3,692 | 3,369 |
| `mfn-storage` | 6 | 1,960 | 1,782 |
| `mfn-bls` | 4 | 862 | 755 |
| `(root)` | 5 | 693 | 492 |
| `scripts` | 1 | 261 | 214 |
| `target-agent` | 91 | 91 | 91 |
| `.github` | 1 | 90 | 83 |

## Lines of code by file extension

| Extension | Files | Lines | Non-empty lines | Bytes |
| --- | ---: | ---: | ---: | ---: |
| `.rs` | 70 | 36,737 | 33,903 | 1,374,696 |
| `.md` | 39 | 10,574 | 7,564 | 681,402 |
| `.svg` | 3 | 480 | 425 | 32,915 |
| `.mjs` | 1 | 261 | 214 | 7,024 |
| `.toml` | 8 | 257 | 215 | 7,288 |
| `.json` | 93 | 130 | 128 | 57,938 |
| `.yml` | 1 | 90 | 83 | 2,361 |

## Largest source files (by line count)

| Lines | File |
| ---: | --- |
| 3,690 | `mfn-consensus/src/block.rs` |
| 1,661 | `mfn-consensus/tests/integration.rs` |
| 1,552 | `mfn-node/src/mempool.rs` |
| 1,499 | `mfn-light/src/chain.rs` |
| 1,424 | `docs/ROADMAP.md` |
| 1,353 | `mfn-consensus/src/transaction.rs` |
| 1,204 | `mfn-consensus/src/chain_checkpoint.rs` |
| 1,022 | `mfn-light/tests/follow_chain.rs` |
| 1,011 | `mfn-consensus/src/consensus.rs` |
| 953 | `docs/ARCHITECTURE.md` |
| 949 | `mfn-wallet/src/upload.rs` |
| 870 | `mfn-crypto/src/utxo_tree.rs` |
| 816 | `mfn-light/src/checkpoint.rs` |
| 804 | `mfn-storage/src/spora.rs` |
| 774 | `mfn-consensus/src/header_verify.rs` |
| 773 | `mfn-wallet/src/wallet.rs` |
| 766 | `mfn-node/src/mfnd_serve.rs` |
| 729 | `mfn-consensus/src/validator_evolution.rs` |
| 715 | `mfn-node/tests/mempool_integration.rs` |
| 705 | `mfn-consensus/src/checkpoint_codec.rs` |

## Notes

- **Lines** include blank lines and comments; **non-empty** ignores lines that are only whitespace.
- **Source-like** extensions: `.cjs`, `.js`, `.json`, `.jsx`, `.md`, `.mjs`, `.rs`, `.sh`, `.sql`, `.svg`, `.toml`, `.ts`, `.tsx`, `.yaml`, `.yml`.
- **`Cargo.lock`** and other `*.lock` files are excluded so totals emphasize authored source.
- Requires **Node.js** only to regenerate this file; the Rust workspace does not depend on Node for builds.
