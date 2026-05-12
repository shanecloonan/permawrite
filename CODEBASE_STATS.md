# Codebase stats

Auto-generated snapshot of this repository (Rust sources, docs, diagrams, and config-like text; `target/`, `.git`, and common binary formats are excluded).

**Generated (UTC):** 2026-05-12T21:06:55.218Z

**Regenerate:** `node scripts/codebase-stats.mjs`

## Summary

| Metric | Value |
| --- | ---: |
| Source-like files scanned | 88 |
| Total lines (all scanned source-like files) | 29,061 |
| Non-empty lines | 24,974 |
| UTF-8 bytes (source-like) | 1,247,307 |
| Paths visited (before binary/huge skip) | 93 |
| Skipped (binary / non-UTF8 / over 4 MiB) | 1 |

## Lines of code by top-level directory

The first path segment (crate name, `docs`, etc.). Only source-like extensions are included.

| Directory | Files | Lines | Non-empty lines |
| --- | ---: | ---: | ---: |
| `mfn-consensus` | 14 | 9,900 | 9,181 |
| `mfn-crypto` | 22 | 6,221 | 5,564 |
| `docs` | 23 | 6,055 | 4,205 |
| `mfn-storage` | 6 | 1,816 | 1,649 |
| `mfn-node` | 7 | 1,639 | 1,476 |
| `mfn-light` | 5 | 1,562 | 1,393 |
| `mfn-bls` | 4 | 862 | 755 |
| `(root)` | 5 | 688 | 487 |
| `scripts` | 1 | 261 | 214 |
| `.github` | 1 | 57 | 50 |

## Lines of code by file extension

| Extension | Files | Lines | Non-empty lines | Bytes |
| --- | ---: | ---: | ---: | ---: |
| `.rs` | 46 | 20,784 | 19,105 | 767,889 |
| `.md` | 30 | 7,267 | 5,003 | 432,220 |
| `.svg` | 3 | 480 | 425 | 32,915 |
| `.mjs` | 1 | 261 | 214 | 7,024 |
| `.toml` | 7 | 212 | 177 | 5,916 |
| `.yml` | 1 | 57 | 50 | 1,343 |

## Largest source files (by line count)

| Lines | File |
| ---: | --- |
| 3,087 | `mfn-consensus/src/block.rs` |
| 1,661 | `mfn-consensus/tests/integration.rs` |
| 1,011 | `mfn-consensus/src/consensus.rs` |
| 906 | `mfn-consensus/src/transaction.rs` |
| 861 | `mfn-light/src/chain.rs` |
| 791 | `mfn-storage/src/spora.rs` |
| 774 | `mfn-consensus/src/header_verify.rs` |
| 767 | `docs/ARCHITECTURE.md` |
| 703 | `mfn-crypto/src/bulletproofs.rs` |
| 649 | `mfn-storage/src/endowment.rs` |
| 642 | `mfn-crypto/src/oom.rs` |
| 636 | `docs/ROADMAP.md` |
| 633 | `mfn-bls/src/sig.rs` |
| 603 | `docs/CONSENSUS.md` |
| 576 | `docs/STORAGE.md` |
| 564 | `docs/ECONOMICS.md` |
| 553 | `mfn-consensus/src/bond_wire.rs` |
| 504 | `mfn-node/src/producer.rs` |
| 493 | `mfn-crypto/src/utxo_tree.rs` |
| 488 | `mfn-crypto/src/clsag.rs` |

## Notes

- **Lines** include blank lines and comments; **non-empty** ignores lines that are only whitespace.
- **Source-like** extensions: `.cjs`, `.js`, `.json`, `.jsx`, `.md`, `.mjs`, `.rs`, `.sh`, `.sql`, `.svg`, `.toml`, `.ts`, `.tsx`, `.yaml`, `.yml`.
- **`Cargo.lock`** and other `*.lock` files are excluded so totals emphasize authored source.
- Requires **Node.js** only to regenerate this file; the Rust workspace does not depend on Node for builds.
