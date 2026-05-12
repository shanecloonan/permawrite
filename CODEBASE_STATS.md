# Codebase stats

Auto-generated snapshot of this repository (Rust sources, docs, diagrams, and config-like text; `target/`, `.git`, and common binary formats are excluded).

**Generated (UTC):** 2026-05-12T04:13:48.489Z

**Regenerate:** `node scripts/codebase-stats.mjs`

## Summary

| Metric | Value |
| --- | ---: |
| Source-like files scanned | 63 |
| Total lines (all scanned source-like files) | 19,824 |
| Non-empty lines | 16,907 |
| UTF-8 bytes (source-like) | 791,457 |
| Paths visited (before binary/huge skip) | 68 |
| Skipped (binary / non-UTF8 / over 4 MiB) | 1 |

## Lines of code by top-level directory

The first path segment (crate name, `docs`, etc.). Only source-like extensions are included.

| Directory | Files | Lines | Non-empty lines |
| --- | ---: | ---: | ---: |
| `mfn-crypto` | 22 | 6,187 | 5,536 |
| `mfn-consensus` | 11 | 6,089 | 5,608 |
| `docs` | 13 | 4,057 | 2,787 |
| `mfn-storage` | 6 | 1,629 | 1,476 |
| `mfn-bls` | 4 | 862 | 755 |
| `(root)` | 5 | 682 | 481 |
| `scripts` | 1 | 261 | 214 |
| `.github` | 1 | 57 | 50 |

## Lines of code by file extension

| Extension | Files | Lines | Non-empty lines | Bytes |
| --- | ---: | ---: | ---: | ---: |
| `.rs` | 35 | 13,937 | 12,740 | 498,843 |
| `.md` | 18 | 4,928 | 3,342 | 247,301 |
| `.svg` | 3 | 480 | 425 | 32,438 |
| `.mjs` | 1 | 261 | 214 | 7,024 |
| `.toml` | 5 | 161 | 136 | 4,508 |
| `.yml` | 1 | 57 | 50 | 1,343 |

## Largest source files (by line count)

| Lines | File |
| ---: | --- |
| 2,084 | `mfn-consensus/src/block.rs` |
| 906 | `mfn-consensus/src/transaction.rs` |
| 884 | `mfn-consensus/tests/integration.rs` |
| 765 | `mfn-consensus/src/consensus.rs` |
| 703 | `mfn-crypto/src/bulletproofs.rs` |
| 651 | `docs/ARCHITECTURE.md` |
| 649 | `mfn-storage/src/endowment.rs` |
| 642 | `mfn-crypto/src/oom.rs` |
| 633 | `mfn-bls/src/sig.rs` |
| 605 | `mfn-storage/src/spora.rs` |
| 576 | `docs/STORAGE.md` |
| 512 | `docs/ECONOMICS.md` |
| 493 | `mfn-crypto/src/utxo_tree.rs` |
| 488 | `mfn-crypto/src/clsag.rs` |
| 475 | `mfn-crypto/src/vrf.rs` |
| 465 | `mfn-crypto/src/decoy.rs` |
| 450 | `docs/CONSENSUS.md` |
| 447 | `docs/PRIVACY.md` |
| 434 | `mfn-consensus/src/coinbase.rs` |
| 400 | `mfn-crypto/src/range.rs` |

## Notes

- **Lines** include blank lines and comments; **non-empty** ignores lines that are only whitespace.
- **Source-like** extensions: `.cjs`, `.js`, `.json`, `.jsx`, `.md`, `.mjs`, `.rs`, `.sh`, `.sql`, `.svg`, `.toml`, `.ts`, `.tsx`, `.yaml`, `.yml`.
- **`Cargo.lock`** and other `*.lock` files are excluded so totals emphasize authored source.
- Requires **Node.js** only to regenerate this file; the Rust workspace does not depend on Node for builds.
