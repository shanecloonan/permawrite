# Codebase stats

Auto-generated snapshot of this repository (Rust sources, docs, diagrams, and config-like text; `target/`, `.git`, and common binary formats are excluded).

**Generated (UTC):** 2026-05-13T16:29:33.582Z

**Regenerate:** `node scripts/codebase-stats.mjs`

## Summary

| Metric | Value |
| --- | ---: |
| Source-like files scanned | 105 |
| Total lines (all scanned source-like files) | 37,054 |
| Non-empty lines | 32,164 |
| UTF-8 bytes (source-like) | 1,599,715 |
| Paths visited (before binary/huge skip) | 110 |
| Skipped (binary / non-UTF8 / over 4 MiB) | 1 |

## Lines of code by top-level directory

The first path segment (crate name, `docs`, etc.). Only source-like extensions are included.

| Directory | Files | Lines | Non-empty lines |
| --- | ---: | ---: | ---: |
| `mfn-consensus` | 15 | 11,714 | 10,883 |
| `docs` | 27 | 7,365 | 5,242 |
| `mfn-crypto` | 22 | 6,238 | 5,580 |
| `mfn-light` | 6 | 3,915 | 3,571 |
| `mfn-wallet` | 11 | 2,352 | 2,121 |
| `mfn-storage` | 6 | 1,960 | 1,782 |
| `mfn-node` | 7 | 1,639 | 1,476 |
| `mfn-bls` | 4 | 862 | 755 |
| `(root)` | 5 | 691 | 490 |
| `scripts` | 1 | 261 | 214 |
| `.github` | 1 | 57 | 50 |

## Lines of code by file extension

| Extension | Files | Lines | Non-empty lines | Bytes |
| --- | ---: | ---: | ---: | ---: |
| `.rs` | 57 | 27,189 | 25,029 | 1,016,432 |
| `.md` | 35 | 8,826 | 6,245 | 535,238 |
| `.svg` | 3 | 480 | 425 | 32,915 |
| `.mjs` | 1 | 261 | 214 | 7,024 |
| `.toml` | 8 | 241 | 201 | 6,763 |
| `.yml` | 1 | 57 | 50 | 1,343 |

## Largest source files (by line count)

| Lines | File |
| ---: | --- |
| 3,690 | `mfn-consensus/src/block.rs` |
| 1,661 | `mfn-consensus/tests/integration.rs` |
| 1,499 | `mfn-light/src/chain.rs` |
| 1,353 | `mfn-consensus/src/transaction.rs` |
| 1,039 | `mfn-light/src/checkpoint.rs` |
| 1,022 | `mfn-light/tests/follow_chain.rs` |
| 1,011 | `mfn-consensus/src/consensus.rs` |
| 860 | `docs/ARCHITECTURE.md` |
| 804 | `mfn-storage/src/spora.rs` |
| 791 | `docs/ROADMAP.md` |
| 774 | `mfn-consensus/src/header_verify.rs` |
| 729 | `mfn-consensus/src/validator_evolution.rs` |
| 703 | `mfn-crypto/src/bulletproofs.rs` |
| 695 | `docs/CONSENSUS.md` |
| 649 | `mfn-storage/src/endowment.rs` |
| 642 | `mfn-crypto/src/oom.rs` |
| 633 | `mfn-bls/src/sig.rs` |
| 576 | `docs/STORAGE.md` |
| 564 | `docs/ECONOMICS.md` |
| 553 | `mfn-consensus/src/bond_wire.rs` |

## Notes

- **Lines** include blank lines and comments; **non-empty** ignores lines that are only whitespace.
- **Source-like** extensions: `.cjs`, `.js`, `.json`, `.jsx`, `.md`, `.mjs`, `.rs`, `.sh`, `.sql`, `.svg`, `.toml`, `.ts`, `.tsx`, `.yaml`, `.yml`.
- **`Cargo.lock`** and other `*.lock` files are excluded so totals emphasize authored source.
- Requires **Node.js** only to regenerate this file; the Rust workspace does not depend on Node for builds.
