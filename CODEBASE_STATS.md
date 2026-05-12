# Codebase stats

Auto-generated snapshot of this repository (Rust sources, docs, diagrams, and config-like text; `target/`, `.git`, and common binary formats are excluded).

**Generated (UTC):** 2026-05-12T18:20:32.836Z

**Regenerate:** `node scripts/codebase-stats.mjs`

## Summary

| Metric | Value |
| --- | ---: |
| Source-like files scanned | 70 |
| Total lines (all scanned source-like files) | 23,541 |
| Non-empty lines | 20,194 |
| UTF-8 bytes (source-like) | 972,484 |
| Paths visited (before binary/huge skip) | 75 |
| Skipped (binary / non-UTF8 / over 4 MiB) | 1 |

## Lines of code by top-level directory

The first path segment (crate name, `docs`, etc.). Only source-like extensions are included.

| Directory | Files | Lines | Non-empty lines |
| --- | ---: | ---: | ---: |
| `mfn-consensus` | 13 | 8,924 | 8,268 |
| `mfn-crypto` | 22 | 6,214 | 5,558 |
| `docs` | 18 | 4,911 | 3,391 |
| `mfn-storage` | 6 | 1,629 | 1,476 |
| `mfn-bls` | 4 | 862 | 755 |
| `(root)` | 5 | 683 | 482 |
| `scripts` | 1 | 261 | 214 |
| `.github` | 1 | 57 | 50 |

## Lines of code by file extension

| Extension | Files | Lines | Non-empty lines | Bytes |
| --- | ---: | ---: | ---: | ---: |
| `.rs` | 37 | 16,787 | 15,410 | 608,724 |
| `.md` | 23 | 5,795 | 3,959 | 317,970 |
| `.svg` | 3 | 480 | 425 | 32,915 |
| `.mjs` | 1 | 261 | 214 | 7,024 |
| `.toml` | 5 | 161 | 136 | 4,508 |
| `.yml` | 1 | 57 | 50 | 1,343 |

## Largest source files (by line count)

| Lines | File |
| ---: | --- |
| 3,022 | `mfn-consensus/src/block.rs` |
| 1,546 | `mfn-consensus/tests/integration.rs` |
| 1,011 | `mfn-consensus/src/consensus.rs` |
| 906 | `mfn-consensus/src/transaction.rs` |
| 720 | `docs/ARCHITECTURE.md` |
| 703 | `mfn-crypto/src/bulletproofs.rs` |
| 649 | `mfn-storage/src/endowment.rs` |
| 642 | `mfn-crypto/src/oom.rs` |
| 633 | `mfn-bls/src/sig.rs` |
| 605 | `mfn-storage/src/spora.rs` |
| 576 | `docs/STORAGE.md` |
| 564 | `docs/ECONOMICS.md` |
| 553 | `mfn-consensus/src/bond_wire.rs` |
| 539 | `docs/CONSENSUS.md` |
| 493 | `mfn-crypto/src/utxo_tree.rs` |
| 488 | `mfn-crypto/src/clsag.rs` |
| 486 | `mfn-consensus/src/slashing.rs` |
| 475 | `mfn-crypto/src/vrf.rs` |
| 465 | `mfn-crypto/src/decoy.rs` |
| 447 | `docs/PRIVACY.md` |

## Notes

- **Lines** include blank lines and comments; **non-empty** ignores lines that are only whitespace.
- **Source-like** extensions: `.cjs`, `.js`, `.json`, `.jsx`, `.md`, `.mjs`, `.rs`, `.sh`, `.sql`, `.svg`, `.toml`, `.ts`, `.tsx`, `.yaml`, `.yml`.
- **`Cargo.lock`** and other `*.lock` files are excluded so totals emphasize authored source.
- Requires **Node.js** only to regenerate this file; the Rust workspace does not depend on Node for builds.
