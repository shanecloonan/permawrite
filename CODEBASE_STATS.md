# Codebase stats

Auto-generated snapshot of this repository (Rust sources, docs, diagrams, and config-like text; `target/`, `.git`, and common binary formats are excluded).

**Generated (UTC):** 2026-05-12T21:52:11.315Z

**Regenerate:** `node scripts/codebase-stats.mjs`

## Summary

| Metric | Value |
| --- | ---: |
| Source-like files scanned | 90 |
| Total lines (all scanned source-like files) | 30,806 |
| Non-empty lines | 26,545 |
| UTF-8 bytes (source-like) | 1,330,097 |
| Paths visited (before binary/huge skip) | 95 |
| Skipped (binary / non-UTF8 / over 4 MiB) | 1 |

## Lines of code by top-level directory

The first path segment (crate name, `docs`, etc.). Only source-like extensions are included.

| Directory | Files | Lines | Non-empty lines |
| --- | ---: | ---: | ---: |
| `mfn-consensus` | 15 | 10,461 | 9,708 |
| `docs` | 24 | 6,475 | 4,536 |
| `mfn-crypto` | 22 | 6,221 | 5,564 |
| `mfn-light` | 5 | 2,326 | 2,106 |
| `mfn-storage` | 6 | 1,816 | 1,649 |
| `mfn-node` | 7 | 1,639 | 1,476 |
| `mfn-bls` | 4 | 862 | 755 |
| `(root)` | 5 | 688 | 487 |
| `scripts` | 1 | 261 | 214 |
| `.github` | 1 | 57 | 50 |

## Lines of code by file extension

| Extension | Files | Lines | Non-empty lines | Bytes |
| --- | ---: | ---: | ---: | ---: |
| `.rs` | 47 | 22,069 | 20,311 | 821,137 |
| `.md` | 31 | 7,727 | 5,368 | 461,762 |
| `.svg` | 3 | 480 | 425 | 32,915 |
| `.mjs` | 1 | 261 | 214 | 7,024 |
| `.toml` | 7 | 212 | 177 | 5,916 |
| `.yml` | 1 | 57 | 50 | 1,343 |

## Largest source files (by line count)

| Lines | File |
| ---: | --- |
| 2,911 | `mfn-consensus/src/block.rs` |
| 1,661 | `mfn-consensus/tests/integration.rs` |
| 1,258 | `mfn-light/src/chain.rs` |
| 1,011 | `mfn-consensus/src/consensus.rs` |
| 906 | `mfn-consensus/src/transaction.rs` |
| 791 | `mfn-storage/src/spora.rs` |
| 779 | `docs/ARCHITECTURE.md` |
| 774 | `mfn-consensus/src/header_verify.rs` |
| 766 | `mfn-light/tests/follow_chain.rs` |
| 729 | `mfn-consensus/src/validator_evolution.rs` |
| 703 | `mfn-crypto/src/bulletproofs.rs` |
| 676 | `docs/ROADMAP.md` |
| 649 | `mfn-storage/src/endowment.rs` |
| 642 | `mfn-crypto/src/oom.rs` |
| 635 | `docs/CONSENSUS.md` |
| 633 | `mfn-bls/src/sig.rs` |
| 576 | `docs/STORAGE.md` |
| 564 | `docs/ECONOMICS.md` |
| 553 | `mfn-consensus/src/bond_wire.rs` |
| 504 | `mfn-node/src/producer.rs` |

## Notes

- **Lines** include blank lines and comments; **non-empty** ignores lines that are only whitespace.
- **Source-like** extensions: `.cjs`, `.js`, `.json`, `.jsx`, `.md`, `.mjs`, `.rs`, `.sh`, `.sql`, `.svg`, `.toml`, `.ts`, `.tsx`, `.yaml`, `.yml`.
- **`Cargo.lock`** and other `*.lock` files are excluded so totals emphasize authored source.
- Requires **Node.js** only to regenerate this file; the Rust workspace does not depend on Node for builds.
