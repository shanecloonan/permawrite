# Codebase stats

Auto-generated snapshot of this repository (Rust sources, docs, diagrams, and config-like text; `target/`, `.git`, and common binary formats are excluded).

**Generated (UTC):** 2026-07-03T10:56:00.074Z

**Regenerate:** `node scripts/codebase-stats.mjs`

## Summary

| Metric | Value |
| --- | ---: |
| Source-like files scanned | 365 |
| Total lines (all scanned source-like files) | 119,434 |
| Non-empty lines | 107,301 |
| UTF-8 bytes (source-like) | 4,842,219 |
| Paths visited (before binary/huge skip) | 436 |
| Skipped (binary / non-UTF8 / over 4 MiB) | 14 |

## Lines of code by top-level directory

The first path segment (crate name, `docs`, etc.). Only source-like extensions are included.

| Directory | Files | Lines | Non-empty lines |
| --- | ---: | ---: | ---: |
| `mfn-consensus` | 67 | 28,818 | 26,958 |
| `mfn-cli` | 29 | 14,698 | 13,589 |
| `docs` | 50 | 13,221 | 9,758 |
| `mfn-node` | 34 | 11,821 | 10,940 |
| `mfn-crypto` | 23 | 7,291 | 6,564 |
| `scripts` | 40 | 7,263 | 6,390 |
| `mfn-wallet` | 15 | 4,933 | 4,524 |
| `mfn-net` | 11 | 4,602 | 4,197 |
| `mfn-runtime` | 14 | 4,394 | 4,065 |
| `mfn-rpc` | 4 | 3,996 | 3,798 |
| `mfn-light` | 6 | 3,895 | 3,556 |
| `mfn-storage-operator` | 14 | 2,830 | 2,591 |
| `demo` | 12 | 2,478 | 2,292 |
| `mfn-store` | 13 | 2,159 | 1,875 |
| `mfn-wasm` | 11 | 2,070 | 1,873 |
| `mfn-storage` | 6 | 2,005 | 1,821 |
| `.github` | 2 | 1,190 | 1,155 |
| `(root)` | 6 | 875 | 568 |
| `mfn-bls` | 4 | 865 | 757 |
| `.permawrite-devnet-v1` | 4 | 30 | 30 |

## Lines of code by file extension

| Extension | Files | Lines | Non-empty lines | Bytes |
| --- | ---: | ---: | ---: | ---: |
| `.rs` | 212 | 91,986 | 85,241 | 3,333,777 |
| `.md` | 61 | 15,710 | 11,278 | 1,061,780 |
| `.sh` | 34 | 5,826 | 5,293 | 209,827 |
| `.js` | 7 | 1,980 | 1,856 | 64,098 |
| `.yml` | 3 | 1,193 | 1,157 | 67,934 |
| `.json` | 24 | 816 | 799 | 24,015 |
| `.mjs` | 5 | 706 | 616 | 19,916 |
| `.svg` | 4 | 692 | 619 | 46,019 |
| `.toml` | 15 | 525 | 442 | 14,853 |

## Largest source files (by line count)

| Lines | File |
| ---: | --- |
| 4,589 | `mfn-consensus/tests/integration.rs` |
| 3,922 | `mfn-rpc/src/dispatch.rs` |
| 3,062 | `mfn-cli/src/cli.rs` |
| 2,784 | `mfn-consensus/tests/apply_block_proptest.rs` |
| 2,409 | `mfn-node/tests/mfnd_smoke.rs` |
| 2,342 | `docs/ROADMAP.md` |
| 2,290 | `mfn-consensus/tests/block_apply.rs` |
| 1,975 | `mfn-consensus/tests/emission_simulation.rs` |
| 1,975 | `mfn-consensus/tests/producer_treasury_settlement.rs` |
| 1,767 | `mfn-node/src/p2p_fanout.rs` |
| 1,634 | `mfn-light/src/chain.rs` |
| 1,609 | `mfn-runtime/src/mempool.rs` |
| 1,542 | `mfn-cli/src/wallet_cmd.rs` |
| 1,152 | `.github/workflows/ci.yml` |
| 1,140 | `mfn-net/src/serve.rs` |
| 1,109 | `scripts/public-devnet-v1/OPERATORS.md` |
| 1,089 | `mfn-light/tests/follow_chain.rs` |
| 1,081 | `mfn-node/src/mfnd_serve.rs` |
| 1,077 | `mfn-node/src/mfnd_cli.rs` |
| 1,019 | `mfn-consensus/tests/validator_finality_evolution/bond_ops.rs` |

## Notes

- **Lines** include blank lines and comments; **non-empty** ignores lines that are only whitespace.
- **Source-like** extensions: `.cjs`, `.js`, `.json`, `.jsx`, `.md`, `.mjs`, `.rs`, `.sh`, `.sql`, `.svg`, `.toml`, `.ts`, `.tsx`, `.yaml`, `.yml`.
- **`Cargo.lock`** and other `*.lock` files are excluded so totals emphasize authored source.
- Requires **Node.js** only to regenerate this file; the Rust workspace does not depend on Node for builds.
