# Codebase stats

Auto-generated snapshot of this repository (Rust sources, docs, diagrams, and config-like text; `target/`, `.git`, and common binary formats are excluded).

**Generated (UTC):** 2026-07-04T02:13:07.724Z

**Regenerate:** `node scripts/codebase-stats.mjs`

## Summary

| Metric | Value |
| --- | ---: |
| Source-like files scanned | 497 |
| Total lines (all scanned source-like files) | 125,262 |
| Non-empty lines | 112,862 |
| UTF-8 bytes (source-like) | 5,066,338 |
| Paths visited (before binary/huge skip) | 653 |
| Skipped (binary / non-UTF8 / over 4 MiB) | 75 |

## Lines of code by top-level directory

The first path segment (crate name, `docs`, etc.). Only source-like extensions are included.

| Directory | Files | Lines | Non-empty lines |
| --- | ---: | ---: | ---: |
| `mfn-consensus` | 67 | 29,427 | 27,544 |
| `mfn-cli` | 29 | 14,754 | 13,644 |
| `docs` | 50 | 13,204 | 9,752 |
| `mfn-node` | 34 | 11,968 | 11,072 |
| `scripts` | 169 | 11,842 | 10,685 |
| `mfn-crypto` | 23 | 7,291 | 6,564 |
| `mfn-wallet` | 15 | 4,938 | 4,528 |
| `mfn-net` | 11 | 4,659 | 4,250 |
| `mfn-runtime` | 14 | 4,401 | 4,072 |
| `mfn-rpc` | 4 | 3,997 | 3,799 |
| `mfn-light` | 6 | 3,902 | 3,563 |
| `mfn-storage-operator` | 14 | 2,877 | 2,635 |
| `demo` | 12 | 2,478 | 2,292 |
| `mfn-store` | 13 | 2,159 | 1,875 |
| `mfn-wasm` | 11 | 2,079 | 1,882 |
| `mfn-storage` | 6 | 2,071 | 1,883 |
| `.github` | 5 | 1,513 | 1,463 |
| `mfn-bls` | 4 | 865 | 757 |
| `(root)` | 6 | 802 | 567 |
| `.permawrite-devnet-v1` | 4 | 35 | 35 |

## Lines of code by file extension

| Extension | Files | Lines | Non-empty lines | Bytes |
| --- | ---: | ---: | ---: | ---: |
| `.rs` | 212 | 92,998 | 86,202 | 3,364,818 |
| `.md` | 71 | 16,023 | 11,550 | 1,077,131 |
| `.sh` | 37 | 6,563 | 5,985 | 235,586 |
| `.json` | 140 | 4,260 | 4,128 | 164,742 |
| `.js` | 7 | 1,980 | 1,856 | 64,098 |
| `.yml` | 6 | 1,516 | 1,465 | 79,211 |
| `.mjs` | 5 | 706 | 616 | 19,916 |
| `.svg` | 4 | 692 | 619 | 46,019 |
| `.toml` | 15 | 524 | 441 | 14,817 |

## Largest source files (by line count)

| Lines | File |
| ---: | --- |
| 4,583 | `mfn-consensus/tests/integration.rs` |
| 3,923 | `mfn-rpc/src/dispatch.rs` |
| 3,064 | `mfn-cli/src/cli.rs` |
| 2,772 | `mfn-consensus/tests/apply_block_proptest.rs` |
| 2,445 | `mfn-consensus/tests/block_apply.rs` |
| 2,416 | `mfn-node/tests/mfnd_smoke.rs` |
| 2,369 | `docs/ROADMAP.md` |
| 2,162 | `mfn-consensus/tests/producer_treasury_settlement.rs` |
| 2,062 | `mfn-consensus/tests/emission_simulation.rs` |
| 1,850 | `mfn-node/src/p2p_fanout.rs` |
| 1,635 | `mfn-light/src/chain.rs` |
| 1,609 | `mfn-runtime/src/mempool.rs` |
| 1,548 | `mfn-cli/src/wallet_cmd.rs` |
| 1,197 | `mfn-net/src/serve.rs` |
| 1,178 | `.github/workflows/ci.yml` |
| 1,176 | `scripts/public-devnet-v1/OPERATORS.md` |
| 1,094 | `mfn-light/tests/follow_chain.rs` |
| 1,092 | `mfn-node/src/mfnd_cli.rs` |
| 1,081 | `mfn-node/src/mfnd_serve.rs` |
| 1,019 | `mfn-consensus/tests/validator_finality_evolution/bond_ops.rs` |

## Notes

- **Lines** include blank lines and comments; **non-empty** ignores lines that are only whitespace.
- **Source-like** extensions: `.cjs`, `.js`, `.json`, `.jsx`, `.md`, `.mjs`, `.rs`, `.sh`, `.sql`, `.svg`, `.toml`, `.ts`, `.tsx`, `.yaml`, `.yml`.
- **`Cargo.lock`** and other `*.lock` files are excluded so totals emphasize authored source.
- Requires **Node.js** only to regenerate this file; the Rust workspace does not depend on Node for builds.
