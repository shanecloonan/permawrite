# Codebase stats

Auto-generated snapshot of this repository (Rust sources, docs, diagrams, and config-like text; `target/`, `.git`, and common binary formats are excluded).

**Generated (UTC):** 2026-07-04T22:54:54.201Z

**Regenerate:** `node scripts/codebase-stats.mjs`

## Summary

| Metric | Value |
| --- | ---: |
| Source-like files scanned | 590 |
| Total lines (all scanned source-like files) | 131,420 |
| Non-empty lines | 118,269 |
| UTF-8 bytes (source-like) | 5,355,453 |
| Paths visited (before binary/huge skip) | 855 |
| Skipped (binary / non-UTF8 / over 4 MiB) | 180 |

## Lines of code by top-level directory

The first path segment (crate name, `docs`, etc.). Only source-like extensions are included.

| Directory | Files | Lines | Non-empty lines |
| --- | ---: | ---: | ---: |
| `mfn-consensus` | 67 | 30,238 | 28,327 |
| `mfn-cli` | 29 | 14,759 | 13,649 |
| `docs` | 55 | 14,646 | 10,707 |
| `scripts` | 255 | 14,644 | 13,334 |
| `mfn-node` | 34 | 12,082 | 11,180 |
| `mfn-crypto` | 23 | 7,291 | 6,564 |
| `mfn-wallet` | 15 | 4,939 | 4,529 |
| `mfn-net` | 11 | 4,659 | 4,250 |
| `mfn-runtime` | 14 | 4,517 | 4,183 |
| `mfn-rpc` | 4 | 3,997 | 3,799 |
| `mfn-light` | 6 | 3,924 | 3,582 |
| `mfn-storage-operator` | 14 | 3,248 | 2,988 |
| `demo` | 12 | 2,478 | 2,292 |
| `mfn-wasm` | 11 | 2,281 | 2,079 |
| `mfn-store` | 13 | 2,159 | 1,875 |
| `mfn-storage` | 6 | 2,072 | 1,884 |
| `.github` | 6 | 1,645 | 1,588 |
| `(root)` | 7 | 942 | 668 |
| `mfn-bls` | 4 | 865 | 757 |
| `.permawrite-devnet-v1` | 4 | 34 | 34 |

## Lines of code by file extension

| Extension | Files | Lines | Non-empty lines | Bytes |
| --- | ---: | ---: | ---: | ---: |
| `.rs` | 212 | 94,603 | 87,750 | 3,406,735 |
| `.md` | 81 | 17,828 | 12,766 | 1,213,371 |
| `.sh` | 40 | 6,966 | 6,369 | 252,063 |
| `.json` | 219 | 6,473 | 6,262 | 253,803 |
| `.js` | 7 | 1,980 | 1,856 | 64,098 |
| `.yml` | 7 | 1,648 | 1,590 | 84,631 |
| `.mjs` | 5 | 706 | 616 | 19,916 |
| `.svg` | 4 | 692 | 619 | 46,019 |
| `.toml` | 15 | 524 | 441 | 14,817 |

## Largest source files (by line count)

| Lines | File |
| ---: | --- |
| 4,922 | `mfn-consensus/tests/integration.rs` |
| 3,923 | `mfn-rpc/src/dispatch.rs` |
| 3,064 | `mfn-cli/src/cli.rs` |
| 2,892 | `mfn-consensus/tests/apply_block_proptest.rs` |
| 2,734 | `mfn-consensus/tests/block_apply.rs` |
| 2,416 | `mfn-node/tests/mfnd_smoke.rs` |
| 2,371 | `docs/ROADMAP.md` |
| 2,232 | `mfn-consensus/tests/producer_treasury_settlement.rs` |
| 2,056 | `mfn-consensus/tests/emission_simulation.rs` |
| 1,850 | `mfn-node/src/p2p_fanout.rs` |
| 1,725 | `mfn-runtime/src/mempool.rs` |
| 1,635 | `mfn-light/src/chain.rs` |
| 1,548 | `mfn-cli/src/wallet_cmd.rs` |
| 1,239 | `scripts/public-devnet-v1/OPERATORS.md` |
| 1,204 | `.github/workflows/ci.yml` |
| 1,197 | `mfn-net/src/serve.rs` |
| 1,094 | `mfn-light/tests/follow_chain.rs` |
| 1,092 | `mfn-node/src/mfnd_cli.rs` |
| 1,081 | `mfn-node/src/mfnd_serve.rs` |
| 1,019 | `mfn-consensus/tests/validator_finality_evolution/bond_ops.rs` |

## Notes

- **Lines** include blank lines and comments; **non-empty** ignores lines that are only whitespace.
- **Source-like** extensions: `.cjs`, `.js`, `.json`, `.jsx`, `.md`, `.mjs`, `.rs`, `.sh`, `.sql`, `.svg`, `.toml`, `.ts`, `.tsx`, `.yaml`, `.yml`.
- **`Cargo.lock`** and other `*.lock` files are excluded so totals emphasize authored source.
- Requires **Node.js** only to regenerate this file; the Rust workspace does not depend on Node for builds.
