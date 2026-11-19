# Codebase stats

Auto-generated snapshot of this repository (Rust sources, docs, diagrams, and config-like text; `target/`, `.git`, and common binary formats are excluded).

**Generated (UTC):** 2026-11-14T23:32:50.192Z

**Regenerate:** `node scripts/codebase-stats.mjs`

## Summary

| Metric | Value |
| --- | ---: |
| Source-like files scanned | 1,010 |
| Total lines (all scanned source-like files) | 202,683 |
| Non-empty lines | 179,345 |
| UTF-8 bytes (source-like) | 8,339,776 |
| Paths visited (before binary/huge skip) | 1,224 |
| Skipped (binary / non-UTF8 / over 4 MiB) | 7 |

## Lines of code by top-level directory

The first path segment (crate name, `docs`, etc.). Only source-like extensions are included.

| Directory | Files | Lines | Non-empty lines |
| --- | ---: | ---: | ---: |
| `mfn-consensus` | 81 | 41,949 | 39,373 |
| `scripts` | 515 | 36,817 | 30,742 |
| `docs` | 111 | 24,653 | 18,053 |
| `mfn-node` | 47 | 17,041 | 15,798 |
| `mfn-cli` | 36 | 16,885 | 15,593 |
| `mfn-net` | 24 | 8,320 | 7,617 |
| `mfn-crypto` | 23 | 7,829 | 7,056 |
| `mfn-wallet` | 19 | 7,406 | 6,871 |
| `testnet-frontend` | 44 | 6,253 | 5,777 |
| `mfn-runtime` | 15 | 5,994 | 5,583 |
| `mfn-storage` | 9 | 4,367 | 4,034 |
| `mfn-rpc` | 6 | 4,278 | 4,069 |
| `mfn-light` | 6 | 4,256 | 3,890 |
| `mfn-storage-operator` | 15 | 3,389 | 3,118 |
| `mfn-wasm` | 12 | 2,936 | 2,696 |
| `demo` | 12 | 2,528 | 2,338 |
| `mfn-store` | 13 | 2,295 | 2,004 |
| `.github` | 6 | 2,146 | 2,083 |
| `(root)` | 7 | 1,757 | 1,241 |
| `mfn-bls` | 4 | 865 | 757 |
| `mfn-checkpoint-log` | 4 | 707 | 642 |
| `.cargo` | 1 | 12 | 10 |

## Lines of code by file extension

| Extension | Files | Lines | Non-empty lines | Bytes |
| --- | ---: | ---: | ---: | ---: |
| `.rs` | 272 | 125,881 | 117,011 | 4,495,986 |
| `.md` | 428 | 41,249 | 29,485 | 2,509,396 |
| `.sh` | 156 | 18,373 | 16,729 | 672,422 |
| `.json` | 75 | 3,434 | 3,359 | 141,645 |
| `.js` | 8 | 3,057 | 2,865 | 99,188 |
| `.tsx` | 12 | 2,677 | 2,513 | 91,151 |
| `.mjs` | 14 | 2,379 | 2,181 | 86,885 |
| `.ts` | 17 | 2,166 | 1,965 | 67,521 |
| `.yml` | 7 | 2,149 | 2,085 | 112,162 |
| `.svg` | 4 | 692 | 619 | 45,465 |
| `.toml` | 17 | 626 | 533 | 17,955 |

## Largest source files (by line count)

| Lines | File |
| ---: | --- |
| 4,959 | `mfn-consensus/tests/integration.rs` |
| 3,936 | `mfn-consensus/tests/block_apply.rs` |
| 3,503 | `mfn-rpc/src/dispatch.rs` |
| 3,271 | `docs/ROADMAP.md` |
| 2,612 | `mfn-consensus/tests/producer_treasury_settlement.rs` |
| 2,568 | `mfn-node/tests/mfnd_smoke.rs` |
| 2,326 | `mfn-consensus/tests/emission_simulation.rs` |
| 2,142 | `mfn-runtime/src/mempool.rs` |
| 2,121 | `mfn-cli/src/cli/parse.rs` |
| 2,099 | `mfn-node/src/p2p_fanout.rs` |
| 1,848 | `mfn-light/src/chain.rs` |
| 1,686 | `mfn-consensus/src/fraud_proof.rs` |
| 1,578 | `.github/workflows/ci.yml` |
| 1,559 | `mfn-cli/src/cli.rs` |
| 1,516 | `mfn-cli/src/wallet_cmd.rs` |
| 1,493 | `scripts/public-devnet-v1/OPERATORS.md` |
| 1,455 | `mfn-wallet/src/upload.rs` |
| 1,434 | `mfn-storage/src/endowment.rs` |
| 1,422 | `mfn-net/src/serve.rs` |
| 1,380 | `docs/F5.md` |

## Notes

- **Lines** include blank lines and comments; **non-empty** ignores lines that are only whitespace.
- **Source-like** extensions: `.cjs`, `.js`, `.json`, `.jsx`, `.md`, `.mjs`, `.rs`, `.sh`, `.sql`, `.svg`, `.toml`, `.ts`, `.tsx`, `.yaml`, `.yml`.
- **`Cargo.lock`** and other `*.lock` files are excluded so totals emphasize authored source.
- Requires **Node.js** only to regenerate this file; the Rust workspace does not depend on Node for builds.
