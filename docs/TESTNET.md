# Permawrite public devnet (M2.4)

This document describes how to run a **three-validator devnet** on loopback or LAN using the reference daemon `mfnd`. The chain is the same MFBN-1 consensus stack used in CI; privacy and permanence economics are live in consensus, while wallet-facing tooling remains library-only until M3.

**Security warning.** The validator seeds in [`mfn-node/testdata/public_devnet_v1.json`](../mfn-node/testdata/public_devnet_v1.json) are **public, deterministic test keys**. Never fund them on a network you care about. Replace every seed before any production or incentivized deployment.

---

## What you need

| Item | Notes |
|------|--------|
| Rust stable | Same toolchain as CI (`rust-toolchain.toml` in repo root). |
| `mfnd` binary | `cargo build -p mfn-node --release --bin mfnd` |
| Genesis file | `public_devnet_v1.json` (three equal-stake validators, quorum 2/3). |
| Chain identity | `genesis_id` **`7fef4492dba32d7ba652cceb5465cae86d6630a9e0a4855adf3acdc5f6b2a2df`** ([`public_devnet_v1.manifest.json`](../mfn-node/testdata/public_devnet_v1.manifest.json)). |
| Open TCP ports | One RPC + one P2P port per node (defaults bind `127.0.0.1:0` — OS assigns). |

On `mfnd serve`, stdout includes `mfnd_chain_network=public_devnet_v1` and `mfnd_chain_genesis_id=…` when `--genesis` points at the public spec. Peers reject handshakes when `genesis_id` differs.

---

## One-command local mesh (M2.4.3)

After `cargo build -p mfn-node --release --bin mfnd`:

| Platform | Start three validators | Health check |
|----------|------------------------|--------------|
| Linux / macOS | `bash scripts/public-devnet-v1/start-all.sh` | `bash scripts/public-devnet-v1/health-check.sh` |
| Windows | `powershell -File scripts/public-devnet-v1/start-all.ps1` | `powershell -File scripts/public-devnet-v1/health-check.ps1` |

Operator onboarding and seed-node list: [`scripts/public-devnet-v1/OPERATORS.md`](../scripts/public-devnet-v1/OPERATORS.md).

---

## Network roles

| Role | Flags | Responsibility |
|------|--------|----------------|
| **Hub producer** | `serve --produce` | Slot timer, builds proposals when VRF-eligible, seals when local validator is proposer and quorum votes arrive. |
| **Committee voter** | `serve --committee-vote` | Votes on inbound proposals; does **not** run the slot loop. |
| **Observer** | `serve` (no produce flags) | Syncs blocks/txs, exposes JSON-RPC; no validator env required. |

CI uses one hub + two committee voters so only the proposer seals (avoids forked tips under `expected_proposers_per_slot: 10` in the local harness spec). The **public devnet** spec sets `expected_proposers_per_slot: 1.5` so operators can later run three `--produce` nodes with natural slot skipping; the commands below match the proven hub + voter topology.

---

## Environment (per validator)

Set these in the shell that starts each `mfnd serve` process:

```text
MFND_VALIDATOR_INDEX=0   # 0, 1, or 2 — must match genesis row
MFND_VRF_SEED_HEX=<32-byte hex from genesis validators[].vrf_seed_hex>
MFND_BLS_SEED_HEX=<32-byte hex from genesis validators[].bls_seed_hex>
```

Seeds for `public_devnet_v1.json` are listed in that file. Index `0` is the usual hub producer.

---

## Example: three nodes on one machine

Build once:

```bash
cargo build -p mfn-node --release --bin mfnd
export MFND=target/release/mfnd
export GENESIS=mfn-node/testdata/public_devnet_v1.json
```

**Validator 0 (hub)** — note RPC/P2P lines on stdout:

```bash
mkdir -p /tmp/mfn-v0
MFND_VALIDATOR_INDEX=0 \
MFND_VRF_SEED_HEX=0101010101010101010101010101010101010101010101010101010101010101 \
MFND_BLS_SEED_HEX=6565656565656565656565656565656565656565656565656565656565656565 \
$MFND --data-dir /tmp/mfn-v0 --genesis $GENESIS --store fs \
  --rpc-listen 127.0.0.1:0 --p2p-listen 127.0.0.1:0 \
  --slot-duration-ms 30000 serve --produce
```

Copy `mfnd_p2p_listening=HOST:PORT` from stdout as `HUB_P2P`.

**Validator 1 (committee voter):**

```bash
mkdir -p /tmp/mfn-v1
MFND_VALIDATOR_INDEX=1 \
MFND_VRF_SEED_HEX=0202020202020202020202020202020202020202020202020202020202020202 \
MFND_BLS_SEED_HEX=7676767676767676767676767676767676767676767676767676767676767676 \
$MFND --data-dir /tmp/mfn-v1 --genesis $GENESIS --store fs \
  --rpc-listen 127.0.0.1:0 --p2p-listen 127.0.0.1:0 \
  --p2p-dial $HUB_P2P --slot-duration-ms 30000 serve --committee-vote
```

**Validator 2** — same as validator 1 with index `2` and the third seed pair from genesis; add `--p2p-dial $HUB_P2P`.

---

## Health checks (JSON-RPC)

Each node prints `mfnd_serve_listening=127.0.0.1:PORT`.

**M3.0 — `mfn-cli`** (after `cargo build -p mfn-cli --release`):

```bash
mfn-cli --rpc 127.0.0.1:<RPC_PORT> tip
mfn-cli --rpc 127.0.0.1:<RPC_PORT> methods
```

Raw one-liner (no CLI):

```bash
echo '{"jsonrpc":"2.0","method":"get_tip","id":1}' | nc 127.0.0.1 <RPC_PORT>
```

All validators should report the same `tip_height` and `tip_id` after a slot seals. Use `get_block_header` with `"height": N` to inspect canonical block ids.

---

## P2P mesh tips

- **Boot dial:** At least one `--p2p-dial` to a peer already on the chain (usually the hub). Repeat `--p2p-dial` for multiple seeds (**M2.4.4**).
- **Manifest seeds:** With `--genesis path/to/public_devnet_v1.json`, `mfnd` also dials every `seed_nodes` entry from the sibling `public_devnet_v1.manifest.json` (deduped with CLI flags). Operators append public `host:port` values to that list; stdout prints `mfnd_p2p_boot_dials=…` when any boot peer is configured.
- **Persistent peers:** Successful handshakes append to `peers.json` under `--data-dir`; restart reconnects automatically (**M2.3.22**, **M2.4.2** block-sync on reconnect). Saved-peer reconnect skips addresses already dialed at boot.
- **Catch-up:** Outbound dials pull missing blocks when the remote tip is ahead; handshake height uses the live chain tip (**M2.3.24+**).

---

## CI reference

Integration coverage lives in:

- `mfn-node/tests/three_validator_produce_smoke.rs` — three-process harness, hub + two voters, shared tip through **height 2** (**M2.3.25**).
- `mfn-node/tests/three_validator_all_produce_smoke.rs` — three `--produce` validators on `devnet_three_validators_produce.json` (`expected_proposers_per_slot: 1.5`), shared canonical tip (**M2.3.26**).
- `mfn-node/tests/multi_validator_producer.rs` — in-process proposal/vote/quorum.

Run locally:

```bash
cargo test -p mfn-node --test three_validator_produce_smoke --release
cargo test -p mfn-node --test three_validator_all_produce_smoke --release
```

---

## Roadmap

| Milestone | Focus |
|-----------|--------|
| **M2.4** (this doc) | Operator runbook + public devnet genesis. |
| **M3** | `mfn-cli` wallet (stealth scan, CLSAG send, storage upload). |
| **M4** | WASM bindings for browser wallets. |
| **M5+** | Hardening, audits, public incentivized testnet. |

Privacy (CLSAG, ring signatures, stealth addresses) and permanence (storage endowments, SPoRA proofs) are implemented in consensus and wallet **libraries**; the devnet exercises block production and P2P sync first, then wallets attach via JSON-RPC in M3.
