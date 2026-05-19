# Public devnet v1 — operator invite list (M2.4.3)

Join the **public-devnet-v1** network only if your node's `genesis_id` matches the manifest:

`7fef4492dba32d7ba652cceb5465cae86d6630a9e0a4855adf3acdc5f6b2a2df`

Use genesis file: [`mfn-node/testdata/public_devnet_v1.json`](../../mfn-node/testdata/public_devnet_v1.json).

## Seed nodes

Add your node's **public P2P listen address** (`host:port`, reachable from the internet or your LAN) to [`public_devnet_v1.manifest.json`](../../mfn-node/testdata/public_devnet_v1.manifest.json) under `seed_nodes`, then open a PR or post in the operator channel.

New peers should:

1. Build `mfnd` from this repository (or a release artifact with matching consensus).
2. Start with `--genesis` pointing at the canonical JSON (byte-identical file).
3. `--p2p-dial` at least one `seed_nodes` entry (or a known hub).
4. Verify `mfnd_chain_genesis_id=` on stdout matches the manifest.

## Roles

| Role | Flags | Notes |
|------|--------|--------|
| Hub | `serve --produce` | Usually validator index `0`. |
| Voter | `serve --committee-vote` | Indices `1` and `2`; set `MFND_VALIDATOR_INDEX` + seeds from genesis. |
| Observer | `serve` | No validator env; sync + RPC only. |

## Bootstrap scripts

From repo root (after `cargo build -p mfn-node --release --bin mfnd`):

| Platform | Command |
|----------|---------|
| Linux/macOS | `bash scripts/public-devnet-v1/start-all.sh` |
| Windows | `powershell -File scripts/public-devnet-v1/start-all.ps1` |

Health check: `health-check.sh` or `health-check.ps1` in the same directory.

Full runbook: [`docs/TESTNET.md`](../../docs/TESTNET.md).

## Firewall

| Port | Purpose |
|------|---------|
| P2P listen | Inbound peers (`--p2p-listen 0.0.0.0:PORT` for LAN/public; default loopback-only). |
| RPC listen | Wallets/operators (`--rpc-listen`); keep off the public internet until RPC auth ships. |

## Security

Validator seeds in the public genesis are **test keys only**. Do not use them on mainnet or with real funds.
