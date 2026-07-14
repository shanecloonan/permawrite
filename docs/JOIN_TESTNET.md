# Join the Permawrite testnet

**Experimental testnet — pre-audit, test-only value, no production safety claims.**

A live mesh is on the public internet. You can sync blocks, use a wallet, upload permanent data, and run a storage operator. This is the shortest path from zero to participating.

| | |
| --- | --- |
| Network | `public-devnet-v1` |
| Genesis ID | `454fa5d4a9bd6f59e35cf9ea7e68c096c9a271a92b2ec5931184e7f34a42a005` |
| Boot peers | `5.161.201.73:19001`, `5.161.201.73:19002`, `5.161.201.73:19003` |

If your node prints a different `mfnd_chain_genesis_id=`, you are on the wrong chain.

---

## Before you start

- **Rust** stable ([rustup.rs](https://rustup.rs)) or prebuilt `mfnd` / `mfn-cli` from [GitHub Releases](https://github.com/shanecloonan/permawrite/releases).
- **Disk** a few GB for chain data.
- **Firewall:** outbound TCP to the boot peers (no inbound ports required for a wallet user).
- **RPC stays local.** Keep `--rpc-listen` on `127.0.0.1`. Do not expose JSON-RPC to the internet.

Read [`PUBLIC_DEVNET_THREAT_MODEL.md`](./PUBLIC_DEVNET_THREAT_MODEL.md) if you are evaluating real funds or production use. Do not use this network for either.

---

## Step 1 — Clone and build

```bash
git clone https://github.com/shanecloonan/permawrite.git
cd permawrite
cargo build -p mfn-node --release --bin mfnd
cargo build -p mfn-cli --release --bin mfn-cli
```

Windows: same commands in PowerShell from the repo root. Use the `*.ps1` tools under `scripts/` if you do not have MSYS.

---

## Step 2 — Start a node (observer)

This starts a node that syncs over P2P and serves RPC on your machine only:

```bash
mfnd --data-dir ./testnet-data \
  --genesis mfn-node/testdata/public_devnet_v1.json \
  --store fs \
  --rpc-listen 127.0.0.1:18734 \
  --p2p-listen 127.0.0.1:0 \
  serve
```

`mfnd` reads boot peers from `mfn-node/testdata/public_devnet_v1.manifest.json` and dials them automatically.

Leave this terminal running. Open a second terminal for wallet commands.

---

## Step 3 — Confirm you are synced

```bash
mfn-cli --rpc 127.0.0.1:18734 status
mfn-cli --rpc 127.0.0.1:18734 tip
```

Check that:

- `genesis_id` matches the table above.
- `tip_height` increases over a minute or two.

If dials fail, the operator mesh may be restarting. Retry in a few minutes or open a GitHub issue.

---

## Step 4 — Create a wallet

```bash
mfn-cli --rpc 127.0.0.1:18734 --wallet ./alice.json wallet new
mfn-cli --rpc 127.0.0.1:18734 --wallet ./alice.json wallet address
```

Back up `alice.json`. It holds your seed. Never commit it or share it.

---

## Step 5 — Get test funds

Testnet coins have **no real value**. You still need a balance to send transfers or pay upload fees.

**Option A — ask the operator:** open a [GitHub issue](https://github.com/shanecloonan/permawrite/issues) with your `mf...` receive address (from `wallet address`) and ask for a small testnet top-up.

**Option B — run locally:** start your own three-validator mesh with `bash scripts/public-devnet-v1/start-all.sh` (or the `.ps1` on Windows), fund from the documented validator faucet wallet, then point your wallet at that local RPC. See [`TESTNET.md`](./TESTNET.md) for the full local-devnet runbook.

After funding, confirm balance:

```bash
mfn-cli --rpc 127.0.0.1:18734 --wallet ./alice.json wallet scan
mfn-cli --rpc 127.0.0.1:18734 --wallet ./alice.json wallet balance
```

---

## Step 6 — Upload permanent data

Create a small file and upload it:

```bash
echo "hello permanence" > sample.txt
mfn-cli --rpc 127.0.0.1:18734 --wallet ./alice.json wallet upload ./sample.txt --json
```

The JSON output includes `storage_commitment_hash` and `upload_artifact_dir`. Keep the artifact directory — it holds your payload bytes for restore and proof flows.

Retrieve and verify locally:

```bash
mfn-cli --rpc 127.0.0.1:18734 --wallet ./alice.json uploads retrieve \
  --commitment <STORAGE_COMMITMENT_HASH> --out ./restored.txt
```

---

## Optional — storage operator

To replicate chunks and submit SPoRA proofs (earn testnet storage yield), build the operator binary and follow the permanence section in [`OPERATORS.md`](../scripts/public-devnet-v1/OPERATORS.md):

```bash
cargo build -p mfn-storage-operator --release --bin mfn-storage-operator
```

You only need a synced RPC (`127.0.0.1:18734` on your own node). You do not need validator keys.

---

## Troubleshooting

| Problem | What to try |
| --- | --- |
| `tip_height` stuck at 0 | Check outbound connectivity to `5.161.201.73:19001–19003`; restart `mfnd`. |
| Wrong `genesis_id` | Use the exact genesis file from this repo; do not edit it. |
| Wallet balance 0 after funding | Run `wallet scan`, wait for the next block, check `wallet status --json` for `blocks_behind`. |
| Upload fails | Ensure balance covers fee + endowment; wallet needs at least 2 owned UTXOs under current policy — ask for a second top-up if needed. |

More detail: [`TESTNET.md`](./TESTNET.md), [`OPERATORS.md`](../scripts/public-devnet-v1/OPERATORS.md).

---

## What not to share

Never publish validator seeds, wallet JSON files, or RPC URLs on the public internet. Bootstrapping uses P2P addresses only.

---

## Next reading

- [`TESTNET.md`](./TESTNET.md) — full runbook (local mesh, health checks, recovery)
- [`TESTNET_INVITE.md`](./TESTNET_INVITE.md) — operator invite packet and launch evidence
- [`FEES.md`](./FEES.md) — what uploads and transfers cost
- [`STORAGE_ACCESSIBILITY.md`](./STORAGE_ACCESSIBILITY.md) — storage operator hardware expectations