# Public testnet invite packet (Lane 7 / TL-8)

Use this **after** the operator completes TL-5–TL-9 on a VPS and publishes `seed_nodes`. Share this document — not validator seeds, RPC URLs, or wallet files.

**Posture:** pre-audit experimental testnet; test-only value; no production safety claims.

---

## Network identity

| Field | Value |
| --- | --- |
| `network_id` | `public-devnet-v1` |
| `genesis_id` | `454fa5d4a9bd6f59e35cf9ea7e68c096c9a271a92b2ec5931184e7f34a42a005` |
| Genesis file | [`mfn-node/testdata/public_devnet_v1.json`](../mfn-node/testdata/public_devnet_v1.json) (byte-identical required) |
| Boot peers | `seed_nodes` in [`public_devnet_v1.manifest.json`](../mfn-node/testdata/public_devnet_v1.manifest.json) |

Every node must print the same `mfnd_chain_genesis_id=` on startup. A mismatch means you are on a different chain.

---

## What to run (observer or wallet)

Minimum join path — **observer** (sync + RPC for your own use):

```bash
git clone https://github.com/shanecloonan/permawrite.git
cd permawrite
cargo build -p mfn-node --release --bin mfnd
cargo build -p mfn-cli --release --bin mfn-cli

mfnd --data-dir ./observer-data \
  --genesis mfn-node/testdata/public_devnet_v1.json \
  --store fs \
  --rpc-listen 127.0.0.1:18734 \
  --p2p-listen 127.0.0.1:0 \
  serve
```

`mfnd` merges `seed_nodes` from the manifest beside the genesis file and dials boot peers automatically (**M2.4.4**). You may also pass explicit `--p2p-dial HOST:PORT` flags.

Verify:

```bash
mfn-cli --rpc 127.0.0.1:18734 status
mfn-cli --rpc 127.0.0.1:18734 tip
```

Expect `genesis_id` = `454fa5d4…` and advancing `tip_height`.

---

## Wallet quick path

```bash
mfn-cli --rpc 127.0.0.1:18734 --wallet ./alice.json wallet new
# Fund from operator faucet (test-only); see OPERATORS.md fund-wallet
mfn-cli --rpc 127.0.0.1:18734 --wallet ./alice.json wallet upload ./sample.txt --json
```

Read [`TESTNET.md`](./TESTNET.md) § Join The Testnet and [`OPERATORS.md`](../scripts/public-devnet-v1/OPERATORS.md) for permanence flows.

---

## What we do not publish

| Never share | Why |
| --- | --- |
| Validator VRF/BLS seeds | Consensus impersonation |
| `MFND_RPC_API_KEY` / wallet seeds | Custody loss |
| `peers.json` from operators | Topology leak |
| RPC URLs on the public internet | Read exposure + abuse (keep loopback or SSH tunnel) |

Bootstrapping uses **P2P `host:port` only** in `seed_nodes`.

---

## Operator launch evidence (for invitees to request)

Before trusting the network, ask the launch operator for:

- Green CI on the published commit (`release-ci-watch`)
- `release-evidence-*.json` for that commit
- VPS soak transcript: `vps-internet-soak-linux-*.txt` (TL-5)
- VPS rehearsal transcript: `vps-participant-rehearsal-*.txt` (TL-6)
- TL-7 genesis ceremony sign-off ([`TESTNET_GENESIS_CEREMONY.md`](./TESTNET_GENESIS_CEREMONY.md))
- `launch-go-no-go.sh` PASS output (TL-9 automatable gates)

---

## Threat model

Read [`PUBLIC_DEVNET_THREAT_MODEL.md`](./PUBLIC_DEVNET_THREAT_MODEL.md) before joining. Residual risks include undiscovered bugs, public test keys on Path A deployments, and RPC abuse if operators expose JSON-RPC.

---

## Launch path reference

Ordered operator checklist: [`TESTNET_LAUNCH.md`](./TESTNET_LAUNCH.md). Status helper:

```bash
bash scripts/public-devnet-v1/launch-status.sh
```
