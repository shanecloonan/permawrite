# Single-VPS internet-facing testnet (Lane 7 / TL-4)

Minimum deployment for an **experimental internet-facing** public-devnet mesh: one Linux VPS runs hub + two committee voters + observer. P2P is reachable on the public internet; JSON-RPC stays on loopback (operators tunnel in).

**Prerequisites:** TL-2 green CI and TL-3 release evidence on the exact commit you deploy. Read [`PUBLIC_DEVNET_THREAT_MODEL.md`](./PUBLIC_DEVNET_THREAT_MODEL.md) before opening ports.

---

## Hardware and cost

| Role | Minimum | Notes |
| --- | --- | --- |
| VPS | 2 vCPU, 4 GB RAM, 40 GB disk | Ubuntu 22.04+ or Debian 12+ |
| Operator laptop | Any | SSH client; not a consensus peer |
| Budget | ~$5–10/mo | Single provider region is fine for testnet |

A laptop alone is enough for rehearsal (`start-all.sh` on loopback). Internet-facing testnet needs at least one always-on host with a public IP.

---

## Network posture

| Surface | Bind | Firewall |
| --- | --- | --- |
| P2P (hub, voters, observer) | `0.0.0.0:19001–19004` (defaults in `vps-bind.env.example`) | Allow inbound TCP on those ports from `0.0.0.0/0` |
| JSON-RPC | `127.0.0.1:18731–18734` only | **Do not** expose RPC to the internet |
| SSH | `22/tcp` | Restrict to your IP if possible |

Peers dial **P2P addresses only**. Never publish RPC URLs in `seed_nodes` or the manifest.

---

## Provision the VPS

See [`VPS_PROVISION.md`](./VPS_PROVISION.md) for provider-agnostic steps. Summary:

```bash
git clone https://github.com/shanecloonan/permawrite.git && cd permawrite
cargo build -p mfn-node --release --bin mfnd
cargo build -p mfn-cli --release --bin mfn-cli
```

---

## Configure binds

```bash
cd scripts/public-devnet-v1
cp vps-bind.env.example vps-bind.env
# Edit ports if your host already uses 19001–19004
```

`vps-bind.env` sets per-role `MFN_RPC_LISTEN_*` (loopback) and `MFN_P2P_LISTEN_*` (`0.0.0.0`).

Child scripts (`start-hub.sh`, `start-voter.sh`, `start-observer.sh`) honor `MFN_RPC_LISTEN` and `MFN_P2P_LISTEN` when exported by `start-all.sh` in VPS mode.

---

## Start the mesh

```bash
bash scripts/public-devnet-v1/vps-start-all.sh
```

This sets `MFN_VPS_MODE=1`, sources `vps-bind.env`, and runs the normal `start-all.sh` orchestration with public P2P binds.

Verify logs under `scripts/public-devnet-v1/logs/`:

- `mfnd_chain_genesis_id=454fa5d4a9bd6f59e35cf9ea7e68c096c9a271a92b2ec5931184e7f34a42a005`
- `mfnd_p2p_listening=` shows `0.0.0.0:1900x` (not `127.0.0.1`)
- Hub tip advances (`hub_tip_wait` / health-check)

Stop before upgrades:

```bash
bash scripts/public-devnet-v1/stop-all.sh
```

---

## Operator RPC access (SSH tunnel)

From your laptop:

```bash
ssh -N -L 18734:127.0.0.1:18734 user@YOUR_VPS_PUBLIC_IP
```

In another terminal on the laptop:

```bash
export MFN_RPC_URL=http://127.0.0.1:18734
mfn-cli status
mfn-cli wallet status --json
```

Use hub RPC (`18731`) for validator diagnostics; observer (`18734`) for wallet flows.

Optional: set `MFND_RPC_API_KEY` on nodes before launch if you later expose RPC behind TLS with auth (not required for loopback-only).

---

## Firewall example (ufw)

```bash
sudo ufw allow OpenSSH
sudo ufw allow 19001:19004/tcp
sudo ufw enable
sudo ufw status
```

Confirm RPC ports **18731–18734 are not** in the allow list.

---

## TL-5 — Internet soak (height ≥ 10)

After firewall + `vps-bind.env` are configured:

```bash
# Preflight only (bind file, loopback RPC, public P2P, binaries)
bash scripts/public-devnet-v1/vps-preflight.sh

# Start mesh, multi-sample health, archive evidence (default 20 min, min height 10)
bash scripts/public-devnet-v1/vps-internet-soak.sh
```

Override duration or height gate:

```bash
MFN_VPS_SOAK_MINUTES=30 MFN_VPS_SOAK_MIN_HEIGHT=15 \
  bash scripts/public-devnet-v1/vps-internet-soak.sh
```

On **PASS**, evidence is written to `scripts/public-devnet-v1/evidence/vps-internet-soak-linux-*.txt`. Commit that file to the repo (Lane 7 TL-5 gate) before TL-6.

Verify public P2P is listening (not loopback):

```bash
grep mfnd_p2p_listening= scripts/public-devnet-v1/logs/v0.log
# expect 0.0.0.0:19001 (or your vps-bind.env ports)
```

If the mesh is already running:

```bash
bash scripts/public-devnet-v1/vps-internet-soak.sh --no-start
```

---

## TL-6 — Participant rehearsal on VPS

After TL-5 PASS evidence is archived, run the full fund → upload → restore → prove flow on the same host:

```bash
# Mesh still up from TL-5 soak (recommended):
bash scripts/public-devnet-v1/vps-participant-rehearsal.sh --no-start --no-stop

# Cold start (stops any stale mesh, runs vps-preflight + vps-start-all):
bash scripts/public-devnet-v1/vps-participant-rehearsal.sh
```

Evidence archives to `scripts/public-devnet-v1/evidence/vps-participant-rehearsal-observer-linux-*.txt`. Commit on PASS before TL-7.

From your laptop, tunnel observer RPC if running wallet commands remotely:

```bash
ssh -N -L 18734:127.0.0.1:18734 user@YOUR_VPS_PUBLIC_IP
export MFN_RPC_URL=http://127.0.0.1:18734
```

---

## Publish seed nodes (TL-8)

After TL-7 human sign-off (Path A toy keys or Path B fresh genesis), publish P2P seeds:

```bash
# Dry-run (prints JSON snippet):
bash scripts/public-devnet-v1/publish-seed-nodes.sh --public-ip YOUR_VPS_PUBLIC_IP

# Apply to manifest after review:
bash scripts/public-devnet-v1/publish-seed-nodes.sh --public-ip YOUR_VPS_PUBLIC_IP --apply
```

See [`TESTNET_GENESIS_CEREMONY.md`](../docs/TESTNET_GENESIS_CEREMONY.md) for TL-7. Never publish RPC URLs in `seed_nodes`.

Example manifest fragment:

```json
"seed_nodes": [
  "YOUR_VPS_PUBLIC_IP:19001",
  "YOUR_VPS_PUBLIC_IP:19002",
  "YOUR_VPS_PUBLIC_IP:19003"
]
```

---

## TL-9 — Launch go/no-go

Before inviting outside operators:

```bash
bash scripts/public-devnet-v1/launch-go-no-go.sh
```

Automates evidence + `seed_nodes` checks. Human sign-off for TL-7 and TL-9 (named watchers, halt authority) is still required — see [`OPERATORS.md`](../scripts/public-devnet-v1/OPERATORS.md) § Launch go/no-go checklist.

---

## What you cannot edit live

| Change | Effect |
| --- | --- |
| Genesis JSON bytes | New chain (`genesis_id` mismatch) — requires TL-7 ceremony |
| `seed_nodes` in manifest | Bootstrapping only; does not rewrite committed blocks |
| VPS env / firewall | Affects reachability, not consensus rules |
| New blocks / txs | Normal chain evolution via validators |

---

## Next phases

| Phase | Action |
| --- | --- |
| TL-5 | `vps-preflight.sh` then `vps-internet-soak.sh` — archive PASS evidence |
| TL-6 | `vps-participant-rehearsal.sh` — fund → upload → prove on VPS |
| TL-7 | Toy keys vs fresh genesis decision (human) |
| TL-8 | Publish `seed_nodes` + invite packet |
| TL-9 | Launch go/no-go sign-off |

Track status: `bash scripts/public-devnet-v1/launch-status.sh`
