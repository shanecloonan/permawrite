# VPS provisioning (Lane 7 / TL-5 prerequisite)

Short guide to get from **zero** to **ready for `vps-internet-soak.sh`**. Provider-agnostic (DigitalOcean, Hetzner, Linode, Vultr, etc.).

Full mesh runbook: [`VPS_SINGLE_BOX_LAUNCH.md`](./VPS_SINGLE_BOX_LAUNCH.md). Ordered phases: [`TESTNET_LAUNCH.md`](./TESTNET_LAUNCH.md).

---

## Minimum spec

| Item | Recommendation |
| --- | --- |
| OS | Ubuntu 22.04 LTS or Debian 12 |
| CPU / RAM | 2 vCPU, 4 GB RAM |
| Disk | 40 GB |
| Network | Static public IPv4 |
| Cost | ~$5–10/month |

Your **laptop** is the ops console (SSH + RPC tunnel). The **VPS** is the always-on mesh.

---

## 1. Create the instance

1. Pick a region close to you (latency matters for SSH; testnet is experimental).
2. Enable **SSH key** auth (disable password login if the provider allows).
3. Note the **public IPv4** — you need it for TL-8 `seed_nodes`.

---

## 2. First login and packages

```bash
ssh root@YOUR_VPS_IP   # or ubuntu@ for some images

apt-get update
apt-get install -y build-essential pkg-config libssl-dev git curl ufw

# Rust (if not using prebuilt release binaries)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
source "$HOME/.cargo/env"
```

---

## 3. Clone and build Permawrite

Use the **software-ready pin** from [`TESTNET_LAUNCH.md`](./TESTNET_LAUNCH.md) (or current `main` after green CI + matching release evidence):

```bash
git clone https://github.com/shanecloonan/permawrite.git
cd permawrite
# Checkout the Release commit from TESTNET_LAUNCH.md § Software-ready pin
git checkout <pin-sha-from-TESTNET_LAUNCH.md>
git log -1 --oneline   # record for soak evidence

cargo build -p mfn-node --release --bin mfnd
cargo build -p mfn-cli --release --bin mfn-cli
cargo build -p mfn-storage-operator --release --bin mfn-storage-operator
```

---

## 4. Firewall (P2P only)

```bash
cd permawrite/scripts/public-devnet-v1
cp vps-bind.env.example vps-bind.env

ufw allow OpenSSH
ufw allow 19001:19004/tcp
ufw enable
ufw status
```

Confirm **18731–18734 are not** in the allow list (RPC stays loopback).

Copy `vps-bind.env.example` to `vps-bind.env` — it sets `MFND_PM23_HARD_FAIL=1` so mfnd aborts on PM23 role-env violations (P32 phase 4c).

**Multi-host alternative:** when validators, observers, operators, and wallets run on separate machines, copy the matching [`vps-role-*.env.example`](../scripts/public-devnet-v1/) templates (see [`REFERENCE_TOPOLOGY.md`](./REFERENCE_TOPOLOGY.md)). Rehearsal gate: `bash scripts/public-devnet-v1/vps-role-templates-rehearsal-smoke.sh --plan-only`.

---

## 5. Preflight

```bash
bash scripts/public-devnet-v1/vps-preflight.sh
```

Expect `detected_public_ip=YOUR_VPS_IP`, `require_endowment_range_proof=1`, and `next=vps-internet-soak.sh`.

---

## 5b. TL-5 soak (human gate — do not skip)

```bash
bash scripts/public-devnet-v1/vps-execution-checklist.sh --strict
bash scripts/public-devnet-v1/vps-internet-soak.sh
# on PASS: archive scripts/public-devnet-v1/evidence/vps-internet-soak-linux-*.txt
```

Then TL-6 on the same VPS:

```bash
bash scripts/public-devnet-v1/vps-participant-rehearsal.sh
```

---

## 6. Run the full ceremony (on VPS)

One helper prints the ordered path and current status:

```bash
bash scripts/public-devnet-v1/vps-execution-checklist.sh   # laptop: verify local RC before provisioning
bash scripts/public-devnet-v1/vps-launch-ceremony.sh --plan-only
bash scripts/public-devnet-v1/vps-launch-ceremony.sh          # status + go/no-go check
```

Then execute TL-5 → TL-6 per [`VPS_SINGLE_BOX_LAUNCH.md`](./VPS_SINGLE_BOX_LAUNCH.md). After VPS evidence is archived, the checklist `v2` JSON also lists TL-7 sign-off, TL-8 `publish-seed-nodes --apply`, checkpoint log publish, and [`TESTNET_INVITE.md`](./TESTNET_INVITE.md) before TL-9 `launch-go-no-go`.

---

## 7. Laptop RPC tunnel (optional)

From your laptop while mesh runs on VPS:

```bash
ssh -N -L 18734:127.0.0.1:18734 root@YOUR_VPS_IP
```

```bash
mfn-cli --rpc 127.0.0.1:18734 status
```

---

## After PASS

1. Commit evidence under `scripts/public-devnet-v1/evidence/`.
2. Complete TL-7 sign-off ([`TESTNET_GENESIS_CEREMONY.md`](./TESTNET_GENESIS_CEREMONY.md)).
3. `publish-seed-nodes.sh --apply`
4. `launch-go-no-go.sh`
5. Share [`TESTNET_INVITE.md`](./TESTNET_INVITE.md) with joiners.
