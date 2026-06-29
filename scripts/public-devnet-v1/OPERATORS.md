# Public devnet v1 — operator invite list (M2.4.3 / M2.4.4)

Join the **public-devnet-v1** network only if your node's `genesis_id` matches the manifest:

`7fef4492dba32d7ba652cceb5465cae86d6630a9e0a4855adf3acdc5f6b2a2df`

Use genesis file: [`mfn-node/testdata/public_devnet_v1.json`](../../mfn-node/testdata/public_devnet_v1.json).

## Seed nodes

Add your node's **public P2P listen address** (`host:port`, reachable from the internet or your LAN) to [`public_devnet_v1.manifest.json`](../../mfn-node/testdata/public_devnet_v1.manifest.json) under `seed_nodes`, then open a PR or post in the operator channel.

The manifest includes `seed_nodes_examples` (documentation only — `mfnd` ignores unknown JSON fields and reads only `seed_nodes`). Replace those placeholders with live addresses before publishing.

### Local mesh → published seeds

After `start-all.sh` / `start-all.ps1`:

1. Open `scripts/public-devnet-v1/devnet-ports.env` (see [`devnet-ports.example.env`](devnet-ports.example.env)).
2. Use `HUB_P2P` as `--p2p-dial` for committee voters (already wired in `start-voter.sh`).
3. When exposing validators on a LAN or VPS, bind P2P explicitly, e.g. `--p2p-listen 0.0.0.0:19001`, and append the **reachable** `host:port` to `seed_nodes` in the manifest.

Example manifest after three operators deploy:

```json
"seed_nodes": [
  "203.0.113.10:19001",
  "203.0.113.11:19002",
  "203.0.113.12:19003"
]
```

New peers should:

1. Build `mfnd` from this repository (or a release artifact with matching consensus).
2. Start with `--genesis` pointing at the canonical JSON (byte-identical file).
3. Boot peers: either rely on manifest `seed_nodes` (auto-merged from `public_devnet_v1.manifest.json` beside the genesis file — **M2.4.4**), and/or pass one or more `--p2p-dial host:port` flags (repeatable). `mfnd` trims, dedupes, and validates every boot peer as `HOST:PORT` before dialing; use `[IPv6]:PORT` for IPv6 literals. If your own resolved P2P listen address appears in CLI dials, manifest seeds, or `peers.json`, `mfnd` logs `mfnd_p2p_self_dial_skip peer=...` and skips that outbound dial.
4. Verify `mfnd_chain_genesis_id=` on stdout matches the manifest; when boot peers are configured, `mfnd_p2p_boot_dials=` lists the merged dial set.
5. Run `health-check.sh` / `health-check.ps1` — hub, voters, and the bundled observer must share the same `tip_height` and `tip_id` (**M2.4.6** / **M2.4.9**). For a liveness window, set `MFN_HEALTH_STALL_SAMPLES=2` and `MFN_HEALTH_STALL_INTERVAL_SECONDS` longer than the slot duration; the check fails if the shared tip does not advance by `MFN_HEALTH_MIN_HEIGHT_DELTA` blocks.

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

Stop a local mesh before rebuilding release binaries or running CI:

```bash
# Preview first, then stop PIDs recorded in devnet-ports.env.
bash scripts/public-devnet-v1/stop-all.sh --dry-run
bash scripts/public-devnet-v1/stop-all.sh

# If stale devnet daemons still hold binaries, explicitly stop all mfnd processes owned by this user.
bash scripts/public-devnet-v1/stop-all.sh --all-mfnd
```

```powershell
# Preview first, then stop PIDs recorded in devnet-ports.env.
powershell -File scripts/public-devnet-v1/stop-all.ps1 -DryRun
powershell -File scripts/public-devnet-v1/stop-all.ps1

# If stale devnet daemons still hold target\release\mfnd.exe, explicitly stop all mfnd processes.
powershell -File scripts/public-devnet-v1/stop-all.ps1 -AllMfnd
```

Preflight:

```bash
# Linux/macOS: prints actionable diagnostics for Rust/Git, helper tools,
# release binaries, devnet-ports.env, and running mfnd processes.
bash scripts/public-devnet-v1/preflight.sh

# Treat warnings as failures when preparing to run the full local CI mirror.
bash scripts/public-devnet-v1/preflight.sh --strict
```

```powershell
# Windows: prints actionable diagnostics for Rust/Git, optional helper runtimes,
# release binaries, devnet-ports.env, and running mfnd processes that can lock builds.
powershell -File scripts/public-devnet-v1/preflight.ps1

# Treat warnings as failures when preparing to run the full local CI mirror.
powershell -File scripts/public-devnet-v1/preflight.ps1 -Strict
```

The preflight scripts do not install tools or stop nodes. They report missing `node` for `CODEBASE_STATS.md`, missing helper runtimes such as `bash` / `nc` / `python3`, missing `wasm-pack` and `cargo-audit` for the local CI mirror, missing `dlltool.exe` on Windows release-test setups, missing release binaries, absent `devnet-ports.env`, and running `mfnd` PIDs that should be stopped before rebuilding release binaries in place.

### Toolchain Recovery

Use this when `preflight` or `scripts/ci-check` reports missing tools:

```powershell
# Windows: Rust-side CI helpers.
cargo install wasm-pack --locked
cargo install cargo-audit --locked

# Windows: Node.js for CODEBASE_STATS.md and Git Bash for .sh validation.
winget install OpenJS.NodeJS.LTS
winget install Git.Git

# Windows: dlltool.exe for release-test dependencies.
# Install MSYS2, then add the mingw64 bin directory to PATH.
winget install MSYS2.MSYS2
pacman -S --needed mingw-w64-x86_64-binutils
```

```bash
# Linux/macOS: Rust-side CI helpers.
cargo install wasm-pack --locked
cargo install cargo-audit --locked

# Linux examples.
sudo apt-get update
sudo apt-get install -y nodejs npm netcat-openbsd python3

# macOS examples.
brew install node netcat python
```

After installing tools, open a fresh shell so PATH changes are visible, rerun `preflight` in strict mode, and only then rerun `node scripts/codebase-stats.mjs` and the local CI mirror.

## Launch go/no-go checklist

Use this checklist before advertising a public testnet endpoint, publishing seed nodes, or asking outside operators to join. A single unchecked critical item is a no-go. This project is pre-audit; passing this checklist means "acceptable experimental public-devnet risk," not production safety.

### Critical no-go items

- [ ] `git pull --ff-only origin main` succeeds on the release branch, or the exact release commit is intentionally pinned and reviewed.
- [ ] `CODEBASE_STATS.md` was regenerated with `node scripts/codebase-stats.mjs` after the final code/doc changes.
- [ ] The local CI mirror passed on the release host or equivalent clean machine: `scripts/ci-check.ps1` on Windows or `scripts/ci-check.sh` on Linux/macOS.
- [ ] Ignored/nightly smoke coverage passed for public-devnet release candidates: `scripts/ci-ignored.ps1` or `scripts/ci-ignored.sh`.
- [ ] GitHub CI is green for the exact commit that will be published.
- [ ] `SECURITY.md` still states the software is pre-audit and does not imply production-grade security.
- [ ] The published genesis JSON and manifest are byte-identical across operators, and every node prints the expected `mfnd_chain_genesis_id=`.
- [ ] Public deterministic test seeds were replaced for any shared, production-like, incentivized, or non-toy deployment.
- [ ] RPC is loopback-only, VPN/SSH-only, or behind the documented firewall/TLS pattern; `mfn-cli --rpc <RPC> status` reports `rpc.public_bind=false` unless an explicit firewall/API-key/TLS review approved the exposure.
- [ ] Backups exist for node data dirs, genesis/manifest, wallet files, upload artifacts, validator secrets, and RPC API keys; at least one restore was tested on an isolated host.
- [ ] Rollback plan is written down: previous binary, pre-upgrade data-dir backup, operator contact path, and conditions for stopping rather than rolling back.

### Operator readiness

- [ ] Each validator operator has only their own `MFND_VALIDATOR_INDEX`, `MFND_VRF_SEED_HEX`, and `MFND_BLS_SEED_HEX`.
- [ ] Operators know that current devnet validator VRF/BLS seeds are not live-rotatable on an already-published genesis.
- [ ] `seed_nodes` contains reachable public P2P addresses only; no private RPC addresses, wallet files, API keys, or `peers.json` contents are published.
- [ ] P2P ports are reachable from at least one external observer, while RPC ports are not directly reachable unless intentionally exposed through the documented controls.
- [ ] `mfn-cli --rpc <RPC> status` and `tip` return the expected `genesis_id`, shared `tip_height`, shared `tip_id`, `rpc.listen_addr`, and `rpc.public_bind` posture.
- [ ] Multi-sample health checks pass with a liveness window longer than the configured slot duration.
- [ ] At least one storage upload, replication/backfill, retrieval, and SPoRA proof flow has been rehearsed on the candidate network or a byte-identical staging network.

### Launch-day watch

- [ ] A named operator watches `mfnd` stdout/stderr for genesis mismatch, P2P quarantine, stalled height, malformed RPC, and storage proof failures.
- [ ] A named operator watches GitHub Actions after the launch commit reaches `main`.
- [ ] Operators agree on halt conditions: divergent tips, repeated invalid block/gossip errors, leaked validator seeds, unexpected public RPC exposure, or reproducible storage data-root mismatches.
- [ ] Operators agree where incident notes live and who can publish "pause, rollback, or rotate genesis" instructions.

Health check: `health-check.sh` or `health-check.ps1` in the same directory (**M2.4.6** / **M2.4.9** — exits non-zero if hub, voters, or observer diverge, `genesis_id` ≠ public devnet manifest, or an opt-in multi-sample liveness window stalls).

Local soak:

```bash
bash scripts/public-devnet-v1/soak.sh --duration-minutes 60
powershell -File scripts/public-devnet-v1/soak.ps1 -DurationMinutes 60
```

The soak starts the local hub + two voters + observer unless `--no-start` / `-NoStart` is supplied, checks recorded PIDs, verifies follower/observer P2P dial logs, and repeatedly runs the multi-sample health check.

If a peer repeatedly fails outbound dials, fan-out, or catch-up, `mfnd` temporarily quarantines that address in memory and logs `mfnd_p2p_peer_quarantine peer=...`. Quarantine skips reconnect/catch-up/fan-out attempts for that process only; a later successful handshake or push clears the penalty, and a restart reloads the persisted `peers.json` normally. The saved `max_outbound_peers` reconnect cap defaults to 8 and is clamped to 64 even if `peers.json` is hand-edited. If malformed, empty, or duplicate saved peers are ignored on load, `mfnd` logs `mfnd_peers_load_filtered raw=... kept=... filtered=...`.

When a saved peer is also present in CLI or manifest boot dials, reconnect skips the duplicate and logs `mfnd_p2p_reconnect_skip peer=... reason=boot_dial`; the explicit boot dial remains responsible for that connection attempt.

If saved-peer reconnect reaches the configured cap, `mfnd` logs `mfnd_p2p_reconnect_cap_reached count=... cap=...`. Increase `max_outbound_peers` in `peers.json` only when the host and network can tolerate more simultaneous boot dials.

Committee catch-up uses the same cap during periodic sync pulls and skips the node's own P2P listen address with `mfnd_p2p_self_dial_skip peer=...`. If an interval reaches the cap, `mfnd` logs `mfnd_p2p_catchup_cap_reached count=... cap=...`; this means remaining saved peers are deferred to later intervals rather than dialed all at once.

If an outbound dial fails with `reason=genesis_mismatch ...`, the peer is on a different chain. `mfnd` drops that address from the durable peer set and logs `mfnd_p2p_peer_drop peer=... reason=genesis_mismatch ...`; fix the manifest or operator inventory rather than re-adding the peer.

Full runbook: [`docs/TESTNET.md`](../../docs/TESTNET.md).

New participants should start with the role-based [Join the testnet](../../docs/TESTNET.md#join-the-testnet) path before choosing observer, wallet, storage-operator, or validator commands.

## Firewall

| Port | Purpose |
|------|---------|
| P2P listen | Inbound peers (`--p2p-listen 0.0.0.0:PORT` for LAN/public; default loopback-only). |
| RPC listen | Wallets/operators (`--rpc-listen`); see [RPC exposure](#rpc-exposure-m248) below. |

## RPC exposure (M2.4.8)

`mfnd serve` exposes an **unauthenticated** JSON-RPC 2.0 line protocol on `--rpc-listen`. Any client that can open a TCP connection may:

- Read chain state (`get_tip`, `get_block`, `list_methods`, …)
- Submit transactions and storage proofs (`submit_tx`, `submit_storage_proof`, …)
- Inspect the mempool and proof pool

There is **no TLS** in v0.1 testnet builds. Optional API-key auth can gate `wallet-write` and `operator-admin` RPC methods, but public read methods remain open by design.

| Deployment | Recommended bind | Rationale |
|------------|------------------|-----------|
| Local dev / CI | `127.0.0.1:0` (default) | OS-assigned port; not reachable from other hosts. |
| LAN validators | `127.0.0.1:PORT` + SSH tunnel for operators | Wallets/operators connect via tunnel; P2P still on `0.0.0.0` if needed. |
| Public VPS | **Do not** publish RPC to `0.0.0.0` | Use firewall deny on the RPC port; operators use VPN/SSH. P2P may be public. |

P2P and RPC are independent: you can advertise `mfnd_p2p_listening=` to the mesh while keeping RPC loopback-only.

Even with RPC API-key auth enabled, treat `--rpc-listen 0.0.0.0` as high risk until TLS, rate limits, and deployment hardening are in place.

### RPC capacity and diagnostics

`mfnd serve` defaults to at most 64 in-flight JSON-RPC connections. Set `MFND_RPC_MAX_IN_FLIGHT=<N>` only when the host has enough CPU, memory, file descriptors, and upstream firewall/TLS/rate-limit controls for the larger connection budget. Lower it on small VPS instances or private staging nodes where slow clients should be shed aggressively.

Verify the active limits through `mfn-cli --rpc <RPC> status`: the `rpc` object reports `listen_addr`, `public_bind`, `max_in_flight`, `current_in_flight`, `max_request_line_bytes`, and `io_timeout_ms`. During launch-day watch, `public_bind=true` means the node is not loopback-only, and sustained `current_in_flight` near `max_in_flight` means the node is at the RPC edge; inspect firewall/proxy logs before raising the cap.

### Firewall and TLS examples

The safest public-devnet shape is: public P2P, private RPC. Bind RPC to loopback, require an API key for write/admin methods, and expose it only through a tunnel, VPN, or TLS reverse proxy that you control.

```bash
# Linux/macOS: node binds RPC locally and P2P publicly.
MFND_RPC_API_KEY="$(openssl rand -hex 32)" \
target/release/mfnd --data-dir /var/lib/permawrite \
  --genesis mfn-node/testdata/public_devnet_v1.json \
  --rpc-listen 127.0.0.1:18731 \
  --p2p-listen 0.0.0.0:19001 \
  serve
```

```powershell
# Windows PowerShell: node binds RPC locally and P2P publicly.
$bytes = [byte[]]::new(32)
[System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
$env:MFND_RPC_API_KEY = -join ($bytes | ForEach-Object { $_.ToString("x2") })
target\release\mfnd.exe --data-dir C:\permawrite\data `
  --genesis mfn-node\testdata\public_devnet_v1.json `
  --rpc-listen 127.0.0.1:18731 `
  --p2p-listen 0.0.0.0:19001 `
  serve
```

Linux `ufw` baseline: allow SSH and P2P, deny direct RPC. If operators need remote RPC, prefer WireGuard/VPN or SSH forwarding (`ssh -L 18731:127.0.0.1:18731 operator@host`) over publishing the RPC port.

```bash
sudo ufw default deny incoming
sudo ufw allow OpenSSH
sudo ufw allow 19001/tcp comment 'permawrite p2p'
sudo ufw deny 18731/tcp comment 'permawrite rpc stays private'
sudo ufw enable
```

Windows Defender Firewall baseline: allow inbound P2P, block inbound RPC. Run PowerShell as Administrator.

```powershell
New-NetFirewallRule -DisplayName "Permawrite P2P 19001" `
  -Direction Inbound -Action Allow -Protocol TCP -LocalPort 19001
New-NetFirewallRule -DisplayName "Permawrite RPC 18731 private" `
  -Direction Inbound -Action Block -Protocol TCP -LocalPort 18731
```

If RPC must cross the internet, terminate TLS before it reaches `mfnd` and keep `mfnd` bound to `127.0.0.1`. The example below uses Nginx `stream` TLS proxying; restrict the allowed source IPs at the host firewall or cloud security group, because the JSON-RPC protocol itself is still newline-delimited TCP and public read methods remain unauthenticated.

```text
# /etc/nginx/nginx.conf
stream {
  upstream mfnd_rpc {
    server 127.0.0.1:18731;
  }

  server {
    listen 443 ssl;
    proxy_pass mfnd_rpc;

    ssl_certificate /etc/letsencrypt/live/rpc.example.net/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/rpc.example.net/privkey.pem;

    allow 198.51.100.0/24;
    allow 203.0.113.10;
    deny all;
  }
}
```

`mfn-cli` speaks raw TCP, not TLS. Client-side, prefer SSH forwarding and keep normal CLI calls pointed at loopback:

```bash
ssh -N -L 18731:127.0.0.1:18731 operator@rpc.example.net
MFN_RPC_API_KEY="$MFND_RPC_API_KEY" mfn-cli --rpc 127.0.0.1:18731 status
```

For the Nginx TLS proxy pattern, run a client-side TLS wrapper such as `stunnel` that exposes a local raw TCP port, then point `mfn-cli` at that local port. Do not point `mfn-cli` directly at `rpc.example.net:443`.

## Security

Validator seeds in the public genesis are **test keys only**. Do not use them on mainnet or with real funds.

Never commit wallet files, production seeds, or `peers.json` from private networks into public repos.

### Replacing public test keys

Before any shared devnet with non-public funds, incentivized rewards, or production-like uptime expectations, fork the genesis instead of reusing `public_devnet_v1.json` as-is:

1. Generate fresh 32-byte VRF and BLS seed hex for every validator on an offline or operator-controlled machine.
2. Replace every `validators[].vrf_seed_hex` and `validators[].bls_seed_hex` value in a copied genesis JSON. Keep validator `index` values contiguous from `0`; choose stake values intentionally because quorum weight follows the genesis rows.
3. Regenerate and publish the manifest `genesis_id` for the exact byte-identical genesis file operators will run. Peers reject handshakes when `genesis_id` differs, so do not edit whitespace or fields after publishing without also publishing a new manifest.
4. Give each operator only their own `MFND_VALIDATOR_INDEX`, `MFND_VRF_SEED_HEX`, and `MFND_BLS_SEED_HEX`; never share all validator seeds in one chat, ticket, or repo.
5. Start validators with the copied genesis and verify stdout `mfnd_chain_genesis_id=` matches the new manifest before opening P2P ports.
6. Rotate `seed_nodes` to reachable P2P addresses for the new network. Do not copy `peers.json` from a different genesis or private network.
7. Create fresh wallet files for the network and back them up separately. Never reuse devnet wallet seeds, production validator seeds, or public payout test keys across networks.

If a seed leaks before launch, discard the genesis and publish a new `genesis_id`. If a seed leaks after launch, treat that validator as compromised until validator-rotation and slashing policy for that network can remove or slash it.

---

## Backups, upgrades, rollback, and key rotation

This is a public-devnet runbook, not a production custody policy. Permawrite is still pre-audit software; keep validator keys, wallet seeds, and RPC API keys out of chat logs, tickets, repos, shell history, and shared screenshots.

### What to back up

Back up enough material to recover both the chain node and the operator's ability to spend, prove, and serve permanent data:

| Item | Why it matters | Handling |
|------|----------------|----------|
| `--data-dir` | Node store, durable block log/replay state, saved peers, and `chunk-inbox/` replica bytes. | Stop `mfnd` first, then archive the directory. Encrypt before copying off host. |
| Genesis JSON + manifest | Defines the exact `genesis_id`; peers reject mismatches. | Keep byte-identical copies with the backup. Do not edit after publication. |
| Validator env values | `MFND_VALIDATOR_INDEX`, `MFND_VRF_SEED_HEX`, and `MFND_BLS_SEED_HEX` are signing authority for the validator. | Store in a password manager or offline secret store, never in the repo. |
| Wallet files | Spending/proving identity and light-client trusted summaries live in `wallet.json`-style files. | Encrypt separately; test restore on a non-public node. |
| `*.upload-artifacts/` | Local payload/chunk metadata needed to serve/reprove storage uploads. | Back up with the wallet or make sure enough independent peers hold byte-identical chunks. |
| RPC API key | Required by auth-enabled nodes for `wallet-write` and `operator-admin` calls. | Rotate if it appears in logs or is shared beyond intended operators. |

Linux example:

```bash
sudo systemctl stop permawrite-mfnd || true
tar --xattrs --acls -czf permawrite-node-$(date -u +%Y%m%dT%H%M%SZ).tgz \
  /var/lib/permawrite \
  mfn-node/testdata/public_devnet_v1.json \
  mfn-node/testdata/public_devnet_v1.manifest.json
```

Windows PowerShell example:

```powershell
Stop-Process -Name mfnd -ErrorAction SilentlyContinue
$stamp = (Get-Date).ToUniversalTime().ToString("yyyyMMddTHHmmssZ")
Compress-Archive -Path C:\permawrite\data, `
  mfn-node\testdata\public_devnet_v1.json, `
  mfn-node\testdata\public_devnet_v1.manifest.json `
  -DestinationPath "permawrite-node-$stamp.zip"
```

Before trusting a backup, restore it on an isolated machine, start `mfnd serve` on loopback, then verify:

```bash
mfn-cli --rpc 127.0.0.1:<RPC> status
mfn-cli --rpc 127.0.0.1:<RPC> tip
mfn-cli --rpc 127.0.0.1:<RPC> --wallet ./operator.json wallet status --json
mfn-cli --rpc 127.0.0.1:<RPC> --wallet ./operator.json wallet balance --json
mfn-cli --wallet ./operator.json wallet backup-info
mfn-cli --wallet ./operator.json operator artifacts --json
mfn-cli --rpc 127.0.0.1:<RPC> --wallet ./operator.json uploads status --json
```

`wallet status --json` is seed-free and reports the cached wallet view (`scan_height`, `tip_height`, `blocks_behind`, `sync_needed`, cached balance/owned counts, pending spends, and light-summary presence) without downloading blocks. Use it before `wallet scan --json` or `wallet balance --json` when a support ticket needs to distinguish a stale scan from missing funds; the scan/balance JSON output records `blocks_scanned`, final `scan_height`, balance, owned-output count, and pending-spend count after the rescan. `wallet backup-info` is also seed-free and should be safe to paste into an operator ticket; add `--json` when automation needs a structured inventory. It reports whether upload artifacts exist, where they live, and how many payload bytes need backup. `operator artifacts --json` / `uploads local --json` and `uploads status --json` print structured artifact manifests, aggregate payload bytes, and reconciliation rows so operators can size backup archives and detect missing local artifacts before copying. `wallet restore <SEED_HEX>` recovers spend authority, but it does not recreate `{wallet_stem}.upload-artifacts/`. If a restored operator wallet reports `chain_only` rows in `uploads status`, rebuild artifacts from a peer before proving: use `uploads fetch-http <COMMIT_HASH_HEX> ./restored.bin <PEER_HTTP> --json` for HTTP chunk replicas, or assemble P2P inbox chunks and then run `uploads retrieve <COMMIT_HASH_HEX> ./restored.bin`.

### Upgrade

Only upgrade a validator after the candidate commit has passed the local CI mirror and, for shared testnets, after operators agree on the target commit or release artifact. Mixed binaries are acceptable only when the consensus wire/state format is unchanged; if a release changes consensus, checkpoint encoding, genesis handling, or P2P frame semantics, coordinate the upgrade window.

1. Record current health: `mfn-cli --rpc <RPC> status`, `mfn-cli --rpc <RPC> tip`, and the stdout `mfnd_chain_genesis_id=`.
2. Stop `mfnd` cleanly. If running under a supervisor, disable restart during the upgrade.
3. Back up the node data dir, genesis, manifest, wallet files, and upload artifacts.
4. Build or install the new binaries: `cargo build -p mfn-node -p mfn-cli -p mfn-storage-operator --release`.
5. Start with the same `--data-dir`, `--genesis`, `--store`, RPC, P2P, and validator env values.
6. Verify `genesis_id`, `tip_height`, `tip_id`, and peer connectivity before re-enabling producer/voter duties.
7. Keep the previous binary and backup until the node has sealed or accepted new blocks and peers agree on the tip.

### Rollback

Rollback is safe only when the new binary has not written data that the old binary cannot read. If a release changes checkpoint/store schema or consensus behavior, treat rollback as a coordinated network event rather than a local operation.

1. Stop `mfnd`.
2. Preserve the failed post-upgrade data dir for diagnosis; do not overwrite the only copy.
3. Restore the pre-upgrade data-dir backup or start the previous binary against an unchanged copy.
4. Start on loopback first and check `status`, `tip`, and `genesis_id`.
5. Reopen P2P only after the node follows the same tip as trusted peers.

If the upgraded node broadcast invalid data, leaked secrets, or followed a different `genesis_id`, do not simply roll back and rejoin. Quarantine the host, rotate affected keys/API secrets, and coordinate with other operators.

### Key rotation

Current devnet validator keys are genesis-bound test keys. There is no live hot-swap for `MFND_VRF_SEED_HEX` or `MFND_BLS_SEED_HEX` on an already-published genesis. Rotating validator identity today means publishing a new genesis/manifest or using future validator-rotation protocol support once that path is operational for the target network.

Use this policy until live validator-key rotation is implemented:

| Secret | Normal rotation | Compromise response |
|--------|-----------------|---------------------|
| RPC API key | Generate a new 32-byte random key, restart `mfnd` with `MFND_RPC_API_KEY`, and redistribute only to intended operators. | Rotate immediately; assume write/admin RPC was available to anyone who had the old key. |
| Wallet seed/file | Create a new wallet and move spendable funds when protocol/tooling allows. | Stop using the old wallet; treat pending uploads/proofs as untrusted until reconciled. |
| Validator VRF/BLS seed | Not live-rotatable on the current public genesis. | Before launch, discard the genesis and publish a new `genesis_id`; after launch, coordinate removal/replacement through validator-rotation governance/tooling when available. |
| TLS/private host keys | Rotate certificate/key material through the proxy or host OS. | Revoke/replace certificates and audit proxy/firewall logs. |

After any key or API-key rotation, rerun health checks and update only the private operator inventory. Do not publish validator seeds, wallet files, API keys, or private `peers.json` contents in the manifest.

---

## Permanence operators (storage + SPoRA) — M6 / M7

Permawrite separates **on-chain anchors** (private `StorageCommitment` in a block) from **off-chain bytes** (chunk payloads). Validators only mine SPoRA proofs when they can read the challenged chunk. Operators run replication and proving on devnet today via `mfn-cli` and `mfn-storage-operator`.

Build both CLIs after `mfnd`:

```bash
cargo build -p mfn-node --release --bin mfnd
cargo build -p mfn-cli --release --bin mfn-cli
cargo build -p mfn-storage-operator --release --bin mfn-storage-operator
```

Point `--rpc` at any synced node's `mfnd_serve_listening=` address. Use the same `--wallet` file for upload, prove, and chunk commands.

### End-to-end flow

```text
wallet upload  →  tx mined (storage on-chain)
       ↓
replicate bytes to peers (HTTP and/or P2P ChunkV1)
       ↓
assemble local artifact  →  operator prove  →  SPoRA proof mined
```

| Stage | On-chain | Off-chain |
|-------|----------|-----------|
| Upload | Commitment + endowment in a block | `wallet.upload-artifacts/<hash>/` (payload + metadata) |
| Replicate | — | Peers hold matching chunk bytes |
| Prove | `StorageProof` in a later block | Operator uses artifact or inbox bytes |

### 1. Anchor data (any synced node)

```bash
mfn-cli --rpc 127.0.0.1:<RPC> wallet new   # once per operator
mfn-cli --rpc 127.0.0.1:<RPC> --wallet ./alice.json \
  wallet upload ./myfile.bin --fee 10000 --replication 3 --json
```

JSON stdout includes `storage_commitment_hash`, `data_root`, `tx_id`, `upload_artifact_dir`, `upload_artifact_payload_bytes`, fee/burden fields, and post-upload wallet state. Mine the mempool tx on a producer (stop `serve`, run `mfnd step`, or wait for the next sealed block on `--produce`).

Check status:

```bash
mfn-cli --rpc 127.0.0.1:<RPC> uploads list --limit 20 --include-claims --json
mfn-cli --rpc 127.0.0.1:<RPC> operator challenge <COMMIT_HASH_HEX> --json
```

### 2. Replicate chunk bytes

Pick **at least `replication` peers** (from the commitment) that store byte-identical chunks.

#### HTTP (M6) — good for observers and static fetch

On a machine that has the wallet artifact:

```bash
mfn-storage-operator serve-chunks --wallet ./alice.json --listen 127.0.0.1:18780
# GET http://127.0.0.1:18780/chunk/<commit_hex>/<index>
```

Or prove + serve in one process:

```bash
mfn-storage-operator run --once --chunk-listen 127.0.0.1:18780 \
  --wallet ./alice.json --rpc 127.0.0.1:<RPC>
```

Pull from a peer into the local artifact tree:

```bash
mfn-cli --rpc 127.0.0.1:<RPC> --wallet ./alice.json \
  operator fetch-chunk <COMMIT_HASH_HEX> 0 127.0.0.1:18780

mfn-cli --rpc 127.0.0.1:<RPC> --wallet ./alice.json \
  operator backfill <COMMIT_HASH_HEX> 127.0.0.1:18780 [more-peers...] --json
```

With multiple peers, `backfill` requires **byte-identical** chunks from every peer (quorum verify). Add `--json` to capture the rebuilt `artifact_dir`, `payload_bytes`, peer list, and quorum size in automation or support tickets.

To restore directly from HTTP chunk peers into a local file:

```bash
mfn-cli --rpc 127.0.0.1:<RPC> --wallet ./bob.json \
  uploads fetch-http <COMMIT_HASH_HEX> ./restored.bin 127.0.0.1:18780 [more-peers...] [replace] --json
```

`uploads fetch-http` first rebuilds the wallet artifact from peer chunks using the on-chain challenge, then exports the restored payload bytes. Add `--json` to record the restored `output_path`, `artifact_dir`, `payload_bytes`, peer list, and quorum size. Use `replace` only when both the local artifact and output file may be overwritten.

#### P2P ChunkV1 (M7) — good for `mfnd` mesh

Each `mfnd --data-dir` may contain:

```text
<data-dir>/chunk-inbox/<commit_hex>/<index>.bin
```

Push all artifact chunks over an existing P2P session (handshake + burst + `GossipEnd`):

```bash
# PEER is the remote mfnd_p2p_listening= host:port (not your own hub port)
mfn-cli --rpc 127.0.0.1:<HUB_RPC> --wallet ./alice.json \
  operator push-chunks <COMMIT_HASH_HEX> <PEER1> [PEER2 ...]

mfn-storage-operator push-chunks --wallet ./alice.json \
  <COMMIT_HASH_HEX> <PEER1> [PEER2 ...]
```

On the receiver (same `genesis_id`, caught up to the upload block):

```bash
mfn-cli --rpc 127.0.0.1:<REPLICA_RPC> operator inbox-status <COMMIT_HASH_HEX> /path/to/replica-data-dir --json
mfn-cli --rpc 127.0.0.1:<REPLICA_RPC> --wallet ./bob.json \
  operator assemble-inbox <COMMIT_HASH_HEX> /path/to/replica-data-dir --json

# Export the reassembled anchored payload for local inspection or restore.
mfn-cli --wallet ./bob.json uploads retrieve <COMMIT_HASH_HEX> ./restored.bin
```

**Auto fan-out (M7.5):** When `mfnd` applies a block that adds **new** storage and already has a **complete** inbox for that commitment, it pushes `ChunkV1` to registered `peers.json` entries **and** live P2P sessions (after producer seal or inbound `BlockV1`). This does **not** run for wallet-only uploads until chunks are in the producer's inbox (usually via `push-chunks` to self or peers first).

**P2P catch-up:** Outbound `--p2p-dial` pulls missing blocks **before** blocking on gossip, so replicas can reach the upload height then receive chunks.

### 3. Submit SPoRA proof

Requires local bytes matching `data_root` (artifact or assembled inbox):

```bash
mfn-cli --rpc 127.0.0.1:<RPC> --wallet ./alice.json \
  operator prove <COMMIT_HASH_HEX>

# Or raw file (must match on-chain size_root):
mfn-cli --rpc 127.0.0.1:<RPC> operator prove <COMMIT_HASH_HEX> ./myfile.bin
```

One-shot operator loop:

```bash
mfn-storage-operator run --once --wallet ./alice.json --rpc 127.0.0.1:<RPC>
```

Inspect the node's proof mempool:

```bash
mfn-cli --rpc 127.0.0.1:<RPC> operator pool --json
```

After the proof is mined, `uploads list` should show a higher `last_proven_height`.

### Devnet mesh checklist

1. Start hub + voters ([bootstrap scripts](#bootstrap-scripts)); note each `mfnd_p2p_listening=`.
2. Upload on a wallet connected to the hub RPC; mine the tx.
3. `push-chunks` to two voter P2P ports (or HTTP `serve-chunks` on the uploader).
4. On each voter: `inbox-status` → `assemble-inbox` → `operator prove` when challenged.
5. For HTTP replicas, run `uploads fetch-http <COMMIT_HASH_HEX> ./restored.bin <PEER_HTTP>`; for assembled P2P artifacts, run `uploads retrieve <COMMIT_HASH_HEX> ./restored.bin`. Confirm identical payload hashes across peers before proving.

### Funding test wallets

Participants need devnet MFN before they can send, claim, or upload. Operators can fund a participant wallet from an already-funded faucet wallet:

```powershell
# Optional local-devnet faucet: restore validator 0's public test payout wallet.
# This is test-only; never reuse public genesis seeds on a network with real value.
mfn-cli --wallet .\validator0-faucet.json --force wallet restore `
  6565656565656565656565656565656565656565656565656565656565656565 `
  --key-derivation payout_stealth_v1

# Shows the resolved RPC, recipient path, amount, and send flow.
powershell -File scripts/public-devnet-v1/fund-wallet.ps1 -PlanOnly

# Real run: create/reuse recipient wallet, send from faucet wallet, wait for balance delta.
powershell -File scripts/public-devnet-v1/fund-wallet.ps1 `
  -Rpc 127.0.0.1:<RPC> `
  -FaucetWallet C:\path\to\faucet.json `
  -RecipientWallet .\alice.json `
  -Amount 1000000
```

Linux/macOS operators can use the matching shell helper:

```bash
# Optional local-devnet faucet: restore validator 0's public test payout wallet.
# This is test-only; never reuse public genesis seeds on a network with real value.
mfn-cli --wallet ./validator0-faucet.json --force wallet restore \
  6565656565656565656565656565656565656565656565656565656565656565 \
  --key-derivation payout_stealth_v1

# Shows the resolved RPC, recipient path, amount, and send flow.
bash scripts/public-devnet-v1/fund-wallet.sh --plan-only

# Real run: create/reuse recipient wallet, send from faucet wallet, wait for balance delta.
bash scripts/public-devnet-v1/fund-wallet.sh \
  --rpc 127.0.0.1:<RPC> \
  --faucet-wallet ./validator0-faucet.json \
  --recipient-wallet ./alice.json \
  --amount 1000000
```

`fund-wallet.ps1` and `fund-wallet.sh` never embed faucet seeds; they require an operator-supplied wallet file that already has spendable devnet outputs. They submit with `wallet send --json`, record the `tx_id`, mempool length, and submission outcome, then wait for `starting_balance + Amount`, so an already-funded wallet does not mask an unmined transfer. For the checked-in `public_devnet_v1.json`, validator payout wallets are derived from each public validator `bls_seed_hex` with `payout_stealth_v1`, so the examples above are only appropriate for local/public test funds earned by validator 0. Keep faucet wallets out of the repo, never reuse public genesis seeds on a network with real value, and wait for the transfer to mine before asking the participant to run `wallet upload` or the permanence demo.

### Permanence demo scripts

Windows operators can run a guided HTTP permanence loop against an existing public-devnet RPC:

```powershell
# Prints the planned flow and resolved RPC without requiring binaries.
powershell -File scripts/public-devnet-v1/permanence-demo.ps1 -PlanOnly

# Real run: upload -> discover -> serve HTTP chunks -> fetch-http restore -> prove.
powershell -File scripts/public-devnet-v1/permanence-demo.ps1 -Rpc 127.0.0.1:<RPC>
```

Linux/macOS operators can run the matching shell demo:

```bash
# Prints the planned flow and resolved RPC without requiring binaries.
bash scripts/public-devnet-v1/permanence-demo.sh --plan-only

# Real run: upload -> discover -> serve HTTP chunks -> fetch-http restore -> prove.
bash scripts/public-devnet-v1/permanence-demo.sh --rpc 127.0.0.1:<RPC>
```

The demos store wallets and payloads under `scripts/public-devnet-v1/permanence-demo/` by default and reuse existing wallet files on repeat runs. Before a real run, fund the uploader wallet with enough devnet MFN for upload fees and storage endowment; otherwise `wallet upload` will fail during tx construction. The scripts exit nonzero if the upload is not discovered, peer restore fails, proof submission fails, or the restored SHA-256 does not match the original payload.

### Permanence troubleshooting

| Symptom | Likely cause | Recovery |
|---------|--------------|----------|
| `wallet upload` succeeds but `uploads list` does not show the commitment | The tx is still only in the mempool, or the wallet is pointed at a node on a different chain/tip | Prefer `wallet upload --json` and keep the `tx_id`, `storage_commitment_hash`, `data_root`, `upload_artifact_dir`, and `fee` fields. After mining, run `uploads list --include-claims --json` and keep `uploads_returned`, matching upload rows, and any claim arrays. Check `mfn-cli --rpc <RPC> mempool` for the tx id, mine or wait for the next producer block, then verify `mfn-cli --rpc <RPC> tip` and `genesis_id` match the public devnet manifest. |
| `wallet claim --json` succeeds but claim queries do not show the authorship row | The claim tx is still only in the mempool, the query is pointed at a stale/diverged node, or the wrong `data_root`/`claim_pubkey` is being queried | Keep the `tx_id`, `claim_pubkey_hex`, `data_root`, and `commit_hash` from `wallet claim --json`; after mining, run `claims for <DATA_ROOT_HEX> --json` and, if needed, `claims by-pubkey <CLAIM_PUBKEY_HEX> --json` against a synced node with the same `genesis_id`. |
| `wallet balance` looks stale or support cannot tell whether funds were scanned | The wallet cache is behind the node tip, or pending spends are masking locally selected outputs | Run `mfn-cli --rpc <RPC> --wallet <WALLET> wallet status --json` and capture `scan_height`, `tip_height`, `blocks_behind`, `sync_needed`, `balance_cached`, and `pending_spent_count`; if `sync_needed=true`, run `wallet scan --json` or `wallet balance --json` against the same RPC and capture `blocks_scanned`, final `scan_height`, `balance`, and `owned_count`. |
| `operator inbox-status` reports `inbox_complete=false` | The replica has only some chunks, or it has not caught up to the upload block yet | Wait for `mfn-cli --rpc <REPLICA_RPC> tip` to match the hub, rerun `operator push-chunks <COMMIT_HASH_HEX> <REPLICA_P2P>`, or use HTTP `operator backfill <COMMIT_HASH_HEX> <PEER_HTTP>` from a peer with a complete artifact. Add `--json` to capture `present_indices` and `missing_indices` in support tickets. |
| `operator assemble-inbox` says chunks are missing | The node's `chunk-inbox/<commit>/<index>.bin` set is incomplete | Run `operator inbox-status --json` to see `missing_indices`, push chunks again from the original uploader, then retry `operator assemble-inbox ... replace --json` only after `inbox_complete=true`; the JSON output records the rebuilt `artifact_dir` and `payload_bytes`. |
| `operator prove` fails with `data_root` or size mismatch | The local payload/artifact is not the bytes anchored on-chain | Rebuild the artifact from a known-good peer with `operator backfill --json` or `operator assemble-inbox --json`, then run `uploads retrieve <COMMIT_HASH_HEX> ./restored.bin` and compare the restored file hash against the uploader before proving. |
| `operator prove` submits but `uploads list` still shows the old `last_proven_height` | The proof is queued but not mined yet, or the producer cannot read the challenged chunk | Check `mfn-cli --rpc <RPC> operator pool --json`; make sure the producer's data dir has the chunk inbox or artifact bytes, then mine/wait for the next block. Use `operator challenge --json` and `uploads list --json` before and after mining to capture the challenge target and indexed `last_proven_height` row without parsing key/value output. |
| RPC returns an authorization error for upload/prove/pool commands | The node was started with `--rpc-api-key` / `MFND_RPC_API_KEY` and the client did not send the same key | Retry with `mfn-cli --rpc <RPC> --rpc-api-key <KEY> ...` or set `MFN_RPC_API_KEY=<KEY>` in the operator shell. |
| Health check reports divergent or stalled tips | Nodes are on different genesis files, cannot reach P2P peers, or the producer is not sealing slots | Confirm every node prints the same `mfnd_chain_genesis_id`, check `--p2p-dial` / manifest seeds and firewalls, then run `health-check` with `MFN_HEALTH_STALL_SAMPLES=2` and an interval longer than the slot duration. |

### CI reference (permanence)

| Test | What it proves |
|------|----------------|
| `mfn-cli` `chunk_p2p_smoke` | push → inbox → assemble → prove (single node) |
| `mfn-cli` `chunk_p2p_two_node_smoke` | hub mines, replica sync + push, matching payload |
| `mfn-cli` `chunk_p2p_three_node_smoke` | hub → two replicas via multi-peer `push-chunks` |
| `mfn-storage-operator` `chunk_http_smoke` | HTTP chunk serve matches artifact |

```bash
cargo test -p mfn-cli --release --test chunk_p2p_smoke --test chunk_p2p_two_node_smoke --test chunk_p2p_three_node_smoke
cargo test -p mfn-storage-operator --release --test chunk_http_smoke
```
