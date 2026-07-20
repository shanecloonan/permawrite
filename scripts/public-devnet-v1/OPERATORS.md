# Public devnet v1 — operator invite list (M2.4.3 / M2.4.4)

Join the **public-devnet-v1** network only if your node's `genesis_id` matches the manifest:

`454fa5d4a9bd6f59e35cf9ea7e68c096c9a271a92b2ec5931184e7f34a42a005`

Use genesis file: [`mfn-node/testdata/public_devnet_v1.json`](../../mfn-node/testdata/public_devnet_v1.json). It includes deterministic synthetic test decoys so fresh devnet wallets can build initial privacy rings before organic transaction volume exists. The spec sets `endowment.require_endowment_range_proof: 1`, so storage uploads must carry a verified surplus Bulletproof (`MFER` in `tx.extra` MFEX v3); reference `mfn-cli wallet upload` attaches this automatically without revealing over-payment.

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
3. Boot peers: either rely on manifest `seed_nodes` (auto-merged from `public_devnet_v1.manifest.json` beside the genesis file — **M2.4.4**), and/or pass one or more `--p2p-dial host:port` flags (repeatable). `mfnd` trims, dedupes, and validates every boot peer as `HOST:PORT` before dialing; use `[IPv6]:PORT` for IPv6 literals. If your own resolved P2P listen address appears in CLI dials, manifest seeds, or `peers.json`, `mfnd` logs `mfnd_p2p_self_dial_skip peer=...` and skips that outbound dial. The merged CLI/manifest boot list is capped at 64 peers with explicit `--p2p-dial` entries kept first; if the cap drops extras, stdout logs `mfnd_p2p_boot_dials_capped configured=... retained=... dropped=... cap=64`. Stale or firewalled public seeds are bounded per resolved TCP address by a 5s connect timeout before the dial logs `mfnd_p2p_dial_abort` / `mfnd_p2p_catchup_dial_abort` and peer scoring decides whether to quarantine later retries.
4. Verify `mfnd_chain_genesis_id=` on stdout matches the manifest; when boot peers are configured, `mfnd_p2p_boot_dials=` lists the merged dial set.
5. Run `health-check.sh` / `health-check.ps1` — hub, voters, and the bundled observer must share the same `tip_height` and `tip_id` (**M2.4.6** / **M2.4.9**), all expected role RPC endpoints must be discoverable, and each checked node must have at least `MFN_HEALTH_MIN_P2P_SESSIONS` live P2P sessions (default `1`). For a liveness window, set `MFN_HEALTH_STALL_SAMPLES=2` and `MFN_HEALTH_STALL_INTERVAL_SECONDS` longer than the slot duration; the check fails if the shared tip does not advance by `MFN_HEALTH_MIN_HEIGHT_DELTA` blocks. Set `MFN_HEALTH_REQUIRE_ALL_ROLES=0` only for intentional partial-mesh diagnostics.

## Roles

| Role | Flags | Notes |
|------|--------|--------|
| Hub | `serve --produce` | Usually validator index `0`; scans up to 128 slots per tick when VRF-ineligible. |
| Voter | `serve --committee-vote` | Indices `1` and `2`; vote on hub proposals and run periodic catch-up dials. |
| Observer | `serve` | No validator env; sync + RPC only. |

## Bootstrap scripts

### P32 role-separated VPS templates (multi-host testnet)

For **production-style** separation (validators, observer, operator, wallet on different hosts), copy the role env templates in this directory:

| Template | Role |
|---|---|
| [`vps-role-validator.env.example`](vps-role-validator.env.example) | Dedicated validator (`--produce` or `--committee-vote`); loopback RPC only |
| [`vps-role-observer.env.example`](vps-role-observer.env.example) | Community observer; public RPC + P2P |
| [`vps-role-operator.env.example`](vps-role-operator.env.example) | Storage operator; RPC-only path to observer |
| [`vps-role-wallet.env.example`](vps-role-wallet.env.example) | Wallet client; never dial your own validator RPC |

See [`docs/REFERENCE_TOPOLOGY.md`](../../docs/REFERENCE_TOPOLOGY.md) for layout diagrams and anti-patterns. Single-box internet launch (all roles on one VPS) uses [`vps-bind.env.example`](vps-bind.env.example) instead — loopback RPC + public P2P per process.

### Local mesh scripts

From repo root (after `cargo build -p mfn-node --release --bin mfnd`):

| Platform | Command |
|----------|---------|
| Linux/macOS (local loopback) | `bash scripts/public-devnet-v1/start-all.sh` |
| Linux VPS (internet P2P) | `bash scripts/public-devnet-v1/vps-start-all.sh` — see [`docs/VPS_SINGLE_BOX_LAUNCH.md`](../../docs/VPS_SINGLE_BOX_LAUNCH.md) |
| VPS provision (zero → soak) | [`docs/VPS_PROVISION.md`](../../docs/VPS_PROVISION.md) — provider-agnostic TL-5 prerequisite |
| TL-5 provision rehearsal (CI) | `bash scripts/public-devnet-v1/vps-provision-rehearsal-smoke.sh --plan-only` |
| P32 role templates rehearsal (CI) | `bash scripts/public-devnet-v1/vps-role-templates-rehearsal-smoke.sh --plan-only` |
| TL-5 preflight rehearsal (CI) | `bash scripts/public-devnet-v1/vps-preflight-rehearsal-smoke.sh --plan-only` |
| Linux VPS TL-5 soak | `bash scripts/public-devnet-v1/vps-internet-soak.sh` — after `vps-preflight.sh` |
| TL-5 soak rehearsal (CI) | `bash scripts/public-devnet-v1/vps-internet-soak-rehearsal-smoke.sh --plan-only` |
| TL-5 soak evidence assert | `bash scripts/public-devnet-v1/assert-vps-internet-soak-evidence.sh scripts/public-devnet-v1/evidence/vps-internet-soak-linux-*.txt` — before commit |
| TL-5 soak evidence rehearsal (CI) | `bash scripts/public-devnet-v1/vps-internet-soak-evidence-rehearsal-smoke.sh --plan-only` |
| Linux VPS TL-6 rehearsal | `bash scripts/public-devnet-v1/vps-participant-rehearsal.sh` — after TL-5 soak PASS |
| TL-6 rehearsal gate (CI) | `bash scripts/public-devnet-v1/vps-participant-rehearsal-rehearsal-smoke.sh --plan-only` |
| TL-6 rehearsal evidence assert | `bash scripts/public-devnet-v1/assert-vps-participant-rehearsal-evidence.sh scripts/public-devnet-v1/evidence/vps-participant-rehearsal-*.txt` — before commit |
| B-15 JOIN_TESTNET rehearsal evidence assert | `bash scripts/public-devnet-v1/assert-join-testnet-rehearsal-evidence.sh scripts/public-devnet-v1/evidence/join-testnet-rehearsal-*.txt` — before commit |
| B-15 JOIN_TESTNET rehearsal (live) | `bash scripts/public-devnet-v1/join-testnet-rehearsal-smoke.sh --no-build --archive-evidence` on synced observer RPC (VPS: `127.0.0.1:18734`) |
| B-15 JOIN_TESTNET rehearsal (CI) | `bash scripts/public-devnet-v1/join-testnet-rehearsal-evidence-rehearsal-smoke.sh --plan-only` |
| TL-6 rehearsal evidence rehearsal (CI) | `bash scripts/public-devnet-v1/vps-participant-rehearsal-evidence-rehearsal-smoke.sh --plan-only` |
| TL-7 ceremony rehearsal (CI) | `bash scripts/public-devnet-v1/vps-launch-ceremony-rehearsal-smoke.sh --plan-only` |
| TL-7 Path B header_version (CI) | `bash scripts/public-devnet-v1/genesis-header-version-rehearsal-smoke.sh --plan-only` |
| VPS ceremony (status/plan) | `bash scripts/public-devnet-v1/vps-launch-ceremony.sh` |
| TL-8 publish seeds | `bash scripts/public-devnet-v1/publish-seed-nodes.sh` — after TL-7 sign-off |
| Public observer read-RPC proxy | `http://5.161.201.73:8787/rpc` — systemd `observer-rpc-proxy.service` → observer `127.0.0.1:18734` (public-safe methods only; status pages / lite explorers). Tall-tip `get_light_snapshot` / `get_block_headers` use `PROXY_HEAVY_RPC_TIMEOUT_MS` (default 180s; B-52/F54) |
| Public testnet frontend (B-55) | `http://5.161.201.73:3000/testnet` — systemd `testnet-frontend.service`; deploy with `bash scripts/public-devnet-v1/vps-start-testnet-frontend.sh --apply` (UFW `:3000`; never restarts mfnd/faucet) |
| Public testnet faucet HTTP | `node scripts/public-devnet-v1/faucet-http.mjs` on `:8788` — async `POST /faucet` + `/faucet/job`; **F7 dual-send** (two transfers + tip-wait/rescan between sends); IP cooldown uses **TCP peer IP only** (R-4 — ignore spoofed `X-Forwarded-For`); loopback peer skips cooldown (R-3); clients retry on `503 busy`; **B-47:** `/health` never races claim `mfn-cli` (cached status while busy + wallet lock when idle); CLI retries on EAGAIN/refused |
| Faucet catch-up (VPS) | `bash scripts/public-devnet-v1/faucet-catchup.sh` — background `wallet light-scan` for operator faucet |
| Faucet UTXO consolidate (VPS) | `bash scripts/public-devnet-v1/faucet-consolidate.sh --plan-only` then real run weekly when `owned_count` grows |
| VPS mfnd binary roll (hub+voters) | `bash scripts/public-devnet-v1/vps-roll-mfnd.sh --apply` — **B-49/B-60**; rebuild `mfnd`, soften dial/`Wants=`, restart voters then hub; **never** `faucet-http`; fail-closed preflight: CI GREEN + faucet idle (B-45+B-48+B-51) |
| VPS faucet deploy | `bash scripts/public-devnet-v1/vps-update-faucet.sh` — pull, rebuild `mfn-cli`, restart faucet HTTP (**do not** run during B-15 JOIN evidence capture — restarts drop in-memory jobs; see AGENTS §6) |
| B-15 outside-in JOIN | `bash scripts/public-devnet-v1/run-join-testnet-vps-once.sh` — archive `join-testnet-rehearsal-linux-*.txt`; **no parallel** `join-testnet-rehearsal*` while evidence is in flight |
| TL-8 publish seeds rehearsal (CI) | `bash scripts/public-devnet-v1/publish-seed-nodes-rehearsal-smoke.sh --plan-only` |
| TL-8 invite packet rehearsal (CI) | `bash scripts/public-devnet-v1/testnet-invite-rehearsal-smoke.sh --plan-only` — validates [`TESTNET_INVITE.md`](../../docs/TESTNET_INVITE.md) |
| Tall-tip wallet bootstrap (B-50) | `bash scripts/public-devnet-v1/bootstrap-wallet-from-checkpoint-log.sh --apply --wallet PATH` — pin via `get_light_snapshot` then light-scan; `--checkpoint-log` alone does **not** skip genesis |
| Block-log health (B-53 / F62) | `bash scripts/public-devnet-v1/assert-vps-block-log-health.sh --rpc 127.0.0.1:18734 --data-dir .permawrite-devnet-v1/observer` — tip + `get_block(tip)` (+ optional `chain.blocks` size) |
| Faucet `/health` (B-53) | Non-blocking: never waits on wallet lock; may set `wallet_status_cached` / `wallet_lock_held` during keepalive |
| Faucet keepalive (B-56) | Tip-first: poll tip without wallet lock when near tip; full sync only when behind > `SYNC_BEHIND` |
| TL-8 publish checkpoint log | `bash scripts/public-devnet-v1/publish-checkpoint-log.sh` — after TL-7; commits `public_devnet_v1.checkpoints.jsonl`; **B-22:** merges manifest `seed_nodes` into `anchor_peers` (drops loopback when public seeds exist) |
| TL-8 publish checkpoint log rehearsal (CI) | `bash scripts/public-devnet-v1/publish-checkpoint-log-rehearsal-smoke.sh --plan-only` |
| TL-8 invite packet | [`docs/TESTNET_INVITE.md`](../../docs/TESTNET_INVITE.md) — share after `publish-seed-nodes --apply` + checkpoint log |
| Launch posture | `bash scripts/public-devnet-v1/launch-status.sh` / `launch-status.ps1 -Json` — TL phase + checkpoint log tracking (`launch-status.v7`) |
| VPS preflight checklist | `bash scripts/public-devnet-v1/vps-execution-checklist.sh` — before TL-5/TL-6 (`v2` schema; use `--strict` when CI must be green) |
| VPS checklist rehearsal | `bash scripts/public-devnet-v1/vps-execution-checklist-rehearsal-smoke.sh --plan-only` — ci-check gate |
| Treasury telemetry (F6) | `bash scripts/public-devnet-v1/treasury-telemetry-watch.sh --rpc HOST:PORT` — FEES.md §5 revisit triggers |
| P32 / PM23 rehearsal | `bash scripts/public-devnet-v1/pm23-operator-manifest-rehearsal-smoke.sh --plan-only` — role env separation gate |
| TL-9 go/no-go | `bash scripts/public-devnet-v1/launch-go-no-go.sh` — before outside invites |
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

The preflight scripts do not install tools or stop nodes. They report missing `node` for `CODEBASE_STATS.md`, missing helper runtimes such as `bash` / `nc` / `python3`, missing `wasm-pack`, `wasm-opt` (Binaryen), and `cargo-audit` for the local CI mirror, missing `dlltool.exe` on Windows release-test setups, missing release binaries, absent `devnet-ports.env`, and running `mfnd` PIDs that should be stopped before rebuilding release binaries in place.

### Toolchain Recovery

Use this when `preflight` or `scripts/ci-check` reports missing tools:

```powershell
# Windows: Rust-side CI helpers.
cargo install wasm-pack --locked
cargo install cargo-audit --locked

# Windows: Binaryen (wasm-opt) for wasm-pack release builds.
# Download the latest x86_64-windows Binaryen release, extract, and add its bin/
# directory to PATH. Example layout after manual install:
#   $env:PATH = "$env:USERPROFILE\.local\bin\binaryen-version_120\bin;" + $env:PATH
# Verify: wasm-opt --version

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

# Linux/macOS: Binaryen (wasm-opt) for wasm-pack release builds.
# Linux (Debian/Ubuntu): sudo apt-get install -y binaryen
# macOS: brew install binaryen
# Verify: wasm-opt --version

# Linux examples.
sudo apt-get update
sudo apt-get install -y nodejs npm netcat-openbsd python3 binaryen

# macOS examples.
brew install node netcat python binaryen
```

After installing tools, open a fresh shell so PATH changes are visible, rerun `preflight` in strict mode, and only then rerun `node scripts/codebase-stats.mjs` and the local CI mirror.

## Launch go/no-go checklist

Use this checklist before advertising a public testnet endpoint, publishing seed nodes, or asking outside operators to join. A single unchecked critical item is a no-go. This project is pre-audit; passing this checklist means "acceptable experimental public-testnet risk," not production safety. Review the [public testnet threat model](../../docs/PUBLIC_DEVNET_THREAT_MODEL.md) before signing off.

### Critical no-go items

- [ ] `git pull --ff-only origin main` succeeds on the release branch, or the exact release commit is intentionally pinned and reviewed.
- [ ] `CODEBASE_STATS.md` was regenerated with `node scripts/codebase-stats.mjs` after the final code/doc changes.
- [ ] The [release-candidate artifact inventory](../../docs/RELEASE_ARTIFACT_INVENTORY_TEMPLATE.md) was copied, filled out, and attached to launch notes with checksums for binaries, genesis, manifest, evidence, support bundle, and sign-off output.
- [ ] Release-candidate evidence was generated and attached to the launch notes: `release-evidence.ps1` or `release-evidence.sh`.
- [ ] The local CI mirror passed on the release host or equivalent clean machine: `scripts/ci-check.ps1` on Windows or `scripts/ci-check.sh` on Linux/macOS.
- [ ] Ignored/nightly smoke coverage passed for public-devnet release candidates: `scripts/ci-ignored.ps1` or `scripts/ci-ignored.sh`.
- [ ] GitHub CI is green for the exact commit that will be published, verified with `release-ci-watch.ps1` or `release-ci-watch.sh`.
- [ ] `SECURITY.md` still states the software is pre-audit and does not imply production-grade security.
- [ ] The public-devnet threat model was reviewed, and every accepted residual risk has a named operator owner (complete [§ Residual-risk owners and halt authority](#residual-risk-owners-and-halt-authority-b-30) before TL-9).
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
- [ ] **B-30:** Residual-risk owner matrix in [`PUBLIC_DEVNET_THREAT_MODEL.md`](../../docs/PUBLIC_DEVNET_THREAT_MODEL.md) reviewed; human owner cells filled below; halt authority named.


### B-41 — public P2P seed reachability (socat forwards)

**Do not** bind `mfnd` itself on `0.0.0.0:1900x` on the current Hetzner image — startup hung before RPC bind (2026-07-20). Working posture: loopback `mfnd` on `:19101-19104` + `socat` public forwards `0.0.0.0:1900x -> 127.0.0.1:1910x` (`repair-vps-p2p-binds.sh --apply`). Do not socat the same port mfnd holds on loopback. RPC stays `127.0.0.1`.

### Tip stall after P2P remap (B-46)

If tip freezes after mfnd remaps/restarts: (1) ensure hub has quoted `Environment="MFN_P2P_DIAL_EXTRA=127.0.0.1:19102 127.0.0.1:19103 127.0.0.1:19104"`; (2) `bash scripts/public-devnet-v1/vps-soften-mfnd-requires.sh` (Requires→Wants); (3) start voters, then **restart hub only** so boot dials succeed (avoid 300s quarantine). Do not restart `faucet-http` during B-15.

### B-22 — Path A checkpoint republish

`bootstrap-path-a-checkpoint-signer.sh --apply` mints `~/.mfn/checkpoint-signer.env` (never commit) and appends a near-tip JSONL entry. Commit `public_devnet_v1.checkpoints.jsonl` only.

### Residual-risk owners and halt authority (**B-30**)

Fill every blank before circulating outside invites (TL-9). Standing lane owners are defined in [`AGENTS.md`](../../AGENTS.md); humans below are the named people who can act without waiting for an agent session.

| Role | Name / handle | Contact path | Authority |
| --- | --- | --- | --- |
| **Halt authority** (may publish pause / stop invites) | ________________ | ________________ | Unilateral halt on any critical no-go condition |
| **Rollback authority** (may direct binary/data-dir rollback) | ________________ | ________________ | Coordinated rollback per § Backups below; not solo if consensus/schema changed |
| **Genesis rotation publisher** (may announce new `genesis_id`) | ________________ | ________________ | Only after halt; Path A toy-key rotation or Path B ceremony |
| **Launch-day log watcher** | ________________ | ________________ | Watches `mfnd` + faucet + observer proxy on VPS |
| **Launch-day CI watcher** | ________________ | ________________ | Watches GitHub CI/Nightly on invite head |
| **Privacy / permanence veto** | ________________ | ________________ | May block invites that would weaken ring, endowment, or SPoRA guarantees |

**Halt conditions (must stop invites / public advertising immediately):**

1. Divergent tips across hub/voters/observer that health-check cannot clear within one soak window.
2. Repeated invalid block or gossip errors on the public mesh.
3. Leaked validator VRF/BLS seeds, faucet wallet seeds, or RPC API keys.
4. Unexpected `rpc.public_bind=true` or unauthenticated wallet-write exposure on the VPS.
5. Reproducible storage data-root mismatch or failed retrieve/prove after a passing soak.
6. Nightly participant/observer RED on the exact invite commit without a landed fix-forward.

**Incident notes location:** `scripts/public-devnet-v1/evidence/incidents/` (create dated `YYYYMMDD-<slug>.md`; never paste seeds or API keys).

**Sign-off flags** (for `release-signoff-manifest`): `--threat-model-reviewed` + `--residual-risks-have-owners` + `--halt-rollback-authority-agreed` only after this section is filled.

Health check: `health-check.sh` or `health-check.ps1` in the same directory (**M2.4.6** / **M2.4.9** — exits non-zero if hub, voters, or observer diverge, any expected role RPC endpoint is missing while `MFN_HEALTH_REQUIRE_ALL_ROLES` is enabled (default `1`), `genesis_id` ≠ public devnet manifest, live P2P sessions are below `MFN_HEALTH_MIN_P2P_SESSIONS` (default `1`), or an opt-in multi-sample liveness window stalls).

Release-candidate evidence:

```bash
# Linux/macOS: write a Markdown evidence record for launch notes.
bash scripts/public-devnet-v1/release-evidence.sh \
  --rpc 127.0.0.1:18731 \
  --run-health-check \
  --operator "name or handle" \
  --output release-evidence.md

# Add --json when archiving evidence for CI dashboards or automation.
bash scripts/public-devnet-v1/release-evidence.sh --json --output release-evidence.json
```

```powershell
# Windows: write a Markdown evidence record for launch notes.
powershell -File scripts/public-devnet-v1/release-evidence.ps1 `
  -Rpc 127.0.0.1:18731 `
  -RunHealthCheck `
  -Operator "name or handle" `
  -OutputPath release-evidence.md

# Add -Json when archiving evidence for CI dashboards or automation.
powershell -File scripts/public-devnet-v1/release-evidence.ps1 -Json -OutputPath release-evidence.json
```

The evidence generator records the current branch, commit, dirty-tree state, `CODEBASE_STATS.md` timestamp, GitHub CI status when available, expected public-devnet `genesis_id`, optional health-check output, optional RPC status (`rpc.public_bind`, auth, in-flight limits, tip, P2P sessions), and sign-off fields. Markdown is for launch notes; JSON is for archiving, CI dashboards, or automation. JSON output uses the versioned [`release-evidence.v1` schema](../../docs/release-evidence-v1.schema.json); see the [sample artifact](../../docs/release-evidence-v1.sample.json) for dashboard ingestion. Unknown evidence remains `unknown` or unchecked; do not treat generated output as a pass unless every launch blocker is manually reviewed.

Validate archived evidence JSON against the published schema:

```powershell
powershell -File scripts/public-devnet-v1/release-json-schema-validate.ps1 `
  -Schema .\docs\release-evidence-v1.schema.json `
  -Json .\release-evidence.json
```

```bash
bash scripts/public-devnet-v1/release-json-schema-validate.sh \
  --schema ./docs/release-evidence-v1.schema.json \
  --json ./release-evidence.json
```

The schema validator is dependency-free and intentionally scoped to the schema features used by Permawrite release artifacts: required fields, `additionalProperties`, `type`, `const`, `enum`, arrays, and local `$ref`. It is not a general-purpose Draft 2020-12 engine. For release-candidate publication, also install the pinned strict validator and run the Draft 2020-12 check:

```powershell
python -m pip install --disable-pip-version-check --require-hashes -r scripts/public-devnet-v1/requirements-release-schema.txt
powershell -File scripts/public-devnet-v1/release-json-schema-draft202012.ps1 `
  -Schema .\docs\release-evidence-v1.schema.json `
  -Json .\release-evidence.json
```

```bash
python3 -m pip install --disable-pip-version-check --require-hashes -r scripts/public-devnet-v1/requirements-release-schema.txt
bash scripts/public-devnet-v1/release-json-schema-draft202012.sh \
  --schema ./docs/release-evidence-v1.schema.json \
  --json ./release-evidence.json
```

The strict wrapper requires the pinned `jsonschema==4.17.3` dependency and fails closed if a different version is installed. Install with `--require-hashes`; a package hash mismatch is a release-toolchain failure.

### Offline wheelhouse for air-gapped release hosts

Release sign-off hosts without PyPI access should build a local wheelhouse on a connected machine, copy it with the release archive, and install from disk:

```powershell
powershell -File scripts/public-devnet-v1/release-schema-wheelhouse.ps1 `
  -Output .\wheelhouse-release-schema
# Copy wheelhouse-release-schema/ to the air-gapped host, then:
$env:PERMAWRITE_RELEASE_SCHEMA_PYTHON = "python"
powershell -File scripts/public-devnet-v1/release-schema-install-offline.ps1 `
  -Wheelhouse .\wheelhouse-release-schema
powershell -File scripts/public-devnet-v1/release-json-schema-draft202012.ps1 `
  -Schema .\docs\release-evidence-v1.schema.json `
  -Json .\release-evidence.json
```

```bash
bash scripts/public-devnet-v1/release-schema-wheelhouse.sh \
  --output ./wheelhouse-release-schema
# Copy wheelhouse-release-schema/ to the air-gapped host, then:
export PERMAWRITE_RELEASE_SCHEMA_PYTHON=python3
bash scripts/public-devnet-v1/release-schema-install-offline.sh \
  --wheelhouse ./wheelhouse-release-schema
bash scripts/public-devnet-v1/release-json-schema-draft202012.sh \
  --schema ./docs/release-evidence-v1.schema.json \
  --json ./release-evidence.json
```

Re-run `release-schema-wheelhouse` whenever `requirements-release-schema.txt` changes. Archive the wheelhouse directory alongside release binaries and checksum manifests; do not commit wheels to git.

Block release sign-off until GitHub CI is green for the exact commit:

```powershell
powershell -File scripts/public-devnet-v1/release-ci-watch.ps1 `
  -Commit <release_commit_sha> `
  -Wait `
  -TimeoutSeconds 1800
```

```bash
bash scripts/public-devnet-v1/release-ci-watch.sh \
  --commit <release_commit_sha> \
  --wait \
  --timeout-seconds 1800
```

The watcher exits successfully only when the matching `CI` workflow run is `completed` with `conclusion=success`. Missing, queued, in-progress without `--wait`, failed, cancelled, skipped, timed-out, unknown runs, GitHub API errors, and unauthenticated API rate limits are no-go results. It uses authenticated `gh` when available, otherwise falls back to GitHub's Actions API with `GH_TOKEN` / `GITHUB_TOKEN` when set, then to the public unauthenticated API for public repositories. For release sign-off, prefer `gh auth login` or a token environment variable so long polling is not dependent on the low unauthenticated public API limit.

When collecting launch support diagnostics, pass the generated JSON evidence to `support-bundle` so the bundle validates the `release-evidence.v1` contract, copies the evidence as `release-evidence.json`, and records a validation summary in `manifest.json`.

After CI, evidence, inventory, and archive validation pass, write the machine-readable release sign-off manifest:

```powershell
powershell -File scripts/public-devnet-v1/release-signoff-manifest.ps1 `
  -ReleaseEvidenceJson .\release-evidence.json `
  -ArchiveDir .\release-staging\permawrite-public-devnet-<rc>-<commit> `
  -Inventory .\release-artifact-inventory.md `
  -Decision go `
  -Operator "name or handle" `
  -Reviewer "independent reviewer" `
  -ThreatModelReviewed `
  -ResidualRisksHaveOwners `
  -RpcExposureApproved `
  -BackupsRestoreRehearsed `
  -HaltRollbackAuthorityAgreed `
  -OutputPath .\release-signoff-manifest.json
```

```bash
bash scripts/public-devnet-v1/release-signoff-manifest.sh \
  --release-evidence-json ./release-evidence.json \
  --archive-dir ./release-staging/permawrite-public-devnet-<rc>-<commit> \
  --inventory ./release-artifact-inventory.md \
  --decision go \
  --operator "name or handle" \
  --reviewer "independent reviewer" \
  --threat-model-reviewed \
  --residual-risks-have-owners \
  --rpc-exposure-approved \
  --backups-restore-rehearsed \
  --halt-rollback-authority-agreed \
  --output ./release-signoff-manifest.json
```

The manifest uses `schema_version=release-signoff-manifest.v1`; the schema is [`release-signoff-manifest-v1.schema.json`](../../docs/release-signoff-manifest-v1.schema.json), with a sample artifact in [`release-signoff-manifest-v1.sample.json`](../../docs/release-signoff-manifest-v1.sample.json). The helper refuses `go` when exact-commit CI is not green, release evidence is malformed or for a different commit, archive validation fails, the inventory fails validation, or required human approvals are missing. Use `no-go` to archive a failed release review without bypassing any gate.

Validate the sign-off manifest before attaching it to launch notes or publishing the archive:

```powershell
powershell -File scripts/public-devnet-v1/release-json-schema-validate.ps1 `
  -Schema .\docs\release-signoff-manifest-v1.schema.json `
  -Json .\release-signoff-manifest.json

powershell -File scripts/public-devnet-v1/release-signoff-manifest-validate.ps1 `
  -Manifest .\release-signoff-manifest.json
```

```bash
bash scripts/public-devnet-v1/release-json-schema-validate.sh \
  --schema ./docs/release-signoff-manifest-v1.schema.json \
  --json ./release-signoff-manifest.json

bash scripts/public-devnet-v1/release-signoff-manifest-validate.sh \
  --manifest ./release-signoff-manifest.json
```

The validator is dependency-free and mirrors the published schema's required fields. For `decision=go`, it also verifies green CI, passing archive and inventory gates, no manifest issues, and every required approval flag.

After all individual gates pass, generate a final audit packet. This is the operator-facing summary to attach to launch notes before publishing endpoints:

```powershell
powershell -File scripts/public-devnet-v1/release-audit-packet.ps1 `
  -ReleaseEvidenceJson .\release-evidence.json `
  -SignoffManifest .\release-signoff-manifest.json `
  -ArchiveDir .\release-staging\permawrite-public-devnet-<rc>-<commit> `
  -Inventory .\release-artifact-inventory.md `
  -Commit <release_commit_sha> `
  -ParticipantEvidenceDir .\participant-rehearsal-smoke\evidence `
  -Json `
  -OutputPath .\release-audit-packet.json
```

```bash
bash scripts/public-devnet-v1/release-audit-packet.sh \
  --release-evidence-json ./release-evidence.json \
  --signoff-manifest ./release-signoff-manifest.json \
  --archive-dir ./release-staging/permawrite-public-devnet-<rc>-<commit> \
  --inventory ./release-artifact-inventory.md \
  --commit <release_commit_sha> \
  --participant-evidence-dir ./participant-rehearsal-smoke/evidence \
  --json \
  --output ./release-audit-packet.json
```

When evidence is not co-located, pass `-ParticipantRehearsalLog` / `--participant-rehearsal-log` and `-ParticipantSupportBundle` / `--participant-support-bundle` explicitly instead of `-ParticipantEvidenceDir` / `--participant-evidence-dir`.

```powershell
powershell -File scripts/public-devnet-v1/release-audit-packet.ps1 `
  -ReleaseEvidenceJson .\release-evidence.json `
  -SignoffManifest .\release-signoff-manifest.json `
  -ArchiveDir .\release-staging\permawrite-public-devnet-<rc>-<commit> `
  -Inventory .\release-artifact-inventory.md `
  -Commit <release_commit_sha> `
  -ParticipantRehearsalLog .\participant-rehearsal.log `
  -ParticipantSupportBundle .\participant-support-bundle `
  -Json `
  -OutputPath .\release-audit-packet.json
```

```bash
bash scripts/public-devnet-v1/release-audit-packet.sh \
  --release-evidence-json ./release-evidence.json \
  --signoff-manifest ./release-signoff-manifest.json \
  --archive-dir ./release-staging/permawrite-public-devnet-<rc>-<commit> \
  --inventory ./release-artifact-inventory.md \
  --commit <release_commit_sha> \
  --participant-rehearsal-log ./participant-rehearsal.log \
  --participant-support-bundle ./participant-support-bundle \
  --json \
  --output ./release-audit-packet.json
```

The audit packet uses `schema_version=release-audit-packet.v1`; the schema is [`release-audit-packet-v1.schema.json`](../../docs/release-audit-packet-v1.schema.json), with a sample artifact in [`release-audit-packet-v1.sample.json`](../../docs/release-audit-packet-v1.sample.json). The schema includes optional participant evidence paths emitted as `participant_rehearsal_log`, `participant_support_bundle`, and `participant_evidence_dir` when those inputs are supplied. After a local smoke run, `-ParticipantEvidenceDir ./participant-rehearsal-smoke/evidence` resolves the default co-located `participant-rehearsal.log` and `support-bundle/` staged by the smoke wrapper. The packet also runs `release-participant-smoke-policy-check` from the release tree so sign-off fails closed if default CI promotes real-run participant rehearsal smokes outside nightly/`ci-ignored`. A redacted live-rehearsal sample lives in [`fixtures/participant-rehearsal-evidence-v1/`](fixtures/participant-rehearsal-evidence-v1/).

Quick RC dry-run with archived M2.4.70 soak evidence and the participant-rehearsal fixture (decision=go when all gates pass):

```powershell
powershell -File scripts/public-devnet-v1/release-rc-audit-dry-run.ps1
```

After green GitHub CI on `main`, refresh archived release evidence for the current HEAD (Agent 2 handoff). Fails closed unless CI is green unless `-AllowPendingCi` / `--allow-pending-ci`. Validates JSON against `docs/release-evidence-v1.schema.json` before accepting the refresh.

```powershell
powershell -File scripts/public-devnet-v1/release-evidence-refresh-for-head.ps1 `
  -Notes "M2.5.12-14 evidence pipeline; Nightly #55 pending" `
  -RunRcAuditDryRun
```

```bash
bash scripts/public-devnet-v1/release-evidence-refresh-for-head.sh \
  --notes "M2.5.12-14 evidence pipeline; Nightly #55 pending" \
  --run-rc-audit-dry-run
```

Dispatch **CI Queue Cleanup**, **Nightly**, and **Linux Soak Audit** on GitHub Actions (requires `gh auth login` or `GH_TOKEN`/`GITHUB_TOKEN`):

```powershell
powershell -File scripts/public-devnet-v1/dispatch-rc-workflows.ps1 -All
```

```bash
bash scripts/public-devnet-v1/dispatch-rc-workflows.sh --all
```

`-All` / `--all` also triggers **CI Queue Cleanup** (`ci-queue-cleanup.yml`), which cancels stale queued/in-progress CI runs on `main` so the latest commit is not blocked behind a backlog.

Participant rehearsal smoke can archive UTF-8 evidence on PASS:

```powershell
powershell -File scripts/public-devnet-v1/participant-rehearsal-smoke.ps1 -WithObserver -MinHubHeight 5 -ArchiveEvidence
```

Output: `scripts/public-devnet-v1/evidence/rc-audit-dry-run-<commit>-<timestamp>.json`.

Validate the generated packet before publishing launch notes:

```powershell
powershell -File scripts/public-devnet-v1/release-json-schema-validate.ps1 `
  -Schema .\docs\release-audit-packet-v1.schema.json `
  -Json .\release-audit-packet.json

powershell -File scripts/public-devnet-v1/release-json-schema-draft202012.ps1 `
  -Schema .\docs\release-audit-packet-v1.schema.json `
  -Json .\release-audit-packet.json
```

```bash
bash scripts/public-devnet-v1/release-json-schema-validate.sh \
  --schema ./docs/release-audit-packet-v1.schema.json \
  --json ./release-audit-packet.json

bash scripts/public-devnet-v1/release-json-schema-draft202012.sh \
  --schema ./docs/release-audit-packet-v1.schema.json \
  --json ./release-audit-packet.json
```

The audit packet returns `decision=no-go` unless release evidence schema validation, sign-off manifest schema and gate validation, archive validation, artifact inventory validation, exact-commit CI, and `CODEBASE_STATS.md` presence all pass. If participant rehearsal evidence is supplied, the packet also verifies that the evidence log has a final `participant-rehearsal: PASS ... support_bundle=...` line, the restored SHA-256 is 64 hex characters, the PASS line's `support_bundle` reference identifies the provided bundle directory, the support bundle has `manifest.json`, the manifest is `read_only=true`, the manifest commitment matches the PASS line, and the bundle contains the core `node-status`, `uploads-list`, `operator-pool`, and `operator-challenge` captures. Use `-StrictStatsFreshness` / `--strict-stats-freshness` only from a clean release tree, because untracked private files can legitimately change dry-run stats.

### Release sign-off bundle review

Before advertising public endpoints, one reviewer who is not the release operator should inspect the final launch notes plus support bundle. This review is a human gate; schema validation only proves the files are shaped correctly, not that the network is safe.

Start by filling out the [release-candidate artifact inventory](../../docs/RELEASE_ARTIFACT_INVENTORY_TEMPLATE.md). The inventory must name every binary, genesis/manifest file, evidence file, support bundle, sign-off output, checksum, and reviewer before this checklist can be treated as complete.

Publish artifacts using the archive layout in that template so binaries, genesis/manifest, evidence, support bundles, docs snapshots, and checksums live together under one immutable release-candidate directory. Do not include secrets or private operator files in the archive.

Dry-run the archive layout before publication:

```powershell
powershell -File scripts/public-devnet-v1/release-archive-dry-run.ps1 `
  -PlanOnly `
  -ReleaseEvidenceMarkdown .\release-evidence.md `
  -ReleaseEvidenceJson .\release-evidence.json `
  -SignoffManifest .\release-signoff-manifest.json `
  -AuditPacket .\release-audit-packet.json `
  -Inventory .\release-artifact-inventory.md `
  -IncludeReleaseSchemaWheelhouse
```

```bash
bash scripts/public-devnet-v1/release-archive-dry-run.sh \
  --plan-only \
  --release-evidence-md ./release-evidence.md \
  --release-evidence-json ./release-evidence.json \
  --signoff-manifest ./release-signoff-manifest.json \
  --audit-packet ./release-audit-packet.json \
  --inventory ./release-artifact-inventory.md \
  --include-release-schema-wheelhouse
```

The archive dry-run helper stages the canonical public genesis/manifest, docs snapshots, release-evidence schema/sample, participant smoke CI policy helpers under `toolchain/`, optional reviewed evidence, optional reviewed binaries, and checksum files for artifact directories that contain direct files, including nested binary platform directories. Use `-IncludeReleaseSchemaWheelhouse` / `--include-release-schema-wheelhouse` on connected release hosts to also stage `toolchain/requirements-release-schema.txt`, hash-pinned wheel files, and offline strict-validation helpers for air-gapped sign-off. It refuses obvious private file names such as wallet files, private seeds, API keys, credentials, and `peers.json`. If you pass a support-bundle directory, it copies only `manifest.json`; review and compress a redacted support bundle separately before publishing it.

Validate the staged archive before sign-off:

```powershell
powershell -File scripts/public-devnet-v1/release-archive-validate.ps1 `
  -ArchiveDir .\release-staging\permawrite-public-devnet-<rc>-<commit> `
  -RequireReleaseSchemaWheelhouse
```

```bash
bash scripts/public-devnet-v1/release-archive-validate.sh \
  --archive-dir ./release-staging/permawrite-public-devnet-<rc>-<commit> \
  --require-release-schema-wheelhouse
```

The validator checks required public files, verifies staged `checksums.sha256` manifests against the actual bytes, and rejects obvious private file names. Use `-AllowDryRun` / `--allow-dry-run` only for rehearsal archives with template/sample evidence; do not use it for final publication sign-off. When the archive includes `toolchain/wheelhouse-release-schema`, use `-RequireReleaseSchemaWheelhouse` / `--require-release-schema-wheelhouse` so air-gapped strict-validation artifacts are mandatory.

Use `artifact-checksums.ps1` or `artifact-checksums.sh` to generate SHA-256 rows for inventory entries. Run it only on public release artifacts; never hash or publish private keys, wallet seeds, RPC API keys, or private operator files.

Before sign-off, run `artifact-inventory-validate.ps1` or `artifact-inventory-validate.sh` on the filled inventory. The validator fails on missing artifact paths, checksums, reviewers, a missing final decision, or bare `not applicable` entries without a written reason.

Required files:

- [ ] `release-evidence.md` is attached to the launch notes for human review.
- [ ] `release-evidence.json` is archived beside the launch notes and uses `schema_version=release-evidence.v1`.
- [ ] `manifest.json` from `support-bundle` contains `release_evidence.provided=true`, `release_evidence.valid=true`, and the same commit as `release-evidence.json`.
- [ ] `node-status.json`, `uploads-list.json`, and `operator-pool.json` are present in the support bundle and have no unexplained command failures in `manifest.json`.
- [ ] Any wallet/storage support files needed for the launch claim are present, such as `wallet-status.json`, `wallet-backup-info.json`, `uploads-status.json`, `operator-artifacts.json`, `operator-challenge.json`, or `operator-inbox-status.json`.

Required approvals:

- [ ] Release operator confirms the exact commit, `CODEBASE_STATS.md` timestamp, GitHub CI status, ignored/nightly smoke status, and local CI mirror status.
- [ ] Security reviewer confirms `SECURITY.md` and the public-devnet threat model still describe pre-audit experimental risk and every accepted residual risk has an owner.
- [ ] RPC/network reviewer confirms `rpc.public_bind`, `rpc.listen_addr`, firewall/TLS/API-key posture, P2P reachability, and expected `genesis_id`.
- [ ] Storage/permanence reviewer confirms the upload, replication/backfill, retrieval, and SPoRA proof rehearsal evidence.
- [ ] Operations reviewer confirms backups, restore rehearsal, rollback/halt authority, incident notes location, and launch-day watchers.

Any missing required file, unchecked approval, unknown CI/health/RPC field, or dirty working tree must be treated as a no-go unless the reviewer writes down the exception and names an owner before launch.

To print this checklist with paths and detected status from a generated bundle:

```powershell
powershell -File scripts/public-devnet-v1/release-signoff-review.ps1 `
  -BundleDir scripts/public-devnet-v1/support-bundle/<UTC timestamp> `
  -LaunchNotes release-evidence.md
```

```bash
bash scripts/public-devnet-v1/release-signoff-review.sh \
  --bundle-dir scripts/public-devnet-v1/support-bundle/<UTC timestamp> \
  --launch-notes release-evidence.md
```

To rehearse the whole sign-off evidence flow without a live node:

```powershell
powershell -File scripts/public-devnet-v1/release-signoff-dry-run.ps1
```

```bash
bash scripts/public-devnet-v1/release-signoff-dry-run.sh
```

Local soak:

```bash
bash scripts/public-devnet-v1/soak.sh --duration-minutes 60
powershell -File scripts/public-devnet-v1/soak.ps1 -DurationMinutes 60
bash scripts/public-devnet-v1/soak.sh --duration-minutes 60 --restart-observer-once
powershell -File scripts/public-devnet-v1/soak.ps1 -DurationMinutes 60 -RestartObserverOnce
```

For restart/catch-up evidence, add `--restart-observer-once` or `-RestartObserverOnce`; the soak kills the observer once, restarts it against the same data dir and hub P2P endpoint, waits for it to catch up, and emits a `soak: RESTART` line with old/new PIDs, old/new RPCs, and pre/post hub/observer heights.

Production-slot audit (30s blocks, matches default `start-all` when `SLOT_MS` is unset):

```powershell
$env:SLOT_MS = "30000"
powershell -File scripts/public-devnet-v1/soak.ps1 -DurationMinutes 35 -RestartObserverOnce -MinFinalHeight 10 -ArchiveEvidence
```

Linux/bash parity (`soak.sh`):

```bash
SLOT_MS=30000 bash scripts/public-devnet-v1/soak.sh --duration-minutes 35 --restart-observer-once --min-final-height 10 --archive-evidence
```

**GitHub Actions Linux soak audit** (workflow_dispatch, uploads evidence artifact):

1. Open **Actions → Linux Soak Audit → Run workflow** on `main`.
2. Defaults: `SLOT_MS=30000`, 35 minutes, `--min-final-height 10`, observer restart once.
3. The workflow pre-builds **`mfnd` + `mfn-cli`** before `soak.sh` → `start-all.sh --no-build` (`hub_tip_wait` tip polls require `mfn-cli` when `nc` JSON-RPC is empty on GHA).
4. Download artifact `linux-soak-evidence-slot-30000` and archive the transcript under `scripts/public-devnet-v1/evidence/`.

**Auto-dispatch (B-05):** After green **CI** on `main`, when no `soak-restart-linux-30s-slot-*.txt` exists on `main`, CI job `dispatch-linux-soak-rc` triggers **Linux Soak Audit** automatically. On PASS with `max_height >= 10`, the workflow commits the transcript to `main` with `[skip ci]` (does not re-dispatch Nightly/soak).

**Import fallback:** `powershell -File scripts/public-devnet-v1/import-linux-soak-artifact.ps1` or `bash scripts/public-devnet-v1/import-linux-soak-artifact.sh` downloads the latest workflow artifact into `scripts/public-devnet-v1/evidence/` (requires `gh auth login` or `GH_TOKEN`).

**Nightly Linux rehearsal smokes** (06:00 UTC + workflow_dispatch):

- `participant-rehearsal-smoke` — 10s slots, no observer (`MFN_DEVNET_NO_OBSERVER=1`).
- `participant-rehearsal-smoke-observer` — full mesh, `--min-hub-height 5`.

Trigger manually: **Actions → Nightly → Run workflow** on `main` to confirm both jobs green before RC sign-off.

After every green **CI** push to `main`, **RC Validation After CI** automatically dispatches **Nightly** on the exact passing commit (no local `gh` required).

Smoke-slot soak (10s blocks, faster CI-style mesh):

```powershell
$env:SLOT_MS = "10000"
powershell -File scripts/public-devnet-v1/soak.ps1 -DurationMinutes 12 -RestartObserverOnce -ArchiveEvidence
```

Add `-ArchiveEvidence` to write `scripts/public-devnet-v1/evidence/soak-restart-windows-<slot>-<timestamp>.txt` when the soak finishes (PASS or FAIL). Use `-MinFinalHeight 10` on 30s-slot audits so a graceful deadline exit still PASSes when hub height ≥ 10 and at least three health samples succeeded.

While a soak runs it holds `scripts/public-devnet-v1/.soak-active.lock`; `start-all.{ps1,sh}` and `stop-all.{ps1,sh}` refuse to tear down the mesh unless soak bootstrap (`MFN_SOAK_BOOTSTRAP=1`) or `stop-all --force` / `stop-all -Force`.

Before the first health sample, the soak waits for a converged `health-check` pass at `tip_height >= 1` and logs `soak: WARMUP` so `F=1.5` sortition meshes do not fail stall checks while validators are still catching up. On GHA, warmup uses `MFN_HEALTH_MIN_P2P_SESSIONS=0` (because `get_status` may report `p2p.session_count=null`) and may soft-continue when hub tip≥1 and all roles have `mfnd_p2p_dial_ok=` in logs.

The soak starts the local hub + two voters + observer unless `--no-start` / `-NoStart` is supplied, checks recorded PIDs, verifies follower/observer P2P dial logs, and repeatedly runs the multi-sample health check. For release-candidate evidence, archive the final `soak: SUMMARY` line, each `soak: SAMPLE` line, and any `soak: RESTART` line; together they record pass/fail status, elapsed duration, sampled height/tip, genesis id, per-role P2P peer/session counts, and delayed catch-up after observer kill/restart.

If a peer repeatedly fails outbound dials, fan-out, or catch-up, `mfnd` temporarily quarantines that address in memory and logs `mfnd_p2p_peer_quarantine peer=...`. Quarantine skips reconnect/catch-up/fan-out attempts for that process only; a later successful handshake or push clears the penalty, and a restart reloads the persisted `peers.json` normally. Repeated boot-dial connect failures therefore suppress stale public seeds transiently without deleting them; fix reachability or seed inventory if the quarantine repeats. The saved `max_outbound_peers` reconnect cap defaults to 8 and is clamped to 64 even if `peers.json` is hand-edited; quarantined peers are filtered before this cap is counted for saved-peer reconnect, committee catch-up sweeps, and gap-triggered recovery dials. If malformed, empty, or duplicate saved peers are ignored on load, `mfnd` logs `mfnd_peers_load_filtered raw=... kept=... filtered=...`.

When a saved peer is also present in CLI or manifest boot dials, reconnect skips the duplicate and logs `mfnd_p2p_reconnect_skip peer=... reason=boot_dial`; the explicit boot dial remains responsible for that connection attempt.

If saved-peer reconnect reaches the configured cap, `mfnd` logs `mfnd_p2p_reconnect_cap_reached count=... cap=...`. Increase `max_outbound_peers` in `peers.json` only when the host and network can tolerate more simultaneous boot dials.

Committee catch-up uses the same cap during periodic sync pulls and skips the node's own P2P listen address with `mfnd_p2p_self_dial_skip peer=...`. If an interval reaches the cap, `mfnd` logs `mfnd_p2p_catchup_cap_reached count=... cap=...`; this means remaining saved peers are deferred to later intervals rather than dialed all at once.

If an outbound dial fails with `reason=genesis_mismatch ...`, the peer is on a different chain. `mfnd` drops that address from the durable peer set and logs `mfnd_p2p_peer_drop peer=... reason=genesis_mismatch ...`; fix the manifest or operator inventory rather than re-adding the peer.

Full runbook: [`docs/TESTNET.md`](../../docs/TESTNET.md).

New participants should start with [`JOIN_TESTNET.md`](../../docs/JOIN_TESTNET.md), then the role-based [Join the testnet](../../docs/TESTNET.md#join-the-testnet) path before choosing observer, wallet, storage-operator, or validator commands.

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

Hardware roles and decentralization context: [docs/DECENTRALIZATION.md](../../docs/DECENTRALIZATION.md). One-command RPC-only prove loop: [start-storage-operator.sh](./start-storage-operator.sh) / [start-storage-operator.ps1](./start-storage-operator.ps1).

Permawrite separates **on-chain anchors** (private `StorageCommitment` in a block) from **off-chain bytes** (chunk payloads). Validators only mine SPoRA proofs when they can read the challenged chunk. Operators run replication and proving on devnet today via `mfn-cli` and `mfn-storage-operator`.

**Public devnet B3 registry (genesis).** `public_devnet_v1.json` enables `operator_salted_challenges`, `require_registered_operators`, and seeds two genesis storage operators (deterministic payout seeds — **testnet funds only**):

| Index | `payout_seed_hex` (64 hex chars) | Role |
|-------|----------------------------------|------|
| 0 | `c3c3c3…c3` (32 bytes) | Rehearsal replica wallet (`permanence-demo` restores operator-0) |
| 1 | `d4d4d4…d4` (32 bytes) | Second registered operator for multi-replica B3 proofs |

Bond at genesis is `0` (`min_storage_operator_bond: 0`); post-genesis registration uses `StorageOperatorOp::Register` + bond escrow. `genesis_id` is unchanged from pre-B3 public devnet.

**Public devnet B5 slash (phase 5d).** `public_devnet_v1.json` sets non-zero audit slash knobs (slash is **inactive** until storage is stale past `proof_reward_window_slots` and operators miss consecutive operator-salted challenges):

| Field | Value | Meaning (30s slots) |
|-------|-------|---------------------|
| `operator_audit_missed_cap` | `48` | ~24 minutes of consecutive missed audits before slash |
| `operator_slash_bps` | `250` | 2.5% of bonded stake forfeited to treasury per slash event |

Operators should run `mfn-storage-operator prove` on a schedule; a valid operator-salted proof in a block resets the miss counter. Rehearsal operators with `bond_amount: 0` at genesis are not slashable until they register with bond post-genesis.

**Chunk-inbox disk quota (B7).** Gossip chunk writes honor `MFND_CHUNK_INBOX_MAX_BYTES` (default **64 GiB**; `0` disables). When over budget, `mfnd` evicts **incomplete** inbox commit dirs (oldest first) and logs `mfnd_chunk_inbox_evict commit=… bytes=…`. Complete Merkle-verified sets are never evicted — they may be pending repair fan-out.

**Proactive repair (B4).** Every `mfnd serve` node with P2P runs a background repair sweep when `MFND_REPAIR_THRESHOLD_SLOTS` is non-zero (default `14400` ≈ 2× anti-hoarding window). Stale on-chain storage (`current_slot − last_proven_slot` above threshold) with a **complete Merkle-verified** local `chunk-inbox/` is re-fan-out to peers. Tune with:

| Env | Default | Meaning |
|-----|---------|---------|
| `MFND_REPAIR_THRESHOLD_SLOTS` | `14400` | Staleness before repair (`0` disables) |
| `MFND_REPAIR_INTERVAL_MS` | `300000` | Sweep interval (ms) |

Boot log: `mfnd_repair_sweep_start threshold_slots=… interval_ms=…`. Repair action log: `mfnd_p2p_repair_fanout commit=<hex> stale_slots=<n>`.

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

#### Home chunk serve behind NAT

Home operators without a static public IP can still replicate bytes by exposing `serve-chunks` or `run --chunk-listen` through a **TLS-terminated reverse tunnel** (Cloudflare Tunnel, ngrok, or similar). This is packaging only — no protocol relay:

1. Run `mfn-storage-operator serve-chunks --listen 127.0.0.1:18780` locally.
2. Point the tunnel at `127.0.0.1:18780`; publish the tunnel hostname to peers (or add it to manifest `replication_peers` when operating a public devnet).
3. Peers fetch with `operator fetch-chunk` / `uploads fetch-http` using the tunnel URL host:port.

Keep chunk HTTP behind auth at the tunnel edge if the endpoint is public. Proofs still submit via any synced observer RPC — operators do **not** need inbound P2P for the prove loop ([`DECENTRALIZATION.md`](../../docs/DECENTRALIZATION.md) §4.2).

Pull from a peer into the local artifact tree:

```bash
mfn-cli --rpc 127.0.0.1:<RPC> --wallet ./alice.json \
  operator fetch-chunk <COMMIT_HASH_HEX> 0 127.0.0.1:18780 --json

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
  operator push-chunks <COMMIT_HASH_HEX> <PEER1> [PEER2 ...] --json

mfn-storage-operator push-chunks --wallet ./alice.json \
  <COMMIT_HASH_HEX> <PEER1> [PEER2 ...] --json
```

Replicate **every** local upload artifact to manifest `replication_peers` in one command (**M7.10**):

```bash
mfn-storage-operator push-all-chunks --wallet ./alice.json \
  --manifest mfn-node/testdata/public_devnet_v1.manifest.json --json
```

Use this after onboarding a new replica peer or when catching up replication breadth without scripting per-commitment `push-chunks` calls. Requires `--manifest` (or `MFN_OPERATOR_MANIFEST`) with non-empty `replication_peers`.

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
  operator prove <COMMIT_HASH_HEX> --json

# Or raw file (must match on-chain size_root):
mfn-cli --rpc 127.0.0.1:<RPC> operator prove <COMMIT_HASH_HEX> ./myfile.bin --json
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

Participants need devnet MFN before they can send, claim, or upload. On the **live public testnet**, outsiders use the HTTP faucet (`:8788`) documented in [`JOIN_TESTNET.md`](../../docs/JOIN_TESTNET.md) — two F7 transfers, job poll, ~15 min peer-IP cooldown. Operators can also fund a participant wallet from an already-funded faucet wallet:

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

`fund-wallet.ps1` and `fund-wallet.sh` never embed faucet seeds; they require an operator-supplied wallet file that already has spendable devnet outputs. They submit with `wallet send --json`, record the `tx_id`, mempool length, and submission outcome, then wait for `starting_balance + Amount`, so an already-funded wallet does not mask an unmined transfer. **F7 / R-2:** the helpers send **two** transfers and wait for tip advance + faucet rescan between sends so the second UTXO is spendable. HTTP path (`fund-wallet-http.sh` / faucet-http) mirrors that tip-wait + job reclaim (R-1) and uses checkpoint-log `light-scan` on tall tips (B-15). For the checked-in `public_devnet_v1.json`, validator payout wallets are derived from each public validator `bls_seed_hex` with `payout_stealth_v1`, so the examples above are only appropriate for local/public test funds earned by validator 0. Keep faucet wallets out of the repo, never reuse public genesis seeds on a network with real value, and wait for the transfer to mine before asking the participant to run `wallet upload` or the permanence demo.

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

### Participant rehearsal

Use the participant rehearsal when you want one outside-user proof that the faucet, upload, restore, proof, and support handoff all work together:

```bash
# Windows plan mode:
powershell -File scripts/public-devnet-v1/participant-rehearsal.ps1 -PlanOnly `
  -Rpc 127.0.0.1:<RPC> -FaucetWallet ./validator0-faucet.json

# Windows real run:
powershell -File scripts/public-devnet-v1/participant-rehearsal.ps1 `
  -Rpc 127.0.0.1:<RPC> -FaucetWallet ./validator0-faucet.json `
  -EvidenceDir ./participant-evidence

# Linux/macOS plan mode:
bash scripts/public-devnet-v1/participant-rehearsal.sh --plan-only --rpc 127.0.0.1:<RPC> \
  --faucet-wallet ./validator0-faucet.json

# Linux/macOS real run:
bash scripts/public-devnet-v1/participant-rehearsal.sh --rpc 127.0.0.1:<RPC> \
  --faucet-wallet ./validator0-faucet.json \
  --evidence-dir ./participant-evidence
```

The plan output should end with `outputs end with support_bundle=<dir> and evidence_log=<file>`; if it does not, stop and update the helper before inviting outside users. A passing real run ends with `participant-rehearsal: PASS commitment_hash=... restored_sha256=... restored_path=... support_bundle=...` and then `participant-rehearsal: evidence_log=...`. Use `-EvidenceDir` / `--evidence-dir` when staging release evidence; it defaults the support bundle to `<evidence-dir>/support-bundle` and the evidence log to `<evidence-dir>/participant-rehearsal.log`, while explicit `-BundleDir` / `--bundle-dir` or `-EvidenceLog` / `--evidence-log` still override those paths. Archive the evidence log, the support bundle directory, and the helper logs as participant proof-of-success evidence.

The rehearsal creates/reuses wallets under `scripts/public-devnet-v1/participant-rehearsal/`, funds the uploader wallet with `fund-wallet`, runs the HTTP permanence demo, verifies the restored SHA-256, submits a proof, and captures a read-only support bundle for the replica wallet and commitment. The support bundle intentionally omits transient `fetch-chunk` capture because the demo's temporary HTTP chunk server is stopped after restore. Use only operator-controlled public-devnet/test faucet wallets; never put real faucet seeds or production keys in this repo. A failed rehearsal is a launch blocker for outside-user invites unless the failure is clearly scoped, documented, and owned by the relevant lane on the `AGENTS.md` live board.

For a local preflight that proves the same flow against the bundled public-devnet helper mesh, use the smoke wrapper:

```bash
# Windows plan mode, then real run:
powershell -File scripts/public-devnet-v1/participant-rehearsal-smoke.ps1 -PlanOnly
powershell -File scripts/public-devnet-v1/participant-rehearsal-smoke.ps1

# Linux/macOS plan mode, then real run:
bash scripts/public-devnet-v1/participant-rehearsal-smoke.sh --plan-only
bash scripts/public-devnet-v1/participant-rehearsal-smoke.sh
```

The smoke wrapper stops stale recorded mesh processes, starts `start-all`, restores validator 0's public test payout wallet into `participant-rehearsal-smoke/validator0-faucet.json` only when no custom faucet wallet is supplied, rescans until the faucet has spendable balance, runs `participant-rehearsal`, and stops the mesh it started. By default the smoke skips the non-validator observer (`MFN_DEVNET_NO_OBSERVER=1`) for faster nightly CI; pass `-WithObserver` / `--with-observer` to exercise the full hub+voters+observer mesh and optionally `-MinHubHeight` / `--min-hub-height` with `-WaitMinHubHeightSeconds` / `--wait-min-hub-height-seconds` to poll for additional blocks after rehearsal before sign-off. Each faucet wait line includes `hub_tip_height`; if it stays at `0`, diagnose hub `--produce` liveness (bounded slot scan + committee voters) before debugging wallet funding. Pass `-WaitFaucetSeconds` / `--wait-faucet-seconds` to tune the faucet reward window, `-NoStart` / `--no-start` to attach to an already-running local mesh, and `-NoStop` / `--no-stop` only when you intentionally want to inspect the mesh afterward. The wrapper now defaults its release-audit handoff to `participant-rehearsal-smoke/evidence/`, containing the generated `participant-rehearsal.log` plus `support-bundle/`; override with `-EvidenceDir` / `--evidence-dir` when staging multiple runs. A custom `-FaucetWallet` / `--faucet-wallet` is never overwritten. This helper intentionally embeds only the checked-in public validator-0 test payout seed for the default local smoke wallet; use it for local/public-devnet rehearsal only, never for a network with real value or private faucet material.

**CI policy:** `release-participant-smoke-policy-check.ps1` / `.sh` scans `.github/workflows/ci.yml`, `.github/workflows/nightly.yml`, `scripts/ci-ignored.{sh,ps1}`, and the local `ci-check` mirrors. Default CI and `ci-check` may run `participant-rehearsal` / `participant-rehearsal-smoke` with `--plan-only` / `-PlanOnly` only. Real-run mesh smokes run in nightly and `ci-ignored` after soak green and Agent 2/3 sign-off (M2.4.67).

**Nightly evidence artifacts:** On success, nightly uploads `participant-rehearsal-evidence` / `observer-rehearsal-evidence` containing both the summary transcript under `scripts/public-devnet-v1/evidence/` and the audit-ready directory `scripts/public-devnet-v1/participant-rehearsal-smoke/evidence/` (`participant-rehearsal.log` + `support-bundle/`). On failure (including assert-gate rejection after a smoke run), nightly uploads `participant-rehearsal-evidence-partial` / `observer-rehearsal-evidence-partial` when any staged evidence exists so operators can inspect missing PASS lines or incomplete support bundles. After downloading a green nightly artifact, pass `--participant-evidence-dir` / `-ParticipantEvidenceDir` pointing at the extracted `participant-rehearsal-smoke/evidence/` directory when generating `release-audit-packet.v1`. Nightly runs `assert-participant-smoke-evidence.sh` before upload so missing PASS logs or support bundles fail the job instead of shipping empty artifacts. `release-rc-audit-dry-run.ps1` runs the same assert against `fixtures/participant-rehearsal-evidence-v1/` before building the RC audit packet.

### Support bundles

When a participant reports a stuck wallet, missing upload, missing claim, or proof issue, collect the read-only JSON diagnostics in one directory:

```bash
# Windows plan mode:
powershell -File scripts/public-devnet-v1/support-bundle.ps1 -PlanOnly `
  -Rpc 127.0.0.1:<RPC> -Wallet ./alice.json -CommitHash <COMMIT_HASH_HEX>

# Windows capture:
powershell -File scripts/public-devnet-v1/support-bundle.ps1 `
  -Rpc 127.0.0.1:<RPC> -Wallet ./alice.json `
  -CommitHash <COMMIT_HASH_HEX> -Peer 127.0.0.1:18780 -DataDir C:\path\to\replica-data `
  -DataRoot <DATA_ROOT_HEX> -ClaimPubkey <CLAIM_PUBKEY_HEX> `
  -ReleaseEvidence release-evidence.json

# Linux/macOS:
bash scripts/public-devnet-v1/support-bundle.sh --rpc 127.0.0.1:<RPC> --wallet ./alice.json \
  --commit <COMMIT_HASH_HEX> --peer 127.0.0.1:18780 --data-dir /path/to/replica-data \
  --data-root <DATA_ROOT_HEX> --claim-pubkey <CLAIM_PUBKEY_HEX> \
  --release-evidence release-evidence.json
```

Use `-RpcApiKey <KEY>` or `--rpc-api-key <KEY>` for auth-enabled RPC. The key is passed to `mfn-cli` but only `rpc_api_key_set=true` is written to `manifest.json`.

The bundle writes `manifest.json` plus JSON command outputs such as `node-status.json`, `wallet-status.json`, `wallet-backup-info.json`, `uploads-list.json`, `uploads-status.json`, `operator-challenge.json`, `operator-pool.json`, `operator-fetch-chunk.json`, `operator-inbox-status.json`, and claim query results when identifiers are supplied. The helper is intentionally read-only/local-inspection only: it does **not** send funds, scan wallets, upload data, push chunks, assemble inbox artifacts, or submit proofs.

### Recovery plans

Before rebuilding wallet-local upload artifacts, generate a copy-ready recovery plan with backup warnings:

```bash
# Windows:
powershell -File scripts/public-devnet-v1/recovery-plan.ps1 `
  -Rpc 127.0.0.1:<RPC> -Wallet ./alice.json -CommitHash <COMMIT_HASH_HEX> `
  -OutputPath ./restored.bin -Peer 127.0.0.1:18780 -DataDir C:\path\to\replica-data

# Linux/macOS:
bash scripts/public-devnet-v1/recovery-plan.sh --rpc 127.0.0.1:<RPC> --wallet ./alice.json \
  --commit <COMMIT_HASH_HEX> --output ./restored.bin --peer 127.0.0.1:18780 \
  --data-dir /path/to/replica-data
```

The plan helper is non-mutating. It prints the support-bundle command to run first, then the explicit HTTP `uploads fetch-http` path and P2P `operator inbox-status` → `operator assemble-inbox` → `uploads retrieve` path. Add `-Replace` / `--replace` only when the existing artifact or restored output file may be overwritten.

For a guided recovery run that captures a support bundle first, prints the plan, restores the payload, verifies an expected SHA-256 when supplied, and optionally submits a proof:

```bash
# Windows plan mode:
powershell -File scripts/public-devnet-v1/recovery-walkthrough.ps1 -PlanOnly `
  -Rpc 127.0.0.1:<RPC> -Wallet ./alice.json -CommitHash <COMMIT_HASH_HEX> `
  -Peer 127.0.0.1:18780 -ExpectedSha256 <PAYLOAD_SHA256>

# Windows real HTTP restore:
powershell -File scripts/public-devnet-v1/recovery-walkthrough.ps1 `
  -Rpc 127.0.0.1:<RPC> -Wallet ./alice.json -CommitHash <COMMIT_HASH_HEX> `
  -Peer 127.0.0.1:18780 -OutputPath ./restored.bin -ExpectedSha256 <PAYLOAD_SHA256>

# Linux/macOS P2P inbox restore:
bash scripts/public-devnet-v1/recovery-walkthrough.sh --rpc 127.0.0.1:<RPC> --wallet ./alice.json \
  --commit <COMMIT_HASH_HEX> --data-dir /path/to/replica-data --output ./restored.bin \
  --expected-sha256 <PAYLOAD_SHA256>
```

The walkthrough only submits `operator prove` when `-Prove` / `--prove` is set. Use `-RpcApiKey <KEY>` / `--rpc-api-key <KEY>` for auth-enabled nodes; the support bundle records only that an API key was set.

### Permanence troubleshooting

| Symptom | Likely cause | Recovery |
|---------|--------------|----------|
| `wallet upload` succeeds but `uploads list` does not show the commitment | The tx is still only in the mempool, or the wallet is pointed at a node on a different chain/tip | Prefer `wallet upload --json` and keep the `tx_id`, `storage_commitment_hash`, `data_root`, `upload_artifact_dir`, and `fee` fields. After mining, run `uploads list --include-claims --json` and keep `uploads_returned`, matching upload rows, and any claim arrays. Check `mfn-cli --rpc <RPC> mempool` for the tx id, mine or wait for the next producer block, then verify `mfn-cli --rpc <RPC> tip` and `genesis_id` match the public devnet manifest. |
| `wallet claim --json` succeeds but claim queries do not show the authorship row | The claim tx is still only in the mempool, the query is pointed at a stale/diverged node, or the wrong `data_root`/`claim_pubkey` is being queried | Keep the `tx_id`, `claim_pubkey_hex`, `data_root`, and `commit_hash` from `wallet claim --json`; after mining, run `claims for <DATA_ROOT_HEX> --json` and, if needed, `claims by-pubkey <CLAIM_PUBKEY_HEX> --json` against a synced node with the same `genesis_id`. |
| `wallet balance` looks stale or support cannot tell whether funds were scanned | The wallet cache is behind the node tip, or pending spends are masking locally selected outputs | Run `mfn-cli --rpc <RPC> --wallet <WALLET> wallet status --json` and capture `scan_height`, `tip_height`, `blocks_behind`, `sync_needed`, `balance_cached`, and `pending_spent_count`; if `sync_needed=true`, run `wallet scan --json` or `wallet balance --json` against the same RPC and capture `blocks_scanned`, final `scan_height`, `balance`, and `owned_count`. |
| `operator inbox-status` reports `inbox_complete=false` | The replica has only some chunks, or it has not caught up to the upload block yet | Wait for `mfn-cli --rpc <REPLICA_RPC> tip` to match the hub, rerun `operator push-chunks <COMMIT_HASH_HEX> <REPLICA_P2P> --json`, or use HTTP `operator backfill <COMMIT_HASH_HEX> <PEER_HTTP> --json` from a peer with a complete artifact. Capture `push_chunks` peer results plus `present_indices` and `missing_indices` in support tickets. |
| `operator assemble-inbox` says chunks are missing | The node's `chunk-inbox/<commit>/<index>.bin` set is incomplete | Run `operator inbox-status --json` to see `missing_indices`, push chunks again from the original uploader, then retry `operator assemble-inbox ... replace --json` only after `inbox_complete=true`; the JSON output records the rebuilt `artifact_dir` and `payload_bytes`. |
| `operator prove` fails with `data_root` or size mismatch | The local payload/artifact is not the bytes anchored on-chain | Rebuild the artifact from a known-good peer with `operator backfill --json` or `operator assemble-inbox --json`, then run `uploads retrieve <COMMIT_HASH_HEX> ./restored.bin` and compare the restored file hash against the uploader before proving. |
| `operator prove` submits but `uploads list` still shows the old `last_proven_height` | The proof is queued but not mined yet, or the producer cannot read the challenged chunk | Check `mfn-cli --rpc <RPC> operator pool --json`; make sure the producer's data dir has the chunk inbox or artifact bytes, then mine/wait for the next block. Use `operator challenge --json`, `operator prove --json`, and `uploads list --json` before and after mining to capture the challenge target, proof submission outcome, and indexed `last_proven_height` row without parsing key/value output. |
| RPC returns an authorization error for upload/prove/pool commands | The node was started with `--rpc-api-key` / `MFND_RPC_API_KEY` and the client did not send the same key | Retry with `mfn-cli --rpc <RPC> --rpc-api-key <KEY> ...` or set `MFN_RPC_API_KEY=<KEY>` in the operator shell. |
| Health check reports divergent or stalled tips | Nodes are on different genesis files, cannot reach P2P peers, or the producer is not sealing slots | Confirm every node prints the same `mfnd_chain_genesis_id`, check `--p2p-dial` / manifest seeds and firewalls, then run `health-check` with `MFN_HEALTH_STALL_SAMPLES=2` and an interval longer than the slot duration. |

### CI reference (permanence)

| Test | What it proves |
|------|----------------|
| `mfn-cli` `chunk_p2p_smoke` | push → inbox → assemble → prove (single node) |
| `mfn-cli` `chunk_p2p_two_node_smoke` | hub mines, replica sync + push, matching payload |
| `mfn-cli` `chunk_p2p_three_node_smoke` | hub → two replicas via multi-peer `push-chunks` |
| `mfn-cli` `chunk_p2p_auto_fanout_smoke` | hub mines, replica dials, M7.5 session fan-out fills the replica inbox without `push-chunks` (runs on Windows) |
| `mfn-storage-operator` `chunk_http_smoke` | HTTP chunk serve matches artifact |
| `.github/workflows/ci.yml` `public-devnet scripts` | Bash/PowerShell helper syntax plus recovery walkthrough HTTP/P2P plan mode and proof-safety text |
| `participant-rehearsal.{ps1,sh}` plan validation | Full outside-user rehearsal advertises faucet funding, permanence restore/prove, SHA-256 verification, and support-bundle capture |
| `participant-rehearsal-smoke.{ps1,sh}` plan validation | Local real-run smoke advertises start-all, default test-faucet restore/check, faucet balance wait, custom faucet safety, rehearsal execution, and mesh cleanup |

```bash
cargo test -p mfn-cli --release --test chunk_p2p_smoke --test chunk_p2p_two_node_smoke --test chunk_p2p_three_node_smoke --test chunk_p2p_auto_fanout_smoke
cargo test -p mfn-storage-operator --release --test chunk_http_smoke
```
