# Reference node topology (P32)

**Question:** How should validators, storage operators, wallets, and observers be deployed so network observers cannot correlate block production, chunk serving, and spend/submit behavior?

**Short answer:** Run each role on **separate hosts** (or at minimum separate advertised listen addresses). Keep wallet JSON-RPC on loopback; use Tor or a dedicated observer for remote submission. Local devnet meshes intentionally colocate on loopback — production and public testnet VPS layouts must not.

See also: [`DECENTRALIZATION.md`](./DECENTRALIZATION.md) (hardware profiles), [`PRIVACY_HARDENING.md`](./PRIVACY_HARDENING.md) §P32, [`TOR_P2P.md`](./TOR_P2P.md) (B8), [`CHECKPOINT_LOG.md`](./CHECKPOINT_LOG.md) (F12), [`SECURITY.md`](./SECURITY.md) (RPC exposure), [`TESTNET_LAUNCH.md`](./TESTNET_LAUNCH.md) (TL phases).

---

## 1. Why topology is a privacy property

On-chain RingCT hides **which UTXO** you spent. It does **not** hide **who broadcast** the transaction or **which IP** fetched a chunk. A single VPS running `--produce`, public `--rpc-listen`, and `mfn-storage-operator` against the same host lets a network adversary link:

| Observable | Correlation risk |
|---|---|
| Block proposal / vote timing | Validator identity ↔ IP |
| `submit_tx` JSON-RPC source | Wallet spend ↔ IP |
| Chunk HTTP serve / proof submit | Operator corpus ↔ IP |
| P2P session graph | Eclipse / partition (see P31) |

**P32** closes the gap between protocol privacy and operational reality: document safe layouts and warn when `mfnd serve` advertises validator + public wallet RPC on the same host.

---

## 2. Roles and separation rules

| Role | Process | Keys / secrets | Typical listen | Must not share host with |
|---|---|---|---|---|
| **Validator** | `mfnd serve --produce` (or `--committee-vote`) | VRF + BLS validator seeds (`MFND_*` env) | Public P2P `--p2p-listen` | Public wallet RPC; hot wallet file |
| **Observer** | `mfnd serve` (no produce) | None (verify only) | Public P2P + optional public RPC | Validator keys |
| **Storage operator** | `mfn-storage-operator` + `mfn-cli operator …` | Operator payout keys (wallet file) | Optional chunk HTTP (often tunneled) | Validator keys; **prefer** not validator P2P IP |
| **Wallet user** | `mfn-cli` / WASM | Spend + view keys | **Loopback only** for local RPC | Any production validator or operator machine |

**Hard rules (production / public testnet):**

1. **Wallet keys never on validator machines.** Sign and build txs on a separate device; submit via observer RPC or `--tor`.
2. **Public `--rpc-listen` never on a `--produce` host.** Use loopback RPC on validators; expose read/submit through observers.
3. **Operator manifests (PM23) stay off wallet machines.** Operator identity is public by design; wallet history is not.
4. **Prefer RPC-only operators** — `mfn-storage-operator` against any synced observer; no local `mfnd` required ([`DECENTRALIZATION.md` §2.4](./DECENTRALIZATION.md#24-storage-operator)).

Loopback devnet (`127.0.0.1:0`) is exempt from startup warnings — see §5.

---

## 3. Reference layouts

### 3.1 Local developer mesh (loopback — safe for CI)

Public-devnet scripts (`start-all`, Nightly, participant rehearsal) bind RPC and P2P on `127.0.0.1:0`. Validators produce on loopback; observer is a fourth process without `--produce`.

```text
┌──────────────┐  ┌──────────────┐  ┌──────────────┐
│ validator 0  │  │ validator 1  │  │ validator 2  │
│ mfnd --produce│  │ mfnd --produce│  │ mfnd --produce│
│ 127.0.0.1:*  │  │ 127.0.0.1:*  │  │ 127.0.0.1:*  │
└──────┬───────┘  └──────┬───────┘  └──────┬───────┘
       └─────────────────┼─────────────────┘
                         │ P2P mesh
                  ┌──────▼───────┐
                  │  observer    │
                  │  mfnd serve  │
                  │  127.0.0.1:* │
                  └──────────────┘
```

Wallet / operator CLI on the same laptop talks to `127.0.0.1` RPC — **no** `mfnd_role_topology_warning` (loopback exempt).

### 3.2 Public testnet — recommended minimum (3 validators + observer)

Match [`TESTNET.md`](./TESTNET.md) and [`public_devnet_v1.manifest.json`](../mfn-node/testdata/public_devnet_v1.manifest.json): **three validator VPS** + **one observer VPS**. Wallets and storage operators are separate participants.

```text
  VPS-A          VPS-B          VPS-C          VPS-D
 validator      validator      validator      observer
 --produce      --produce      --produce      serve (no produce)
 P2P public     P2P public     P2P public     P2P + RPC public
 RPC loopback   RPC loopback   RPC loopback   (community RPC)

  Home / laptop / operator VPS (anywhere):
    mfn-cli --rpc observer:18731   (or --tor for onion RPC)
    mfn-storage-operator --rpc observer:18731
```

**Seed publication (TL-8):** only P2P dial addresses go in manifest `seed_nodes`; validator RPC stays firewalled or loopback.

### 3.3 Production target — full separation

```text
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│ Validator VPS   │     │ Observer VPS    │     │ Operator VPS    │
│ mfnd --produce  │     │ mfnd serve      │     │ mfn-storage-op  │
│ p2p: public     │     │ p2p + rpc public│     │ rpc → observer  │
│ rpc: 127.0.0.1  │     │ api-key on write│     │ chunk: tunnel   │
└─────────────────┘     └────────▲────────┘     └─────────────────┘
                                   │
                          ┌────────┴────────┐
                          │ Wallet (local)  │
                          │ mfn-cli loopback│
                          │ or --tor submit │
                          └─────────────────┘
```

Optional: onion hidden service for P2P ([`TOR_P2P.md`](./TOR_P2P.md)) and `mfn-cli --tor` for RPC submit (B8.3) so wallet IP never touches cleartext observer logs.

---

## 4. Command templates

### Validator (dedicated host)

```bash
export MFND_VALIDATOR_INDEX=0
export MFND_VRF_SEED_HEX=…
export MFND_BLS_SEED_HEX=…
mfnd --data-dir /var/lib/mfnd-v0 --genesis public_devnet_v1.json \
  --rpc-listen 127.0.0.1:18731 \
  --p2p-listen 0.0.0.0:19001 \
  --p2p-dial 203.0.113.11:19002 --p2p-dial 203.0.113.12:19003 \
  serve --produce --slot-duration-ms 30000
```

- RPC on **loopback** only; operators and wallets use the observer RPC URL.
- Firewall: allow inbound P2P; deny inbound RPC from the internet.

### Observer (community RPC)

Community observers usually expose public RPC for wallets; loopback RPC is OK with SSH tunnel.

```bash
mfnd --data-dir /var/lib/mfnd-observer --genesis public_devnet_v1.json \
  --rpc-listen 0.0.0.0:18731 --rpc-api-key "$MFND_RPC_API_KEY" \
  --p2p-listen 0.0.0.0:19004 \
  serve
```

- Enable API key for `wallet-write` / `operator-admin` methods ([`SECURITY.md`](./SECURITY.md)).
- Publish this RPC in manifest `observer_rpc` / invite docs — not validator RPC.

### Storage operator (RPC-only path)

```bash
export MFN_RPC=http://observer.example:18731
mfn-storage-operator --data-dir ~/permawrite-operator --rpc "$MFN_RPC" …
```

No validator env vars on this machine. See [`start-storage-operator.sh`](../scripts/public-devnet-v1/start-storage-operator.sh).

### Wallet (local or Tor)

```bash
# Local: never point --rpc at your own validator
mfn-cli --rpc 127.0.0.1:18731 wallet …   # local observer tunnel or localhost wallet daemon

# Remote privacy path (B8.3):
mfn-cli --tor --rpc YOURSEED.onion:18731 wallet submit-tx …
```

---

## 5. Startup lint (`mfnd_role_topology_warning`)

**Shipped (P32 phase 0):** [`role_topology.rs`](../mfn-node/src/role_topology.rs) prints a stderr warning at `mfnd serve` startup when:

- `--produce` or `--committee-vote` is enabled, **and**
- `--rpc-listen` is **not** loopback (public wallet RPC surface), **and**
- `--p2p-listen` host matches the RPC host (same advertised IP / wildcard), **and**
- optionally `operator` when the validator payout is registered as a storage operator.

Example harness line:

```text
mfnd_role_topology_warning roles=validator+wallet_rpc+operator rpc_listen=0.0.0.0:18731 p2p_listen=0.0.0.0:8333 host=unspecified; split validator, operator, and wallet RPC across hosts (P32)
```

**Exempt:** `127.0.0.1`, `localhost`, `::1`, and devnet dynamic loopback ports — CI meshes stay quiet.

**Not yet enforced (future P32 phases):** hard fail by default on internet-facing hosts (today warn-only unless `MFND_PM23_HARD_FAIL=1`); separate lint for observer-only nodes binding wallet-write without API key.

---

## 6. Anti-patterns

| Anti-pattern | Why it hurts | Fix |
|---|---|---|
| All-in-one VPS: `--produce` + `0.0.0.0:18731` | Spend submit ↔ block producer IP | Loopback RPC on validator; public RPC on observer |
| Validator keys on operator laptop | Key theft ↔ corpus identity | Generate operator wallet on operator host only |
| Single public RPC for everything | RPC provider sees all submits | Multiple observers; client-side quorum / Tor |
| Wallet `--rpc` pointing at own validator | Self-deanonymization | Use observer or `--tor` |
| Ignoring `mfnd_role_topology_warning` | Silent acceptance of correlatable layout | Split roles before mainnet / public testnet |

---

## 7. Checklist before public testnet (operators)

- [ ] Validators: P2P public, RPC loopback, firewall documented
- [ ] Observer: public RPC with API key on write methods; listed in invite docs
- [ ] No spend keys on validator disks
- [ ] Storage operators use observer RPC, not validator RPC
- [ ] `vps-execution-checklist.sh --strict` PASS ([`TESTNET_CHECKLIST.md`](./TESTNET_CHECKLIST.md))
- [ ] TL-5 internet soak + TL-6 participant rehearsal evidence archived
- [ ] Optional: Tor hidden service for P2P/RPC per [`TOR_P2P.md`](./TOR_P2P.md)

Rehearsal wrappers (plan-only): [`reference-topology-rehearsal-smoke.sh`](../scripts/public-devnet-v1/reference-topology-rehearsal-smoke.sh), [`pm23-operator-manifest-rehearsal-smoke.sh`](../scripts/public-devnet-v1/pm23-operator-manifest-rehearsal-smoke.sh).

Role env templates: [`vps-role-validator.env.example`](../scripts/public-devnet-v1/vps-role-validator.env.example), [`vps-role-observer.env.example`](../scripts/public-devnet-v1/vps-role-observer.env.example), [`vps-role-operator.env.example`](../scripts/public-devnet-v1/vps-role-operator.env.example), [`vps-role-wallet.env.example`](../scripts/public-devnet-v1/vps-role-wallet.env.example).

---

## 8. Roadmap (P32 remaining)

| Phase | Scope | Status |
|---|---|---|
| **0** | Startup warn on colocated validator + public RPC (+ operator) | **Shipped** — `f76991a` |
| **1** | This reference doc + rehearsal smoke | **Shipped** — `85f3512` |
| **2** | Operator runbook cross-links + VPS template env files | **Shipped** — `vps-role-*.env.example` |
| **3** | Observer loopback-RPC hint when P2P is public | **Shipped** — this push |
| **4** | PM23 operator-manifest separation lint | **Phase 4a–4b shipped** — plan gate + runtime `mfnd_pm23_warning` / `mfn_storage_operator_pm23_warning` (warn-only; `MFND_PM23_HARD_FAIL=1`) |

---

## See also

- [`F5.md` §P32](./F5.md) — roadmap item definition
- [`PRIVACY_HARDENING.md` §P32](./PRIVACY_HARDENING.md) — hardening tracker
- [`scripts/public-devnet-v1/OPERATORS.md`](../scripts/public-devnet-v1/OPERATORS.md) — day-2 operations
- [`TESTNET_INVITE.md`](./TESTNET_INVITE.md) — participant-facing boot peers (post TL-8)
