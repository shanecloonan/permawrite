# TL-7 — Genesis and validator key ceremony (Lane 7)

Human decision gate **after** TL-5 soak and TL-6 participant rehearsal PASS on the VPS. Software cannot choose this for you.

**Current public devnet identity:**

| Field | Value |
| --- | --- |
| `network_id` | `public-devnet-v1` |
| `genesis_id` | `454fa5d4a9bd6f59e35cf9ea7e68c096c9a271a92b2ec5931184e7f34a42a005` |
| Genesis file | [`mfn-node/testdata/public_devnet_v1.json`](../mfn-node/testdata/public_devnet_v1.json) |
| Validator seeds | Deterministic toy seeds in `start-hub.sh` / `start-voter.sh` (documented in repo) |

---

## Path A — Toy keys (recommended for first internet-facing experimental testnet)

**Use when:** invite-only experimental testnet, no real value, operators understand seeds are public.

| Keep | Action |
| --- | --- |
| Same `genesis_id` | Deploy byte-identical `public_devnet_v1.json` on VPS |
| Same toy validator seeds | Use `vps-start-all.sh` as-is |
| Same manifest (except `seed_nodes`) | TL-8 publishes P2P only |

**Residual risk:** Anyone with repo access can produce blocks if they know toy seeds. Acceptable only with explicit operator + human sign-off.

**TL-7 sign-off (Path A):**

```text
TL-7 decision: Path A (toy keys)
genesis_id: 454fa5d4a9bd6f59e35cf9ea7e68c096c9a271a92b2ec5931184e7f34a42a005
VPS evidence: vps-internet-soak-linux-*.txt + vps-participant-rehearsal-*.txt
Named approver: ____________________
Date (UTC): ____________________
```

---

## Path B — Fresh genesis ceremony (new chain)

**Use when:** shared/incentivized posture, non-toy deployment, or policy requires non-public validator material.

**Effect:** New `genesis_id` → **new chain**. All prior blocks, wallets, and uploads on the toy chain are irrelevant.

| Step | Owner |
| --- | --- |
| 1. Generate fresh validator VRF/BLS seeds per operator (offline; never paste in chat) | Human |
| 2. Build new genesis spec JSON; each validator supplies `bls_register_sig_hex` (BLS PoP over register payload); set `require_validator_bls_pop: 1` | Lane 4+6 review |
| 3. Run constitution validation + `genesis_config_from_json_bytes` (rejects rogue keys without secret) | Operator |
| 4. Publish new `genesis_id` + manifest; archive ceremony notes | Lane 7 |
| 5. Wipe VPS data dirs; restart mesh from new genesis | Operator |
| 6. Re-run TL-5 soak + TL-6 rehearsal on new chain | Lane 7 |

Lane 7 does **not** implement genesis generation tooling in TL-7; coordinate with lanes 4+6 for spec bytes and proptest coverage before any Path B launch.

**TL-7 sign-off (Path B):**

```text
TL-7 decision: Path B (fresh genesis)
new genesis_id: ____________________
ceremony notes location: ____________________
Named approver: ____________________
Date (UTC): ____________________
```

---

## What does not change at TL-7

| Item | Notes |
| --- | --- |
| `seed_nodes` | TL-8 only; bootstrapping addresses |
| RPC exposure | Stay loopback on VPS |
| Endowment / ring policy | Fixed in genesis unless Path B |

---

## Next phase

After TL-7 human sign-off → **TL-8** [`publish-seed-nodes.sh`](../scripts/public-devnet-v1/publish-seed-nodes.sh) + invite packet → **TL-9** [`launch-go-no-go.sh`](../scripts/public-devnet-v1/launch-go-no-go.sh).
