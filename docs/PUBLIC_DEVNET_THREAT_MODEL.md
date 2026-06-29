# Public Devnet Threat Model

Permawrite is **pre-mainnet, pre-audit** software. This threat model covers the controlled public-devnet and release-candidate path only. It does not claim production security, custody safety, or adversarial/incentivized-testnet readiness.

The safest public-devnet shape is public P2P plus private RPC: validators and observers can accept P2P peers, while JSON-RPC stays on loopback, VPN, SSH tunnel, or a tightly firewalled/TLS-terminated operator endpoint.

## Release Posture

| Level | Allowed goal | Not allowed to claim |
| --- | --- | --- |
| Controlled public devnet | Exercise sync, wallet, storage, proof, recovery, and operator runbooks with known experimental risk. | Production safety, real custody, or audit-grade privacy/security. |
| Internet-facing experimental testnet | Invite outside operators only after launch go/no-go, local CI, ignored/nightly smokes, GitHub CI, private-RPC review, and key-replacement review pass. | That public RPC is safe, that public deterministic test keys are acceptable for value, or that the network is economically hardened. |
| Incentivized/adversarial testnet | Future target after deeper hardening and independent review. | Current readiness. |

## Assets

- Validator VRF/BLS seeds and validator index assignments.
- Wallet seeds, wallet JSON files, scan state, pending spends, and payout/faucet keys.
- RPC API keys, operator shell history, process environments, and support tickets.
- Genesis JSON, manifest, seed-node list, and expected `genesis_id`.
- Node data directories, checkpoints, `chain.blocks`, `peers.json`, and backups.
- Upload artifacts, chunk files, payload bytes, replica inboxes, and SPoRA proof inputs.
- Operator observability records: support bundles, health-check logs, launch sign-off notes, and incident notes.

## Threats and Required Controls

| Area | Threat | Required control before public release candidate |
| --- | --- | --- |
| RPC exposure | Internet clients can read public methods; without API key they may also reach write/admin methods. Even with API key, public read methods remain open and there is no native TLS. | Keep RPC loopback-only, VPN/SSH-only, or behind firewall/TLS with source allowlists. Set `MFND_RPC_API_KEY` for wallet-write/operator-admin methods. Verify `rpc.listen_addr`, `rpc.public_bind`, `rpc.auth_enabled`, and connection limits with `mfn-cli status`. |
| RPC DoS | Slow clients, oversized lines, malformed JSON, or connection floods can exhaust CPU, memory, threads, or file descriptors. | Keep upstream rate limits/firewalls in front of any shared endpoint. Tune `MFND_RPC_MAX_IN_FLIGHT` conservatively. Watch `rpc.current_in_flight`, malformed-request logs, and proxy/firewall counters. |
| P2P bootstrapping | Wrong or malicious seed nodes can cause failed dials, genesis mismatch noise, or wasted catch-up attempts. | Publish only reachable P2P `host:port` values. Never publish private RPC addresses or `peers.json`. Verify `mfnd_chain_genesis_id`, `mfnd_p2p_boot_dials`, genesis mismatch logs, and health-check convergence. |
| P2P sync abuse | Peers can send stale, skipped, oversized, empty, or malformed sync responses to waste work or stall catch-up. | Keep block/light-follow response caps and peer quarantine enabled. Watch `mfnd_p2p_peer_quarantine`, sync abort labels, stalled-height health checks, and repeated offender addresses. |
| Validator keys | Public deterministic devnet seeds can be reused accidentally, leaked, or shared with the wrong operator. | Treat checked-in seeds as toy-only. Replace genesis for any shared, production-like, incentivized, or non-toy deployment. Give each operator only their own `MFND_VALIDATOR_INDEX`, `MFND_VRF_SEED_HEX`, and `MFND_BLS_SEED_HEX`. |
| Wallet seeds | Wallet JSON files or restore seeds can leak through chat, logs, support bundles, screenshots, or shell history. | Support bundles must stay read-only and seed-free. Never paste seeds/API keys into issues or tickets. Back up wallet files separately from upload artifacts. Use test-only funds. |
| Storage artifacts | Upload artifacts or payload bytes can be lost even when wallet funds are recoverable; missing chunks can prevent proving or retrieval. | Back up `{wallet_stem}.upload-artifacts/`, payload bytes, and operator chunk stores. Rehearse `uploads retrieve`, HTTP/P2P backfill, inbox assembly, hash verification, and proof submission before launch. |
| Genesis and manifest drift | Operators may run byte-different genesis/manifest files and silently join different chains. | Pin and compare the expected `genesis_id`. Ensure every node prints the expected `mfnd_chain_genesis_id`. Review manifest `seed_nodes` before publishing. |
| Data loss and rollback | Bad upgrades, disk loss, or accidental cleanup can destroy node state, wallets, artifacts, or rollback evidence. | Require pre-upgrade backups, tested restore, written rollback plan, and halt conditions. Stop local meshes before CI/rebuilds to avoid binary locks and partial state. |
| Operator mistakes | Misconfigured env vars, wrong RPC endpoint, stale wallet scan, missing observer, or stale support info can create false launch confidence. | Run strict preflight, health-check with all expected roles, multi-sample liveness, `mfn-cli status`, wallet `status --json`, and launch sign-off before inviting outside operators. |
| Incident response | Operators may not know who can halt, rotate genesis, revoke endpoints, or publish recovery instructions. | Name launch-day watchers, incident-note location, halt conditions, and authority for "pause, rollback, or rotate genesis" before publishing endpoints. |

## Release-Candidate Evidence

Do not advertise a public endpoint or invite outside operators until evidence exists for all of the following:

- Exact release commit, regenerated `CODEBASE_STATS.md`, green local CI mirror, ignored/nightly smoke pass, and green GitHub CI.
- `SECURITY.md`, `README.md`, and `IMPLEMENTATION_STATUS.md` still say pre-audit and do not imply production safety.
- Public deterministic validator seeds were replaced for any non-toy deployment.
- `mfn-cli status` confirms expected `genesis_id`, `tip_height`, `tip_id`, `rpc.listen_addr`, `rpc.public_bind`, and RPC limit posture.
- Health checks pass with expected hub, voters, observer, P2P session count, and multi-sample liveness window.
- At least one wallet funding, upload, replication/backfill, retrieval, and SPoRA proof flow has been rehearsed on the candidate network or byte-identical staging.
- Backups and restore drills cover node state, genesis/manifest, validator secrets, wallet files, upload artifacts, RPC API keys, and operator notes.
- Named operators are watching logs for malformed RPC, genesis mismatch, peer quarantine, stalled height, divergent tips, storage proof failures, and unexpected public RPC exposure.

## Residual Risk

Even with all controls above, the public devnet remains experimental. Known residual risks include undiscovered consensus bugs, cryptographic implementation flaws, dependency vulnerabilities, economic design mistakes, operational mistakes, and DoS that exceeds the devnet guardrails. Treat any value, payload, or identity used on the public devnet as test-only unless and until independent review and stronger release gates say otherwise.
