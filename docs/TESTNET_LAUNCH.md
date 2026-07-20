# Internet-facing testnet launch (Lane 7)

Ordered path from a **local developer mesh** to the **experimental public testnet**. This is the sole charter for **Lane 7**; other lanes must not duplicate these units.

**Not in scope:** incentivized/adversarial testnet, protocol hardening (lanes 4–6), CI/Nightly fixes (lane 1), release-evidence *tooling* (lane 2).

**Posture:** pre-audit experimental software; test-only value; public P2P + private RPC per [`PUBLIC_DEVNET_THREAT_MODEL.md`](./PUBLIC_DEVNET_THREAT_MODEL.md).

### Software-ready pin (2026-07-19)

| Field | Value |
| --- | --- |
| Release commit | B-29 WS tip `5dc3aa8`; B-15 tooling `02c8df8`; B-16 docs `49d28f9`; ops through `dc05c40` (R-4) |
| CI | `#29711375639` queued on `5dc3aa8` (B-29); prior `#29700946945` GREEN on `b4a3fa7` |
| Nightly | `#29701967243` **RED** — re-dispatch after B-29 CI GREEN |
| RC audit | `release-evidence-b4a3fa7` **go** (refresh after B-15/R-4/B-29 head CI + Nightly GREEN) |
| VPS | Hetzner `5.161.201.73` — mesh + faucet + observer proxy + testnet front-end |
| `seed_nodes` | `5.161.201.73:19001`, `:19002`, `:19003` |
| Checkpoint log | `public_devnet_v1.checkpoints.jsonl` |
| TL-7 | Path A toy keys — [`tl7-genesis-signoff-path-a-20260714.txt`](../scripts/public-devnet-v1/evidence/tl7-genesis-signoff-path-a-20260714.txt) |
| **L3 status** | **Experimental public testnet live** — [`JOIN_TESTNET.md`](./JOIN_TESTNET.md), [`pfpchain.com`](https://pfpchain.com) |
| **Open TL** | **TL-9**; **B-15** JOIN; **B-29** Nightly close; **B-26/27/31** invite gates (**B-16** ✓; **B-30** docs ✓ — fill human cells at sign-off) |
| Strategic ordering | [`ROADMAP.md` L4 checklist](./ROADMAP.md#l4-exit-checklist-concrete-verification) → [Phase 1 permanence playbook](./ROADMAP.md#phase-1-permanence-playbook-acceptance-criteria) |

---

## Launch phases (strict order)

Complete each phase before starting the next. A phase may have multiple commits; one coherent unit per commit.

| Phase | ID | Gate | Owner | Blocked by |
| --- | --- | --- | --- | --- |
| **0** | TL-1 | Lane 7 charter + this playbook + `launch-status` helper | Lane 7 | — |
| **1** | TL-2 | Green GitHub CI on exact release commit (`release-ci-watch`) | Lane 7 → lane 1 monitor | CI `#29221315455` GREEN on `f3e5236` stack (`bd6d4d9`) |
| **2** | TL-3 | `release-evidence` + RC audit dry-run `decision=go` on head | Lane 7 coordinates lane 2 artifacts | TL-2 |
| **3** | TL-4 | Single-VPS runbook — [`VPS_SINGLE_BOX_LAUNCH.md`](./VPS_SINGLE_BOX_LAUNCH.md); TL-5 soak: `vps-internet-soak.sh` | Lane 7 | TL-3 |
| **4** | TL-5 | Internet soak on VPS (multi-sample health, height ≥ 10) | Lane 7 | TL-4 + VPS provisioned |
| **5** | TL-6 | Participant rehearsal on VPS (fund → upload → restore → prove → bundle) | Lane 7 | TL-5 |
| **6** | TL-7 | Genesis/key decision — [`TESTNET_GENESIS_CEREMONY.md`](./TESTNET_GENESIS_CEREMONY.md) | Lane 7 + human | TL-6 |
| **7** | TL-8 | Publish `seed_nodes` + [`TESTNET_INVITE.md`](./TESTNET_INVITE.md) invite packet | Lane 7 | TL-7 |
| **8** | TL-9 | Launch go/no-go — `launch-go-no-go.sh` + named sign-offs + **B-15** JOIN evidence + **B-16** ✓ + **B-29** Nightly GREEN + **B-26/27/30** invite gates | Lane 7 + human | TL-8 + full [L4 checklist](./ROADMAP.md#l4-exit-checklist-concrete-verification) |

Phase 0 is **documentation and status tooling only**. Phases 4–8 require a reachable host (minimum: one Linux VPS).

---

## What “REAL” means here

| Level | TL phase when done | Evidence |
| --- | --- | --- |
| Software ready | TL-3 | Green CI + `release-evidence.json` + RC audit dry-run go |
| Network exists on internet | TL-5–TL-6 | VPS soak + participant rehearsal transcripts archived under `scripts/public-devnet-v1/evidence/` |
| Outsiders can join | TL-8–TL-9 | Non-empty `seed_nodes`, invite doc, human sign-off on [`OPERATORS.md`](../scripts/public-devnet-v1/OPERATORS.md) go/no-go |

Editing genesis after TL-8 starts a **new chain** (`genesis_id` mismatch). Lane 7 never treats manifest edits as live chain patches.

---

## Lane 7 does / does not

| Owns | Does not own |
| --- | --- |
| `docs/TESTNET_LAUNCH.md`, launch-status helpers | M5 proptests, F7 consensus (lane 4) |
| VPS runbook, `seed_nodes` publication process | `release-evidence` schema/scripts (lane 2) |
| Launch ceremony tracking, invite packet | Nightly GHA timeout fixes (lane 1) |
| Coordinating evidence archive on green head | Wallet ring defaults (lane 5) |

---

## Operator quick status

```bash
bash scripts/public-devnet-v1/launch-status.sh
bash scripts/public-devnet-v1/vps-launch-ceremony.sh --plan-only   # full VPS path
```

```powershell
powershell -File scripts/public-devnet-v1/launch-status.ps1
powershell -File scripts/public-devnet-v1/vps-launch-ceremony.ps1 -PlanOnly
```

Provision a host first: [`VPS_PROVISION.md`](./VPS_PROVISION.md).

Prints TL phase hints, `seed_nodes` posture, VPS evidence presence, release binary presence, and CI watcher summary when `gh` is available.

---

## Handoffs

| From | To | When |
| --- | --- | --- |
| Lane 1 | Lane 7 | CI green on head — TL-2 unblocks |
| Lane 2 | Lane 7 | Evidence schema changes — lane 7 consumes, does not fork generators |
| Lane 7 | Human | TL-7 key ceremony, TL-9 sign-off names |

Update [`AGENTS.md`](../AGENTS.md) § Current board and this file when each TL unit lands.
