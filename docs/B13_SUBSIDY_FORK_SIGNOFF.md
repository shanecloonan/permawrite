# B-13 subsidy fork sign-off (**B-33**)

Human gate before **B-13c** enables `subsidy_to_treasury_bps = 1000` on Path A
public devnet. Companion to [`FEES.md` §5.4](./FEES.md#54-subsidy-tail-split--approved-for-next-parameter-fork-10--treasury)
and [`ROADMAP.md` Phase 1](./ROADMAP.md#phase-1--permanence-depth-on-the-live-chain-permanence-first).

**Hard rules**

- Do **not** edit [`public_devnet_v1.json`](../mfn-node/testdata/public_devnet_v1.json)
  until every checkbox below is ticked and a named human signs.
- Do **not** change `fee_to_treasury_bps` in the same fork (one lever).
- This is **not** Path B / header-v2 genesis — new `genesis_id` stays reserved
  for Path B ([`PATH_B_GENESIS_FREEZE.md`](./PATH_B_GENESIS_FREEZE.md)).

---

## Checklist (B-33)

### Technical preconditions (lane 6 — filled when evidence exists)

- [x] **B-13a sims landed** — default-CI 256-block + **512-block** treasury identity at
  `subsidy_to_treasury_bps = 1000` plus fee-drought backstop comparison vs
  `bps = 0` (`mfn-consensus` `emission_simulation` tests; 256 `bbd50ce3`;
  512 `28031bca`). Tip CI must be GREEN on a head that contains these sims
  before B-13c (**CI `#31109005252` GREEN** on `28031bca` / successor).
- [x] **One-lever rule recorded** — enable changes **only**
  `subsidy_to_treasury_bps` (`0` → `1000`). `fee_to_treasury_bps` remains
  `9000` ([`FEES.md` §5.4](./FEES.md)).
- [x] **Producer security budget note** — at tail era, ~10% of scheduled
  subsidy moves from producer coinbase to the permanence treasury
  (~0.195 → ~0.176 MFN/block at default tail). Fees still pay the producer
  10% share. Acceptable on Path A **toy keys**; re-evaluate before Path B
  economic value ([`FEES.md` §5.4](./FEES.md), [`ECONOMICS.md`](./ECONOMICS.md)).
- [x] **Bond residual named** — public devnet keeps
  `min_storage_operator_bond = 0`; B5 slashing is wired but bondless operators
  have limited skin in the game. **PM1** non-zero bonds are deferred to Path B
  / incentivized testnet — not a B-13c blocker
  ([`PROBLEMS.md` §1](./PROBLEMS.md), [`B5_OPERATOR_SLASHING.md`](./B5_OPERATOR_SLASHING.md)).
- [x] **Same-chain lean affirmed (policy draft)** — recommended Path A path is
  **same `genesis_id`** enable of `subsidy_to_treasury_bps = 1000` (parameter
  fork, not a new chain). New `genesis_id` / `header_version: 2` reserved for
  Path B. Human must still affirm or override in the sign-off block below
  (**B-13b**).

### Ops preconditions (lane 7 + human — open until archived)

- [x] **Telemetry baseline archived** — before B-13c enable, capture and commit
  (or attach under `scripts/public-devnet-v1/evidence/`) a pre-enable snapshot:

  ```bash
  bash scripts/public-devnet-v1/treasury-telemetry-watch.sh \
    --rpc <PUBLIC_OR_VPS_RPC> \
    | tee scripts/public-devnet-v1/evidence/b13-pre-enable-treasury-$(date -u +%Y%m%dT%H%M%SZ).txt
  ```

  ```powershell
  # Public observer proxy (HTTP JSON-RPC) or VPS NDJSON HOST:PORT
  powershell -File scripts/public-devnet-v1/treasury-telemetry-watch.ps1 `
    -Rpc http://5.161.201.73:8787/rpc
  ```

  Record at minimum: tip height, `treasury_base_units`,
  `subsidy_to_treasury_bps` (expect `0`), backstop-related fields the helper
  prints, and the git SHA of the running `mfnd` / release pin.

**Archived (lane 6, 2026-08-06):** [`scripts/public-devnet-v1/evidence/b13-pre-enable-treasury-20260806T052834Z.md`](../scripts/public-devnet-v1/evidence/b13-pre-enable-treasury-20260806T052834Z.md)
- public proxy `http://5.161.201.73:8787/rpc`; tip **16063**; `treasury_base_units` **2909711**; `subsidy_to_treasury_bps` **0**; `fee_to_treasury_bps` **9000**; docs SHA `c22e4277` / B-13a `bbd50ce3`.
- Remote `mfnd` release pin not exposed on public-safe proxy (record at VPS roll if needed).

- [x] **B-13a tip CI GREEN** (**CI `#31077911423` GREEN** on `4860a8d1`; body `bbd50ce3`;
  **B-13a-512** body `28031bca` — **CI `#31109005252` GREEN**) — confirm GitHub CI on a
  head that still contains the sims is GREEN before enable.

### Human decision (**B-13b**)

- [ ] **Fork policy chosen:** same-chain enable (**recommended**) / new
  `genesis_id` (write rationale if not same-chain).
- [ ] **Named human sign-off** (print name + date + “go for B-13c” or “hold”):

  | Role | Name | Date | Verdict |
  | --- | --- | --- | --- |
  | Permanence / economics | ________________ | __________ | go / hold |
  | Launch / ops (lane 7) | ________________ | __________ | go / hold |

---

## After sign-off → **B-13c** (lane 7)

Only when every box above is ticked:

1. Set `subsidy_to_treasury_bps: 1000` in
   [`mfn-node/testdata/public_devnet_v1.json`](../mfn-node/testdata/public_devnet_v1.json)
   (same `genesis_id` if same-chain).
2. Announce in [`OPERATORS.md`](../scripts/public-devnet-v1/OPERATORS.md) +
   testnet invite channels: producer-tail cut ~10%, treasury inflow + telemetry
   watch.
3. Do **not** change `fee_to_treasury_bps` in the same commit.
4. Arm **B-28** treasury watch thresholds after enable; **B-40** / **B-25**
   remain on the L4 → permanence-week calendar.

---

## Cross-references

- [`FEES.md` §5.4](./FEES.md#54-subsidy-tail-split--approved-for-next-parameter-fork-10--treasury)
- [`ECONOMICS.md`](./ECONOMICS.md) — drought / permanence durability
- [`TESTNET_CHECKLIST.md`](./TESTNET_CHECKLIST.md) — Phase 1 gate ticks
- [`AGENTS.md`](../AGENTS.md) — lane 6 ownership
