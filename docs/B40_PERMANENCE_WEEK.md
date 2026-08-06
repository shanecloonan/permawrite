# B-40 — First permanence week runbook (lane 6)

Calendar week zero after TL-9 / **L4** closes. Companion to
[`ROADMAP.md`](./ROADMAP.md) § B-40. **Arm day-of L4** — this file is the
checklist; do not invent a second board.

**Priority:** permanence first. No Tier 2 privacy, no Path B economic value,
no `subsidy_to_treasury_bps` enable until **B-33** human go ([`B13_SUBSIDY_FORK_SIGNOFF.md`](./B13_SUBSIDY_FORK_SIGNOFF.md)).

---

## Pre-armed (already landed before L4 — do not re-do on D0)

| Item | Status | Evidence |
| --- | --- | --- |
| **B-13a** sims @ `subsidy_to_treasury_bps=1000` | **Done** | 256 `bbd50ce3` (**CI `#31077911423` GREEN**); 512 `28031bca` (watch `#31109005252`) |
| Pre-enable treasury telemetry | **Done** | [`b13-pre-enable-treasury-20260806T052834Z.md`](../scripts/public-devnet-v1/evidence/b13-pre-enable-treasury-20260806T052834Z.md) |
| HTTP `treasury-telemetry-watch` | **Done** | `360f690b`; **CI `#31090099572` GREEN** |
| **B-28** draft thresholds + assert | **Draft** / helper landed | OPERATORS § B-28; `assert-b28-treasury-thresholds.*` (`980ac1ef`); sample [`b28-treasury-watch-20260806T102833Z.md`](../scripts/public-devnet-v1/evidence/b28-treasury-watch-20260806T102833Z.md) |
| **B-20** fee-shift policy | **Draft** | [`FEES.md`](./FEES.md) §5.5 — arm after B-13c + B-25 |
| **B-33** human go | **Open** | Sign-off table still blank |

On D0, **refresh** a live treasury sample (do not skip) and confirm knobs still
`subsidy_bps=0` / `fee_bps=9000` before any enable talk.

```powershell
powershell -File scripts/public-devnet-v1/treasury-telemetry-watch.ps1 `
  -Rpc http://5.161.201.73:8787/rpc
```

```bash
bash scripts/public-devnet-v1/treasury-telemetry-watch.sh \
  --rpc http://5.161.201.73:8787/rpc
```

Archive under `scripts/public-devnet-v1/evidence/b40-d0-treasury-<UTC>.md`.

---

## Day checklist (arm when L4 closes)

### D0 — L4 close day

- [ ] Claim **B-40** in `AGENTS.md` §5 (lane 6 Doing); claim base = L4 tip SHA.
- [ ] Refresh treasury sample (command above); confirm `subsidy_to_treasury_bps=0`.
- [ ] Run `assert-b28-treasury-thresholds.* --rpc …` (pre-enable floors PASS).
- [ ] Confirm **B-13a** still in tip ancestry / CI GREEN on a head that contains sims.
- [ ] Ping lane 4+7: **B-32** arm status (≥2 distinct hosts) — do not block on it.
- [ ] Confirm **B-33** human cells still open — **do not** enable B-13c on D0 unless fully signed.

### D0–D2

- [ ] Lane 4+7: **B-32** multi-op evidence pack started or blocked-with-reason (2nd host).
- [ ] No faucet-http restart while B-15-style capture busy (honor §6 if open).

### D1–D5

- [x] B-13a 512-block follow-up landed (`28031bca`); cite only after tip CI `#31109005252` GREEN.
- [ ] Daily (or denser) `treasury-telemetry-watch` sample → evidence/`b40-dN-*.md`.
- [ ] Board Next cells stay Phase-1 permanence (no Tier-2 / Path-B value PRs).

### D3–D7

- [ ] Scan §5/§8: no Tier-2 privacy, hidden-fee, or Path-B economic value claims.
- [ ] Permanence regressions only via **B-23** / **B-36** lanes.

### Week close

- [ ] Written week-1 note: sims status, B-32 status, treasury baseline vs live tip,
      B-33/B-13c readiness. Archive `evidence/b40-week1-<UTC>.md` (or OPERATORS link).
- [ ] Move B-40 Doing → Done on board with note path; Next = human B-33 → **B-13c** or hold.

---

## Hard rules

1. Do **not** set `subsidy_to_treasury_bps = 1000` in `public_devnet_v1.json` until **B-33** fully ticked.
2. Do **not** change `fee_to_treasury_bps` in the same fork (**B-20** / one-lever).
3. Do **not** claim **B-25** from a single week of data.
4. Do **not** start Tier 2 / Path B value work under B-40 cover.

---

## Pass

- B-13a GREEN (pre-armed or tip successor).
- Telemetry baseline + D0 refresh archived.
- B-32 armed or explicitly blocked on 2nd host.
- Week-1 note archived; no Tier-2/Path-B drift in §5/§8.

---

## Cross-references

- [`ROADMAP.md`](./ROADMAP.md) — B-40 work package
- [`B13_SUBSIDY_FORK_SIGNOFF.md`](./B13_SUBSIDY_FORK_SIGNOFF.md) — **B-33**
- [`FEES.md`](./FEES.md) §5.4 / §5.5 — subsidy + **B-20**
- [`OPERATORS.md`](../scripts/public-devnet-v1/OPERATORS.md) — B-28 draft thresholds
- [`AGENTS.md`](../AGENTS.md) — live board