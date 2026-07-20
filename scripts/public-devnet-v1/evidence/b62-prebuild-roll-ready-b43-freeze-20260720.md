# B-62 + B-43 — prebuild/roll-ready + Path B freeze inventory (2026-07-20)

## B-62

- `vps-prebuild-mfnd.sh` — release build without unit restarts (started on VPS while CI in flight).
- `assert-vps-roll-ready.sh` — tip + faucet idle + CI GREEN (API) + B-51 marker + binary present.
- Wired plan smokes into `ci-check`.

## B-43

- Draft inventory: `docs/PATH_B_GENESIS_FREEZE.md` (TBD human cells; no ceremony).
- Pointer from `TESTNET_GENESIS_CEREMONY.md`.

## Note

No `vps-roll-mfnd --apply` — CI `#29717107514` still in progress. Faucet untouched.
