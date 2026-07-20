# Live public testnet probe — wave 8 open (2026-07-20)

**Lane:** 3 (onboarding / B-15)
**UTC open:** 2026-07-20T03:26Z
**Prior:** wave7 21ab99c
**Claim:** continue outside-in battery; bootstrap helper; transfer; retrieve; carol fund

## Snapshot at open

| Check | Result |
| --- | --- |
| Public tip | **4074** (proxy + local mfnd match) |
| Seeds 19001–19003 | OPEN |
| Faucet health | ok; wallet synced tip 4074; busy=false |
| Checkpoint log | verify ok entries=5 **max_tip_height=4057** (Δ tip ≈ 17) |
| Alice | bal 998995 owned=2 sync_needed=false pending_spent=2 |
| Bob | bal 1000000 owned=2 scan=4063 behind=11 |
| Local P2P | peer_count=1 session_count=0 (tip still advances via seed) |
| Upload retrieve | **PASS** commitment a20fcb43… → 128 bytes payload matches wave7 sample |

## In flight

1. ootstrap-wallet-from-checkpoint-log.sh plan + apply (carol)
2. Alice → bob transfer
3. Bob catch-up balance
4. Tip soak + proxy allowlist matrix
5. Carol faucet fund + receive verify via B-50 helper

## Pass criteria

| Item | Target |
| --- | --- |
| Retrieve permanence | done (open) |
| Transfer settles | bob balance increases |
| B-50 bootstrap script | plan PASS; apply documents F45 if tip≠log max |
| Carol owned_count | >=2 after fund+bootstrap |
