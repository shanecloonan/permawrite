# Live public testnet probe - wave 3 findings (2026-07-20)

**Lane:** 3 (onboarding / B-15)
**UTC window:** ~2026-07-20T02:15Z-02:35Z
**Prior:** wave1 afca106; wave2 on main; OPERATORS fix 384cd76 / f8cb53b

## Executive verdict

| Check | Result |
| --- | --- |
| Local observer tip after B-41 | **PASS** - tip_height=4030/4031 matching proxy |
| Observer proxy recovery | **PASS** - get_tip 200 after mid-repair 502s |
| Faucet health | **PASS** - wallet heights restored near tip |
| Receive verify (wallet light-scan on faucet-funded alice) | **INCOMPLETE / SLOW** - 10+ min, scan_height still null |
| light-scan --checkpoint-log (repo tip=3) | **UNUSABLE** at live tip (wave1 F6) |

**Finding F17 (JOIN UX):** Fresh wallet light-scan from genesis at tip ~4k is ops-hostile on this path (no mid-scan persist observed for 10+ minutes). Needs B-22 near-tip checkpoint and/or clearer time guidance.

**Finding F18 (SUCCESS):** Outside-in block sync works after B-41: dial seed, handshake, catch up ~4028 blocks, tip parity with public proxy.

## B-15 status

- Outside-in sync evidence: green (wave2/3).
- Outside-in fund HTTP: green (wave1).
- Outside-in receive + permanence: still open (F17 / B-22).
- Do not archive SUMMARY: PASS for full JOIN until owned_count>=2.

## Artifacts (local only - do not commit)

- live-testnet-data/ observer + wallets (contains seeds)

