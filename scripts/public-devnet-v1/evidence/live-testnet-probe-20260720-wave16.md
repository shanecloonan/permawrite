# Live public testnet probe — wave 16 findings (2026-07-20)

**Lane:** 3 (onboarding / B-15)
**UTC window:** ~05:40Z–05:55Z
**Prior:** wave15 e96f41
**Tip:** **4201 → 4205**

## Executive verdict

| Gate | Result |
| --- | --- |
| list_recent_uploads array params | **FAIL** -32602 params must be a JSON object (F81) |
| list_recent_uploads object params | **PASS** — heidi c56e1c69… last_proven **4200** visible on proxy |
| dave → eve 40000 | **PASS** — eve **978997**/owned=2 (unlocked F75) |
| dave → frank 40000 | **FAIL F75** — dave already down to 1 UTXO after eve send |
| dave F71 after failed send | **REPRO** — trusted vs checkpoint 0; recovered via pin@4050 |
| heidi → frank 40000 | **PASS** — frank **1003997**/owned=2 (F75 unlocked) |
| eve upload (post F75 unlock) | **PASS** Fresh 2f5b40f2…; commitment adfaba2… |
| eve last_proven | **PASS** → **4206** matched (~3+ min; F82 slow vs heidi) |

## Finding F81 — list_recent_uploads wants object params

Proxy/public RPC rejects positional array [limit, offset]:

`	ext
params must be a JSON object
`

Working shape: {"limit":8,"offset":0} (or {}). Result envelope: {uploads, total, limit, offset, include_claims}.

**JOIN/docs:** any curl examples using arrays will false-fail on the live proxy.

## Finding F75 cascade — multi-hop spends burn input floor

Dave started with owned=3 / 1.09M. One send to eve consumed enough inputs to leave owned=1 / interim 500k (later recovered **1040000**/2 after pin+scan). Immediate second send to frank failed F75. Heidi (owned=3) successfully topped up frank.

**JOIN implication:** plan transfers knowing each spend may collapse to 1 change UTXO; keep a dual-UTXO reserve or expect faucet/peer top-up before the next action.

## Finding F82 — eve upload settlement slower than heidi

Heidi wave15 reached last_proven within ~90s. Eve wave16 upload adfaba2… stayed local_only ~3+ minutes (through tip 4205) then matched at **last_proven=4206**. Mempool showed len=2 at submit (heidi→frank + eve upload concurrent).

Possible causes: prove backlog, observer index lag, or concurrent mempool contention. Continue polling in follow-up; do not mark permanence FAIL yet.

## Activity log

| Action | Result |
| --- | --- |
| dave→eve 40k | tx e873d0ec…; eve 978997/2 |
| dave→frank | F75 reject |
| heidi→frank 40k | tx 9597c260…; frank 1003997/2; heidi 973997/2 after settle |
| eve upload | commitment adfaba2…; **last_proven=4206** |

## B-15 note

Wave15 heidi loop remains the clean SUMMARY spine. Wave16 adds API param shape (F81), F75 cascading, and a slower second-upload prove (F82) worth watching before invite load.
