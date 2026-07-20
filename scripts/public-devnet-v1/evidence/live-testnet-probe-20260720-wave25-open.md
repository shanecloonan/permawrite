# Live public testnet probe - wave 25 open soak (2026-07-20)

**Lane:** 3 / B-15 follow-on after wave24
**UTC:** ~11:18Z
**Context:** post-wave24; CI B-73 still in flight on main

## Results

| Check | Result |
| --- | --- |
| tip_id match (12 polls x 6s) | **FAIL stuck** local **4367** vs proxy **4366** (different tip_ids) |
| Seeds + FE/faucet ports | **OPEN** |
| Patricia status | last_proven **4362** matched; proxy listed |
| Oscar status | last_proven **4337** matched; proxy listed |
| uploads total | **17** (was 16 at wave24 open) |
| claims recent | **5** |
| headers vs proxy tip | **PASS** {from_height: tip-1, to_height: tip} |
| headers vs local tip while ahead | **FAIL**/unsafe (F94) |

## Finding F94 - do not request headers at local tip while ahead of proxy

Wave25-open briefly set headers_ok=False when using local tip_height **4367** while proxy tip was **4366**. Re-query against **proxy** tip returns result. JOIN tooling should use proxy tip (or min(local,proxy)) for header ranges.

## Finding F88b stuck-ahead mode

Local tip remained exactly one height ahead of proxy for >70s with stable distinct tip_ids. peer_count=3 / session_count=0. Not yet a full F74 diverge (heights still adjacent), but **do not upload/send** until tip_id matches. Continue watching; wipe+resync if gap widens or tip_ids stop reconciling.

## Artifacts

- _wave25-open-results.json (local)
