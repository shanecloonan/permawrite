# B-27 outside-in invite soak refresh (2026-07-21 tip-5148)

## Summary

Lane 1 refreshed invite-head soak on the live public observer proxy after tip advanced past the B-96 archive (4820->4822). Also fixed Windows pin resolution (B-96 follow-up): PowerShell mangles gh --jq; soak now uses Get-MfnGreenRunId + ConvertFrom-Json, and assert requires a single numeric pin line (CRLF-safe).

| Field | Value |
| --- | --- |
| Evidence | outside-in-invite-soak-20260721T132129Z.txt |
| Assert | OK |
| Tip | 5146 -> 5148 (delta=2) |
| Nightly pin | #29833331135 GREEN |
| CI pin | #29831106571 GREEN |
| Head at capture | dd5f9d1 |

## B-15 safety

Read-only public proxy. Never faucet/mfnd/JOIN.
