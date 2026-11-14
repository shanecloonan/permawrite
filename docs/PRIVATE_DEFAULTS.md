# Private spend defaults

`wallet send` with no `--ring-size` uses the largest ring the chain allows and the decoy pool can fill.

| Chain header | Ring the wallet chooses | Fee |
| --- | --- | --- |
| Below 5 (Path A, F-A) | 16. 32 and 64 are refused. | Public. That is the only legal fee. |
| 5 and above | 64 if the pool can fill it, otherwise 32. A smaller ring is not substituted. | Public until version 6. |
| 6 and above | Same as version 5. | Hidden. `--public-fee` is refused. |

Output count is still padded to at least two. That padding is not a switch.

If the pool cannot fill the chosen ring, the send stops. The wallet does not shrink the ring to make the payment go through.
