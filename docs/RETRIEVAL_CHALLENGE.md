# Retrieval challenges (B-317)

SPoRA proves that an operator possessed a chunk. It does not prove the operator served that chunk. A third party cannot show a refusal, so this chain does not ask for a proof of service.

Refusal means silence. A challenger posts a `RetrievalChallenge` naming a file commitment (the chunk Merkle root), a chunk index, and a storage-operator index, and locks a deposit. The operator must answer with a `RetrievalResponse` — the chunk bytes and a Merkle path to that root — within 8 blocks. No valid response by the deadline is a refusal.

## Gate

Header version 7 (`HEADER_VERSION_RETRIEVAL`). Below that, blocks omit the retrieval section and `apply_block` rejects a non-empty list. Path A and F-A stay on header version 1. Their genesis files and `DEFAULT_*` values are unchanged. Checkpoint version 13 bytes are unchanged. Version 14 is still that layout plus the registry. A chain whose header version is 7 or higher now writes checkpoint version 17, which is the permanence fields (fee shift at v15, cold cadence at v16) plus the registry.

## Economics

The slash hits `StorageOperatorEntry.bond_amount` only. Validator equivocation evidence is a separate path.

- Silence slashes `min(bond, clamp(bond * 2500 / 10000, 100, 1_000_000))`. Half of that slash is a bounty to the challenger. The rest is credited to the treasury. The challenger's deposit is returned. A queued bond exit for that operator is dropped, including a matching `pending_unbonds` entry, so the exit cannot pay the old bond.
- A valid response does not reduce the bond. A quarter of the deposit is forfeited: half of the forfeit is added to the operator's bond, half to the treasury. The rest is credited to the challenger's refund key.
- While a challenge is open, `BondOp::Unbond` for that operator index is rejected, and an already queued unbond is not settled.

Deposits, refunds, bounties, bond moves, and treasury credits are checked against one sum in `b317_supply_is_conserved`.

The deposit amount is public. The payer is not. The funding payment is a normal ring-signed transaction; the challenge body does not name that transaction, a spend key, a view key, or a wallet. The only key in the challenge is `one_time_refund`, a fresh Edwards point created for that challenge. The registry credits refunds and bounties to that point.

## Limits

At most 4 open challenges per operator and 1 open challenge per chunk. A chunk that received a valid response cannot be challenged again for 16 blocks.

## What stays public

The commitment and the chunk index are on the chain, so an observer learns which chunk was asked for. That is the residual leak. Posting through a relay, and mixing in cover challenges against chunks the poster does not need, keeps the request from pointing at one person. The one-time key and the ring-signed deposit are what keep the requester off the challenge itself.

## Tests

`mfn-consensus` `retrieval::tests`: an honest response clears the challenge and does not slash; silence slashes, pays the bounty, and drops the exit; a false accusation costs the challenger; supply is conserved; an open challenge blocks the bond exit; header version 1 ignores the section.
