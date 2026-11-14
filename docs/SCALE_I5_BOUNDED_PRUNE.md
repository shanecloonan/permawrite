# I-5 bounded block bodies

An archival log keeps every body. That is the Path A role: `prune_bodies`
refuses.

A bounded log may drop a body only when
`historical_block_body_may_prune` says the height is strictly below a
finalized checkpoint. The header id stays, so the chain still links.
A second prune drops nothing.

Storage commitments, the UTXO map, spent key images, and header ids are
refused. The first three ask `storage_may_prune`, `utxo_may_prune`, and
`spent_key_image_may_prune`, which are false. A checkpoint of 0 drops
nothing.

No consensus change. Path A and F-A files are unchanged.
