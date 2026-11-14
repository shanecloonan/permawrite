# Lock rule (header version 9)

One round of committee votes cannot be both safe and live. Voting again at the same height can finalize two blocks. Voting only once can leave a split with no quorum forever.

From header version 9 a validator keeps a lock:

- A polka (quorum for one block in one round) sets the lock to that block and round.
- Later votes must name the locked block.
- A polka from a strictly later round is the only way to switch.
- No lock means the next round is free, so a split can still finish.
- A height accepts one finalized block hash.

`HEADER_VERSION` stays 1. Path A and F-A do not use this rule. Versions 4–7 are B-35, Tier 2 rings, B-37 hidden fees, and B-317 retrieval. Version 8 is the equivocation height bind. Version 9 is not on the genesis allow-list. `vote_on_proposal` refuses a version-9 header; `vote_on_proposal_locked` is the entry point that carries the lock.
