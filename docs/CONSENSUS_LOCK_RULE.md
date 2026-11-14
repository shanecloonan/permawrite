# Lock rule (header version 6)

One round of committee votes cannot be both safe and live. Voting again at the same height can finalize two blocks. Voting only once can leave a split with no quorum forever.

From header version 6 a validator keeps a lock:

- A polka (quorum for one block in one round) sets the lock to that block and round.
- Later votes must name the locked block.
- A polka from a strictly later round is the only way to switch.
- No lock means the next round is free, so a split can still finish.
- A height accepts one finalized block hash.

`HEADER_VERSION` stays 1. Path A and F-A do not use this rule. Version 4 is B-35 input-count padding. Version 5 is the equivocation height bind. Version 6 is not on the genesis allow-list. `vote_on_proposal` refuses a version-6 header; `vote_on_proposal_locked` is the entry point that carries the lock.
