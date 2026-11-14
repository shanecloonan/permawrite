# I-2 batch verification

Independent proofs in one block do not have to be checked one at a time.
`verify_batch` runs the existing single-proof verifiers (Merkle, CLSAG,
Borromean range, Bulletproof) across threads and writes each accept bit
back into the input position.

Nothing here is a new consensus rule. A proof is accepted only when the
same function `apply_block` already uses would accept it. A worker that
panics rejects its chunk. `workers` of 0 or 1 stays on the calling
thread. `wasm32` stays sequential so a browser wallet still compiles.

The unit test builds two copies of the I-1 workload, flips one CLSAG
message, and checks that 4 workers return the same bit vector as one
worker, with that reject still in its original slot.
