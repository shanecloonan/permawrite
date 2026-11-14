# Sealed replica proofs (header version 10)

A storage proof below version 10 carries the plaintext chunk. At version 10 the proof carries that operator's seal of the chunk. The Merkle leaf is still the plaintext chunk hash, so `data_root` does not change. The verifier opens the seal with the operator id from the payout keys and then checks the leaf.

`get_storage_challenge` now includes `header_version`. When that value is 10 or higher, `mfn-storage-operator` seals the chunk before `submit_storage_proof`. Older nodes omit the field; the operator treats that as plaintext.

Version 8 is reserved for Seat B. Version 9 is the shard stripe. Path A and F-A stay on version 1 and keep plaintext proofs.

A seal copied from operator A does not open under operator B, so one disk of plaintext is not a second operator's proof.
