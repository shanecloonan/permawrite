# Air-gapped signing

The spend seed stays on a machine that does not have a network. The online
machine never sees it.

1. On the offline machine, once, write the seed to a file mode `0600`:

```text
seed <64 hex characters>
```

2. Show the online machine the public keys, in person or on paper:

```bash
mfn-airgap watch --seed seed.txt
```

That prints `view_pub` and `spend_pub`. It does not print the seed. The
online machine can scan with the view key. It cannot spend.

3. The online machine writes a payment request: fee, outputs, and the
SHA-256 of the transaction bytes if those bytes were built offline.

4. The offline machine signs it:

```bash
mfn-airgap sign --seed seed.txt --request request.txt --out signed.txt
```

`signed.txt` carries the request, the spend public key, and a Schnorr
signature from the wallet spend key. A group-readable seed file is refused.

5. The online machine checks the signature against the spend key from step 2,
not against whatever public key is inside the file:

```bash
mfn-airgap verify --signed signed.txt --spend-pub <spend_pub from step 2>
```

A changed fee, a changed payload hash, or a swapped spend key fails.

This does not change consensus, Path A, or F-A. It does not broadcast a
transaction.
