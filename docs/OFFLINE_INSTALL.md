# Offline install

A binary is copied into place only after a signature over its hash checks
out. The installer does not open a network connection.

The signed text is:

```text
permawrite-install v1
file mfnd <sha256> <size>
file mfn-cli <sha256> <size>
```

Names are sorted. The signature is the chain's Schnorr signature, checked
against a public key you already have (paper, a previous install, a friend).
A key that arrives in the same untrusted directory as the binaries is not
consulted.

If the signature is wrong, or a file's bytes do not match the hash, the
destination is left as it was. If a destination file already exists and its
bytes differ, the install stops and that file is not replaced.

This does not change consensus, Path A, or F-A.
