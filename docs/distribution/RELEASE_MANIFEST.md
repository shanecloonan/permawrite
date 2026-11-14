# Signed release manifests

A release manifest names each file, its size, and its SHA-256. Maintainers sign that list. A download is accepted only when at least `threshold` keys from the keyring produce a valid signature over the same bytes.

The signature is the chain's Schnorr scheme over the domain `MFBN-1/release-manifest-v1`. It is an application signature for shipping software. It does not change consensus, header versions, Path A, or F-A.

## Files

| File | Holds |
| --- | --- |
| Maintainer secret | name + scalar hex. Stays offline. |
| Keyring | threshold + public keys. This is the file users keep. |
| Manifest | version, target, files. |
| Signature set | one Schnorr signature per maintainer. |

```bash
cargo run --manifest-path distribution/release-sign/Cargo.toml -- keygen --name alice --out alice.key
cargo run --manifest-path distribution/release-sign/Cargo.toml -- sign --key alice.key --manifest release.json --out alice.sig
cargo run --manifest-path distribution/release-sign/Cargo.toml -- verify --keyring keyring.json --manifest release.json --sigs sigs.json --dir ./unpacked
```

`verify` refuses:

- a threshold of zero, or a threshold higher than the number of keys
- two keys with the same name or the same public key
- a signature from a key that is not in the keyring
- fewer distinct valid signatures than the threshold
- a manifest whose file digest changed after signing
- a path containing `..`, a symlink, or bytes that do not match the digest

Put the signature set together by placing each maintainer's signature object into `{"signatures":[...]}`. One signature is not enough when the keyring says two.
