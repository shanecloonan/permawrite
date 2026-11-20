# Signed release manifests

A release file is accepted when enough maintainers sign the same list of
SHA-256 hashes. One person, including someone who used to be a maintainer,
is not enough.

This is packaging. It does not change consensus, Path A, or F-A.

## What is signed

`mfn-release` (`dist/mfn-release`) writes a text manifest:

```text
permawrite-release-manifest v1
git <40 hex characters of the commit>
rustc 1.83.0
target x86_64-unknown-linux-gnu
threshold 2
artifact mfnd <sha256> <size>
artifact mfn-cli <sha256> <size>
signature alice <128 hex characters>
signature bob <128 hex characters>
```

Each signature is the chain's Schnorr signature over the lines above the
`signature` lines. The artifact list is sorted by name, so two maintainers
who list the files in a different order still sign the same bytes.

## Keys

```bash
mfn-release keygen --id alice --out alice.key
```

`alice.key` holds the secret. Publish only the `public` line, in a keyring
file of `id <64 hex>` lines. Put a lost or departed maintainer's public key
in a revocation file, one key per line. A revoked signature is a failure, not
a signature that is quietly ignored.

## Verify

```bash
mfn-release verify --keyring maintainers.txt --revoked revoked.txt --manifest release.txt
```

Verification fails when:

- fewer distinct signatures verify than `threshold`
- a signature does not match the body
- the signer is not in the keyring
- the signer is revoked
- an artifact name is absolute or contains `..`

Keep the keyring with the source you already trust (a friend, a previous
release, a content-addressed copy). A signature does not help if the only
copy of the keyring came from the same place as a substituted binary.
