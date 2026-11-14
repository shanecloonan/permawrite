# Release pack

`scripts/release-pack.sh --pack` builds `mfn-cli` for the machine it is run on and writes a checksum file. Someone who receives the binary checks that file instead of compiling.

Set `SOURCE_DATE_EPOCH` to a fixed Unix time. The script refuses to build without it, so the binary does not embed today's clock. It also passes `--locked` and `--remap-path-prefix` so the crate path on the builder's disk is not baked into the binary. Two builds with the same epoch, the same lockfile, and the same Rust toolchain on the same operating system are the reproducible pair. A Linux binary is not expected to match a Windows binary.

The checksum file is `dist/release/SHA256SUMS`. Check it with `sha256sum -c SHA256SUMS` in that directory.

To sign it, set `RELEASE_SIGNING_KEY` to a PEM private key. The script writes `SHA256SUMS.sig` (SHA-256, OpenSSL). Publish the matching public key with the files. The script does not generate a long-lived key.

`--self-test` does not compile. It checksums a fixture, signs it with a throwaway key, and verifies the signature. CI runs that test.
