# Release-Candidate Artifact Inventory Template

Use this template for every public-devnet release candidate before publishing endpoints, seed nodes, binaries, or operator instructions. This is an inventory, not an approval by itself. Every path, checksum, and reviewer entry must be filled in or explicitly marked `not applicable` with a reason.

Permawrite is pre-audit experimental software. Do not place secrets in this inventory: no wallet seeds, validator seeds, RPC API keys, private SSH keys, private `peers.json`, or unpublished operator contact credentials.

## Release Identity

- Release candidate name:
- Intended network: `controlled public devnet` / `internet-facing experimental testnet` / other:
- Git branch:
- Git commit:
- Working tree state: `clean` / `dirty with written exception`:
- `CODEBASE_STATS.md` generated UTC:
- GitHub CI run URL:
- Local CI mirror command and result:
- Ignored/nightly smoke command and result:
- Release operator:
- Independent reviewer:
- Launch notes path or URL:

## Archive Layout

Publish release-candidate artifacts as a single immutable directory or archive named after the exact release candidate and commit. Keep the structure stable so operators, reviewers, and dashboards can find evidence without bespoke instructions.

Suggested layout:

```text
permawrite-public-devnet-<rc>-<commit>/
  README.md
  binaries/
    <os>-<arch>/
      mfnd[.exe]
      mfn-cli[.exe]
      mfn-storage-operator[.exe]
      checksums.sha256
  network/
    genesis.json
    public_devnet_manifest.json
    checksums.sha256
  evidence/
    release-evidence.md
    release-evidence.json
    release-evidence-v1.schema.json
    release-signoff-review.md
    release-artifact-inventory.md
    checksums.sha256
  support/
    support-bundle.zip
    manifest.json
    checksums.sha256
  docs/
    TESTNET.md
    SECURITY.md
    PUBLIC_DEVNET_THREAT_MODEL.md
    OPERATORS.md
```

Archive rules:

- [ ] The archive contains only public release artifacts and seed-node information intended for publication.
- [ ] No wallet seeds, validator seeds, RPC API keys, private `peers.json`, private hostnames, or operator credentials are present.
- [ ] Every directory with files has a `checksums.sha256` or equivalent checksum record.
- [ ] `release-artifact-inventory.md` records paths or URLs that match the final archive layout.
- [ ] `release-evidence.json`, support-bundle `manifest.json`, and this inventory all name the same release commit.
- [ ] If the support bundle is compressed, the uncompressed `manifest.json` is also copied to `support/manifest.json` for quick review.
- [ ] Any redacted or omitted artifact is listed in this inventory as `not applicable: <reason and owner>`.

## Binary Artifacts

- `mfnd`
  - Path or URL:
  - Build host/OS:
  - Build command:
  - SHA-256:
  - Reviewer:
- `mfn-cli`
  - Path or URL:
  - Build host/OS:
  - Build command:
  - SHA-256:
  - Reviewer:
- `mfn-storage-operator`
  - Path or URL:
  - Build host/OS:
  - Build command:
  - SHA-256:
  - Reviewer:
- Optional `mfn-wasm` / web demo package
  - Path or URL:
  - Build command:
  - SHA-256:
  - Reviewer:

## Network Definition

- Genesis JSON
  - Path or URL:
  - SHA-256:
  - Expected `genesis_id`:
  - Reviewer:
- Public-devnet manifest
  - Path or URL:
  - SHA-256:
  - `seed_nodes` reviewed for public P2P addresses only: `yes` / `no`:
  - Reviewer:
- Operator instructions snapshot
  - Path or URL:
  - SHA-256:
  - Reviewer:
- Threat model snapshot
  - Path or URL:
  - SHA-256:
  - Residual-risk owner list path or URL:
  - Reviewer:

## Release Evidence

- Human evidence record: `release-evidence.md`
  - Path or URL:
  - SHA-256:
  - Reviewer:
- Machine evidence record: `release-evidence.json`
  - Path or URL:
  - SHA-256:
  - `schema_version`:
  - Reviewer:
- Release-evidence schema
  - Path or URL:
  - SHA-256:
  - Reviewer:
- Support bundle
  - Path or URL:
  - SHA-256 or archive checksum:
  - `manifest.json` confirms `release_evidence.valid=true`: `yes` / `no`:
  - Reviewer:
- Sign-off review output
  - Path or URL:
  - SHA-256:
  - Reviewer:

## Operational Evidence

- Health-check output
  - Path or URL:
  - Roles observed:
  - Result:
  - Reviewer:
- RPC posture evidence
  - Path or URL:
  - `rpc.listen_addr`:
  - `rpc.public_bind`:
  - Auth/firewall/TLS decision:
  - Reviewer:
- P2P reachability evidence
  - Path or URL:
  - Public P2P addresses checked:
  - Reviewer:
- Storage/permanence rehearsal evidence
  - Path or URL:
  - Upload commitment:
  - Retrieval proof:
  - SPoRA proof result:
  - Reviewer:
- Backup/restore rehearsal evidence
  - Path or URL:
  - Restore host:
  - Result:
  - Reviewer:
- Rollback/halt plan
  - Path or URL:
  - Named halt authority:
  - Reviewer:

## Checksums

Record checksums with one command family and keep command output attached to launch notes.

Preferred helper output for inventory rows:

```powershell
powershell -File scripts/public-devnet-v1/artifact-checksums.ps1 `
  target/release/mfnd.exe `
  target/release/mfn-cli.exe `
  scripts/public-devnet-v1/public_devnet_v1.json
```

```bash
bash scripts/public-devnet-v1/artifact-checksums.sh \
  target/release/mfnd \
  target/release/mfn-cli \
  scripts/public-devnet-v1/public_devnet_v1.json
```

Windows:

```powershell
Get-FileHash -Algorithm SHA256 <path>
```

Linux/macOS:

```bash
sha256sum <path>
```

Validate the filled inventory before sign-off:

```powershell
powershell -File scripts/public-devnet-v1/artifact-inventory-validate.ps1 `
  .\release-artifact-inventory.md
```

```bash
bash scripts/public-devnet-v1/artifact-inventory-validate.sh \
  ./release-artifact-inventory.md
```

## Final No-Go Review

- [ ] No required artifact is missing.
- [ ] Every checksum was independently reproduced.
- [ ] `release-evidence.json` and support-bundle `manifest.json` agree on the release commit.
- [ ] Public RPC exposure, if any, has a written firewall/TLS/API-key exception and an owner.
- [ ] All unknown CI, health, RPC, P2P, storage, or backup fields have written exceptions and owners.
- [ ] The release remains described as pre-audit experimental software in public docs.
- [ ] Reviewer signs off that this inventory is complete enough for experimental public-devnet launch.

Reviewer:

Decision: `go` / `no-go`

Reason:
