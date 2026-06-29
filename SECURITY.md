# Security Policy

## Status

Permawrite is **pre-mainnet, pre-audit** software. The repository includes controlled public-devnet tooling, but the consensus-critical cryptography and operator stack have not been independently reviewed. Treat any deployment as experimental.

The reference daemon's JSON-RPC listener is a development/testnet control plane, not an audited public API. By default it binds to loopback; if you bind RPC to a LAN or public interface, set `--rpc-api-key` or `MFND_RPC_API_KEY`, place the port behind a firewall or TLS reverse proxy, and assume the node remains experimental. API-key enforcement protects `wallet-write` and `operator-admin` methods (`submit_tx`, `submit_storage_proof`, mempool/proof-pool clears, checkpoint save, and P2P light-follow proxy calls); public read methods remain unauthenticated. See [`scripts/public-devnet-v1/OPERATORS.md`](scripts/public-devnet-v1/OPERATORS.md#firewall-and-tls-examples) for concrete Linux/Windows firewall and TLS-wrapper examples.

The RPC server has devnet DoS guards: bounded in-flight accepted connections, per-connection I/O timeouts, request-line byte limits, pre-lock request validation, and sanitized request outcome logs. These guards reduce trivial resource-exhaustion risk but do **not** make RPC safe to expose directly to the internet; use upstream firewall, VPN/SSH, TLS termination, and rate limiting for any shared operator endpoint.

For release-candidate risk review, see the [public-devnet threat model](docs/PUBLIC_DEVNET_THREAT_MODEL.md). It covers RPC, P2P, wallet seeds, storage artifacts, genesis/manifest, validator keys, DoS, data loss, and operator mistakes.

## Reporting a vulnerability

If you believe you have found a security vulnerability — in the cryptographic primitives, the encoding/decoding logic, the eventual consensus rules, or anywhere else in this repo — please disclose it **privately**.

**Do not** open a public GitHub issue.

Use one of the following channels:

- **GitHub private vulnerability report.** From the repository page → `Security` tab → `Report a vulnerability`. This is the preferred channel.
- **Email.** Contact the maintainer at the email in the most recent commit (`git log -1 --pretty=%ae`).

Please include:

- A clear description of the issue and the threat it poses.
- A minimal proof-of-concept, ideally as a failing `cargo test` we can run.
- Your assessment of severity (informational / low / medium / high / critical).
- Any suggested mitigation.

You will receive an acknowledgement within **72 hours**. We aim to triage within 7 days and produce a fix or mitigation plan within 30 days, depending on severity.

## What's in scope

- Cryptographic correctness in `mfn-crypto`, `mfn-bls`, and any future protocol crates (ring-signature soundness, range-proof zero-knowledge, hash domain-separation, etc.).
- Constant-time-comparison failures or timing side-channels in code that handles secret material.
- Memory-safety issues (despite `#![forbid(unsafe_code)]`, transitive dependencies may still introduce them).
- Wire-format ambiguities or parser bugs.
- Logic errors in the eventual consensus / state-transition function.
- RPC authentication bypasses, unsafe defaults, malformed-request crashes, or exposure of operator-admin methods without the configured API key.

## What's out of scope (for now)

- Bugs in out-of-repo demos or clients should be reported in those projects.
- Performance / DoS issues that do not affect correctness, except trivial RPC crashes or resource exhaustion that can take down an internet-facing testnet node.
- Build-system issues unrelated to security.

## Coordinated disclosure

Once a fix is in place, we will:

1. Land the fix in a private branch.
2. Publish a release with a generic `chore: security fix` message and a placeholder advisory.
3. After the fix has been deployed (or, before mainnet/incentivized operation, ~30 days), publish the full GitHub Security Advisory crediting the reporter (unless they prefer to remain anonymous).

Thank you for helping make this thing safe.
