# Security Policy

## Status

Permawrite is **pre-network, pre-audit** software. The code in this repository implements consensus-critical cryptography but has not been independently reviewed. Treat any deployment as experimental.

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

## What's out of scope (for now)

- Bugs in the surrounding TypeScript reference implementation (those go to [`cloonan-group`](https://github.com/shanecloonan/cloonan-group)).
- Performance / DoS issues that do not affect correctness.
- Build-system issues unrelated to security.

## Coordinated disclosure

Once a fix is in place, we will:

1. Land the fix in a private branch.
2. Publish a release with a generic `chore: security fix` message and a placeholder advisory.
3. After the fix has been deployed (or, pre-network, ~30 days), publish the full GitHub Security Advisory crediting the reporter (unless they prefer to remain anonymous).

Thank you for helping make this thing safe.
