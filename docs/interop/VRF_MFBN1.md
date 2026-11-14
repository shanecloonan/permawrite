# MFBN-1 VRF variant (ECVRF-EDWARDS25519-SHA512)

Permawrite leader-election VRF follows RFC 9381 (IETF ECVRF over ed25519,
SHA-512, 128-bit challenge) **with one deliberate deviation**: hash-to-curve
uses the protocol's try-and-increment `hash_to_point` instead of the RFC's
mandatory Elligator2 map.

**Do not call this "RFC 9381 conformant."** Security is equivalent for VRF
purposes; **wire proofs and outputs differ** from any library that implements
strict Elligator2. External verifiers must reimplement MFBN-1 or hard-fork to
Elligator2 before claiming standards interop.

Implementation: [`mfn-crypto/src/vrf.rs`](../../mfn-crypto/src/vrf.rs).
Tracked as PROBLEMS.md § 15 / F5 phase F15.

---

## Construction summary

```text
sk  ← 32-byte seed

expand(sk):                              # ed25519 secret expansion
  h      = SHA-512(sk)                     # 64 bytes
  lower  = h[0..32]; prefix = h[32..64]
  lower[0]  &= 248
  lower[31] &= 127; lower[31] |= 64
  x      = lower as scalar mod ℓ          # from_bytes_mod_order
  pk     = x·G

Prove(sk, msg):
  H     = hash_to_point(compress(pk) ‖ msg)   # NOT Elligator2
  Γ     = x·H
  k     = from_bytes_mod_order_wide(SHA-512(prefix ‖ compress(H)))
  c     = chal(pk, H, Γ, k·G, k·H)            # 128-bit; see below
  s     = k + c·x  (mod ℓ)
  π     = (Γ, c, s)                           # 80-byte wire form
  β     = dhash(MFBN-1/vrf-output, compress(8·Γ))

Verify(pk, msg, π):
  recompute H, U = s·G − c·pk, V = s·H − c·Γ
  accept iff c′ = c; return β
```

Domain tags: `MFBN-1/vrf-challenge`, `MFBN-1/vrf-output` (see
[`mfn-crypto/src/domain.rs`](../../mfn-crypto/src/domain.rs)).

---

## Deviation: `hash_to_point`

RFC 9381 §5.4.1 requires Elligator2 on ed25519. MFBN-1 uses:

```text
for counter in 0..1000:
  digest = SHA-512(input ‖ counter.to_be_bytes())
  try decompress first 32 bytes as CompressedEdwardsY
  on success: return point.mul_by_cofactor()   # clear cofactor (×8)
fail after 1000 attempts
```

VRF input to `hash_to_point` is `pk_compressed ‖ msg` (see `vrf_prove` /
`vrf_verify` in `vrf.rs`). This matches Monero-style hashing elsewhere in the
stack and is deterministic across platforms.

Challenge `c` is the low 16 bytes of `dhash`, not a full scalar hash.
`dhash(domain, body)` frames each argument as an MFBN-1 blob (LEB128
length, then bytes) and returns the first 32 bytes of SHA-512. The challenge
body is five raw compressed points concatenated with **no** per-point length
prefix: `compress(pk) ‖ compress(H) ‖ compress(Γ) ‖ compress(k·G) ‖ compress(k·H)`.
`c` is `dhash` bytes `[0..16]` as a little-endian integer (the high 16 scalar
bytes stay zero). Output `β` is `dhash(MFBN-1/vrf-output, compress(8·Γ))`.

**Consequence:** For the same `(pk, msg)`, MFBN-1 and an Elligator2 ECVRF
produce different `H`, hence different `Γ`, `c`, `s`, and `β`. Proofs are not
byte-interchangeable.

---

## Wire encoding

| Piece | Size | Notes |
| --- | --- | --- |
| `gamma` | 32 | Compressed Edwards-y of Γ |
| `c` | 16 | Challenge scalar, little-endian ≤ 2¹²⁸ |
| `s` | 32 | Response scalar mod ℓ |
| **Total `π`** | **80** | `encode_vrf_proof` / `decode_vrf_proof` |

Public key `pk` is a standard ed25519 point (32-byte compressed encoding in
consensus wire). VRF output `β` is always 32 bytes.

---

## Deterministic reference vector

Inputs are fixed so independent implementations can cross-check MFBN-1 behavior.
`b18_mfbn1_reference_vector_is_pinned` in `mfn-crypto` asserts these bytes.
An independent try-and-increment in that test must match `hash_to_point`, and
the reference `H` must decode on counter **0**. Drift is consensus-breaking
for leader election.

| Field | Value |
| --- | --- |
| `sk_seed` | 32× `0x07` (`vrf_keygen_from_seed`) |
| `msg` | ASCII `election seed slot 42` |
| `pk` | `ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c` |
| `H` | `8788174d593715da0d4b3701a507e27c164c91a3396bc4a6a323a628b555ccb4` |
| `β` | `e9cb7a6bc317935bd297c21f86c94094b890239c6b15645efbe92568dfe4b24d` |
| `π` | `0c3d1c69aa9bd44183a5871daffb702e1b63f96a970c20ec2fedbb703bccd85330963f51fd98c39bdeed5e5fe3d35422276c5ea9475a9120d07e467156e408b0b19ad9db1677124cd76809d84c35cc07` |

`π` layout: `Γ` (32) ‖ `c` (16 LE) ‖ `s` (32 LE). `Γ` is the first 32 bytes
(`0c3d1c69…cd853`). `c` is `30963f51fd98c39bdeed5e5fe3d35422`.

To reproduce in Rust:

```text
cargo test -p mfn-crypto vrf::tests::b18_mfbn1_reference_vector_is_pinned -- --exact
```

---

## Leader-election usage

Slot seed (consensus): derived per fork from `prev_id`, `height`, `slot` —
see [`slot_seed`](../../mfn-consensus/src/consensus/engine.rs). Each validator
computes `β_v = VRF(sk_v, slot_seed)`; eligibility compares `β` to a
stake-weighted Q30 threshold ([`eligibility_threshold`](../../mfn-consensus/src/consensus/engine.rs)).
Lowest eligible `β` wins ([`pick_winner`](../../mfn-consensus/src/consensus/engine.rs)).

Verifiers must use MFBN-1 `vrf_verify`, not a generic RFC 9381 crate.

---

## Migration path

Strict Elligator2 would be a **consensus hard fork** (new proofs, new lottery
outcomes). Until then:

- Document tooling as **MFBN-1 VRF**.
- Block explorers and alternate clients ship MFBN-1 verification.
- Do not claim "standard VRF" in user-facing copy.

See also [`CONSENSUS.md § 2`](../CONSENSUS.md), [`SECURITY_CONSIDERATIONS.md § 5`](../SECURITY_CONSIDERATIONS.md).
