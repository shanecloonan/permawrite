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
sk  ← 32-byte seed (ed25519-style expansion)
pk  = x·G

Prove(sk, msg):
  H     = hash_to_point(encode(pk) ‖ msg)   # NOT Elligator2
  Γ     = x·H
  k     = nonce(prefix, H)                  # deterministic Fiat–Shamir
  c     = chal(pk, H, Γ, k·G, k·H)        # dhash(MFBN-1/vrf-challenge, …)
  s     = k + c·x  (mod ℓ)
  π     = (Γ, c, s)                         # 80-byte wire form
  β     = dhash(MFBN-1/vrf-output, encode(8·Γ))

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
Values are asserted in `mfn-crypto` unit tests (`prove_verify_round_trip`,
`output_is_deterministic`, `wire_round_trip`).

| Field | Value |
| --- | --- |
| `sk_seed` | 32× `0x07` (`vrf_keygen_from_seed`) |
| `msg` | ASCII `election seed slot 42` |
| Property | Same `(seed, msg)` ⇒ identical `β`, `Γ`, `c`, `s` across runs |

To reproduce in Rust:

```text
cargo test -p mfn-crypto vrf::tests::output_is_deterministic -- --nocapture
```

For a hex pin of `β` and `π` on the reference vector, run the example below
once and commit the output — drift in `hash_to_point` or challenge encoding is
consensus-breaking.

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
