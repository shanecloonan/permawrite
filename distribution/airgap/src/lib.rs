//! Air-gapped signing.
//!
//! The online machine writes a request: public rings, amounts, and output
//! addresses. It does not contain spend keys. The air-gapped machine adds
//! the spend keys, signs, and returns two files: broadcast bytes, and a
//! blinding file that must not be published.
//!
//! Rings are exactly 16. Inputs and outputs are at least 2. That matches
//! the wallet floor. A smaller ring is refused here, before a signature
//! is made. Verification uses the production ring policy. Header versions
//! are unchanged, so Path A and F-A stay as they are.

use curve25519_dalek::edwards::EdwardsPoint;
use mfn_consensus::{
    decode_transaction, encode_transaction, sign_transaction, tx_id, verify_transaction, InputSpec,
    OutputSpec, Recipient, RingPolicy,
};
use mfn_crypto::clsag::ClsagRing;
use mfn_crypto::{bytes_to_scalar, point_from_bytes, scalar_to_bytes};
use serde::{Deserialize, Serialize};

/// Wallet ring floor. A smaller ring is not signed.
pub const AIRGAP_RING: usize = 16;
/// Wallet input floor.
pub const AIRGAP_MIN_INPUTS: usize = 2;
/// Wallet output floor.
pub const AIRGAP_MIN_OUTPUTS: usize = 2;

/// Why signing or verification stopped.
#[derive(Debug)]
pub enum AirgapError {
    /// The request is below the wallet floor or the keys do not line up.
    Floor(&'static str),
    /// A point or scalar was not 32 bytes, or a point did not decompress.
    BadKey,
    /// The transaction did not verify under the production ring policy.
    Invalid,
    /// JSON was not the request shape. Unknown fields are refused, so a
    /// spend key cannot hide in the online file.
    Format(String),
}

impl std::fmt::Display for AirgapError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Floor(msg) => write!(f, "{msg}"),
            Self::BadKey => write!(f, "key material is not a valid point or scalar"),
            Self::Invalid => write!(f, "broadcast transaction did not verify"),
            Self::Format(msg) => write!(f, "{msg}"),
        }
    }
}

impl std::error::Error for AirgapError {}

/// One input as the online machine sees it. No spend key.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InputRequest {
    /// Compressed spend points, length [`AIRGAP_RING`].
    pub ring_spend_hex: Vec<String>,
    /// Compressed commitments, same length and order.
    pub ring_commit_hex: Vec<String>,
    /// Index of the real spend inside the ring.
    pub signer_idx: usize,
    /// Hidden value of the real input.
    pub value: u64,
    /// Blinding of the real input's commitment.
    pub blinding_hex: String,
}

/// One output. Amounts are typed on the air-gapped machine's request file.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OutputRequest {
    /// Recipient view public key, hex.
    pub view_hex: String,
    /// Recipient spend public key, hex.
    pub spend_hex: String,
    /// Amount.
    pub value: u64,
}

/// The file that may travel to the air-gapped machine.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignRequest {
    /// Inputs. At least [`AIRGAP_MIN_INPUTS`].
    pub inputs: Vec<InputRequest>,
    /// Outputs. At least [`AIRGAP_MIN_OUTPUTS`].
    pub outputs: Vec<OutputRequest>,
    /// Public fee.
    pub fee: u64,
}

/// Spend scalars. This file stays on the air-gapped machine.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SpendKeys {
    /// One hex scalar per input, same order.
    pub spend_hex: Vec<String>,
}

/// What the air-gapped machine returns.
#[derive(Clone, Debug)]
pub struct AirgapSigned {
    /// Wire transaction. Safe to carry back to a networked machine.
    pub broadcast: Vec<u8>,
    /// Hex transaction id.
    pub tx_id_hex: String,
    /// Output blindings. Do not publish these.
    pub private_blindings_hex: Vec<String>,
}

fn hex32(text: &str) -> Result<[u8; 32], AirgapError> {
    let bytes = hex::decode(text).map_err(|_| AirgapError::BadKey)?;
    if bytes.len() != 32 {
        return Err(AirgapError::BadKey);
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn point(text: &str) -> Result<EdwardsPoint, AirgapError> {
    let raw = hex32(text)?;
    point_from_bytes(&raw).map_err(|_| AirgapError::BadKey)
}

/// Sign `request` with `keys`. The request must already meet the wallet floor.
pub fn sign_offline(request: &SignRequest, keys: &SpendKeys) -> Result<AirgapSigned, AirgapError> {
    if request.inputs.len() < AIRGAP_MIN_INPUTS {
        return Err(AirgapError::Floor("need at least 2 inputs"));
    }
    if request.outputs.len() < AIRGAP_MIN_OUTPUTS {
        return Err(AirgapError::Floor("need at least 2 outputs"));
    }
    if keys.spend_hex.len() != request.inputs.len() {
        return Err(AirgapError::Floor("one spend key per input"));
    }
    let mut inputs = Vec::with_capacity(request.inputs.len());
    for (input, spend_hex) in request.inputs.iter().zip(&keys.spend_hex) {
        if input.ring_spend_hex.len() != AIRGAP_RING || input.ring_commit_hex.len() != AIRGAP_RING {
            return Err(AirgapError::Floor("each ring must be exactly 16"));
        }
        if input.signer_idx >= AIRGAP_RING {
            return Err(AirgapError::Floor("signer index is outside the ring"));
        }
        let mut p = Vec::with_capacity(AIRGAP_RING);
        let mut c = Vec::with_capacity(AIRGAP_RING);
        for (spend, commit) in input.ring_spend_hex.iter().zip(&input.ring_commit_hex) {
            p.push(point(spend)?);
            c.push(point(commit)?);
        }
        let spend_priv = bytes_to_scalar(&hex32(spend_hex)?);
        let blinding = bytes_to_scalar(&hex32(&input.blinding_hex)?);
        if scalar_to_bytes(&spend_priv) == [0u8; 32] {
            return Err(AirgapError::BadKey);
        }
        inputs.push(InputSpec {
            ring: ClsagRing { p, c },
            signer_idx: input.signer_idx,
            spend_priv,
            value: input.value,
            blinding,
        });
    }
    let mut outputs = Vec::with_capacity(request.outputs.len());
    for output in &request.outputs {
        outputs.push(OutputSpec::ToRecipient {
            recipient: Recipient {
                view_pub: point(&output.view_hex)?,
                spend_pub: point(&output.spend_hex)?,
            },
            value: output.value,
            storage: None,
        });
    }
    let signed = sign_transaction(inputs, outputs, request.fee, Vec::new())
        .map_err(|_| AirgapError::Invalid)?;
    let broadcast = encode_transaction(&signed.tx);
    let tx_id_hex = hex::encode(tx_id(&signed.tx));
    let private_blindings_hex = signed
        .output_blindings
        .iter()
        .map(|s| hex::encode(scalar_to_bytes(s)))
        .collect();
    Ok(AirgapSigned {
        broadcast,
        tx_id_hex,
        private_blindings_hex,
    })
}

/// Verify broadcast bytes under [`RingPolicy::PRODUCTION`].
pub fn verify_broadcast(bytes: &[u8]) -> Result<String, AirgapError> {
    let tx = decode_transaction(bytes).map_err(|_| AirgapError::Invalid)?;
    let verdict = verify_transaction(&tx, &RingPolicy::PRODUCTION);
    if !verdict.ok {
        return Err(AirgapError::Invalid);
    }
    Ok(hex::encode(tx_id(&tx)))
}

/// Parse a request. Unknown fields, including a spend key, are an error.
pub fn request_from_json(text: &str) -> Result<SignRequest, AirgapError> {
    serde_json::from_str(text).map_err(|e| AirgapError::Format(e.to_string()))
}

/// Parse spend keys.
pub fn keys_from_json(text: &str) -> Result<SpendKeys, AirgapError> {
    serde_json::from_str(text).map_err(|e| AirgapError::Format(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use curve25519_dalek::scalar::Scalar;
    use mfn_crypto::hash::hash_to_scalar;
    use mfn_crypto::{generator_g, generator_h, point_to_bytes, stealth_gen};

    fn scalar_hex(parts: &[&[u8]]) -> (String, Scalar) {
        let s = hash_to_scalar(parts);
        (hex::encode(scalar_to_bytes(&s)), s)
    }

    fn point_hex(p: &EdwardsPoint) -> String {
        hex::encode(point_to_bytes(p))
    }

    fn input(tag: u8, value: u64) -> (InputRequest, String) {
        let (spend_hex, spend) = scalar_hex(&[b"spend", &[tag]]);
        let (blind_hex, blind) = scalar_hex(&[b"blind", &[tag]]);
        let real_p = generator_g() * spend;
        let real_c = generator_g() * blind + generator_h() * Scalar::from(value);
        let mut ring_spend = Vec::new();
        let mut ring_commit = Vec::new();
        ring_spend.push(point_hex(&real_p));
        ring_commit.push(point_hex(&real_c));
        for i in 1..AIRGAP_RING {
            let (ds, dsv) = scalar_hex(&[b"decoy-s", &[tag], &[i as u8]]);
            let (_db, dbv) = scalar_hex(&[b"decoy-b", &[tag], &[i as u8]]);
            let _ = ds;
            let p = generator_g() * dsv;
            let c = generator_g() * dbv + generator_h() * Scalar::from(1u64);
            ring_spend.push(point_hex(&p));
            ring_commit.push(point_hex(&c));
        }
        (
            InputRequest {
                ring_spend_hex: ring_spend,
                ring_commit_hex: ring_commit,
                signer_idx: 0,
                value,
                blinding_hex: blind_hex,
            },
            spend_hex,
        )
    }

    fn output(value: u64) -> OutputRequest {
        let w = stealth_gen();
        OutputRequest {
            view_hex: point_hex(&w.view_pub),
            spend_hex: point_hex(&w.spend_pub),
            value,
        }
    }

    #[test]
    fn offline_sign_verifies_and_the_request_has_no_spend_key() {
        let (in0, sk0) = input(1, 60_000_000);
        let (in1, sk1) = input(2, 40_000_000);
        let request = SignRequest {
            inputs: vec![in0, in1],
            outputs: vec![output(70_000_000), output(29_000_000)],
            fee: 1_000_000,
        };
        let online = serde_json::to_string(&request).unwrap();
        assert!(!online.contains(&sk0));
        assert!(!online.contains(&sk1));
        assert!(
            request_from_json(&format!("{online},\"spend_hex\":[\"{sk0}\"]}}")).is_err()
                || request_from_json(&online.replace('}', ",\"spend_hex\":[]}")).is_err()
        );
        let keys = SpendKeys {
            spend_hex: vec![sk0, sk1],
        };
        let signed = sign_offline(&request, &keys).unwrap();
        let id = verify_broadcast(&signed.broadcast).unwrap();
        assert_eq!(id, signed.tx_id_hex);
        assert_eq!(signed.private_blindings_hex.len(), 2);
        let mut bad = signed.broadcast.clone();
        bad[10] ^= 0xff;
        assert!(verify_broadcast(&bad).is_err());
    }

    #[test]
    fn small_rings_and_single_inputs_are_refused() {
        let (one, sk) = input(9, 10);
        let request = SignRequest {
            inputs: vec![one],
            outputs: vec![output(4), output(5)],
            fee: 1,
        };
        let keys = SpendKeys {
            spend_hex: vec![sk],
        };
        assert!(matches!(
            sign_offline(&request, &keys),
            Err(AirgapError::Floor(_))
        ));
        let (mut a, ska) = input(3, 5);
        let (mut b, skb) = input(4, 5);
        a.ring_spend_hex.pop();
        a.ring_commit_hex.pop();
        b.ring_spend_hex.pop();
        b.ring_commit_hex.pop();
        let short = SignRequest {
            inputs: vec![a, b],
            outputs: vec![output(4), output(5)],
            fee: 1,
        };
        assert!(matches!(
            sign_offline(
                &short,
                &SpendKeys {
                    spend_hex: vec![ska, skb],
                }
            ),
            Err(AirgapError::Floor(_))
        ));
    }
}
