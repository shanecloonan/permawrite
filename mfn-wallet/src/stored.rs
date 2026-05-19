//! Serializable owned-output snapshots for wallet persistence (**M3.6**).

use curve25519_dalek::edwards::EdwardsPoint;
use curve25519_dalek::scalar::Scalar;
use serde::{Deserialize, Serialize};

use mfn_crypto::{bytes_to_scalar, point_from_bytes, scalar_to_bytes};

use crate::error::WalletError;
use crate::owned::OwnedOutput;

/// One owned UTXO in a form suitable for JSON wallet files.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredOwnedOutput {
    /// Compressed Edwards point hex (64 chars).
    pub one_time_addr_hex: String,
    /// Pedersen commitment point hex (64 chars).
    pub commit_hex: String,
    /// Opened value (atomic units).
    pub value: u64,
    /// Blinding scalar hex (64 chars).
    pub blinding_hex: String,
    /// One-time spend scalar hex (64 chars).
    pub one_time_spend_hex: String,
    /// Key image point hex (64 chars).
    pub key_image_hex: String,
    /// Creating transaction id hex (64 chars).
    pub tx_id_hex: String,
    /// Output index within the creating tx.
    pub output_idx: u32,
    /// Block height that credited this output.
    pub height: u32,
}

impl StoredOwnedOutput {
    /// Encode a live [`OwnedOutput`] for disk.
    pub fn from_owned(o: &OwnedOutput) -> Self {
        Self {
            one_time_addr_hex: hex::encode(o.one_time_addr.compress().to_bytes()),
            commit_hex: hex::encode(o.commit.compress().to_bytes()),
            value: o.value,
            blinding_hex: hex::encode(scalar_to_bytes(&o.blinding)),
            one_time_spend_hex: hex::encode(scalar_to_bytes(&o.one_time_spend)),
            key_image_hex: hex::encode(o.key_image.compress().to_bytes()),
            tx_id_hex: hex::encode(o.tx_id),
            output_idx: o.output_idx,
            height: o.height,
        }
    }

    /// Decode into an in-memory [`OwnedOutput`].
    pub fn to_owned(&self) -> Result<OwnedOutput, WalletError> {
        Ok(OwnedOutput {
            one_time_addr: parse_point(&self.one_time_addr_hex, "one_time_addr")?,
            commit: parse_point(&self.commit_hex, "commit")?,
            value: self.value,
            blinding: parse_scalar(&self.blinding_hex, "blinding")?,
            one_time_spend: parse_scalar(&self.one_time_spend_hex, "one_time_spend")?,
            key_image: parse_point(&self.key_image_hex, "key_image")?,
            tx_id: parse_hash32(&self.tx_id_hex, "tx_id")?,
            output_idx: self.output_idx,
            height: self.height,
        })
    }
}

fn parse_point(hex_str: &str, field: &str) -> Result<EdwardsPoint, WalletError> {
    let bytes = parse_fixed_hex::<32>(hex_str, field)?;
    point_from_bytes(&bytes).map_err(|e| WalletError::StoredOwnedDecode(format!("{field}: {e}")))
}

fn parse_scalar(hex_str: &str, field: &str) -> Result<Scalar, WalletError> {
    let bytes = parse_fixed_hex::<32>(hex_str, field)?;
    Ok(bytes_to_scalar(&bytes))
}

fn parse_hash32(hex_str: &str, field: &str) -> Result<[u8; 32], WalletError> {
    parse_fixed_hex(hex_str, field)
}

fn parse_fixed_hex<const N: usize>(hex_str: &str, field: &str) -> Result<[u8; N], WalletError> {
    let t = hex_str.trim();
    let t = t
        .strip_prefix("0x")
        .or_else(|| t.strip_prefix("0X"))
        .unwrap_or(t);
    if t.len() != N * 2 {
        return Err(WalletError::StoredOwnedDecode(format!(
            "{field} must be {} hex characters (got {})",
            N * 2,
            t.len()
        )));
    }
    let bytes =
        hex::decode(t).map_err(|e| WalletError::StoredOwnedDecode(format!("{field} hex: {e}")))?;
    bytes
        .try_into()
        .map_err(|_| WalletError::StoredOwnedDecode(format!("{field} wrong length")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::OwnedOutput;
    use curve25519_dalek::scalar::Scalar;
    use mfn_crypto::point::{generator_g, generator_h};

    fn sample_owned() -> OwnedOutput {
        let spend = Scalar::from(7u64);
        let blind = Scalar::from(11u64);
        let addr = generator_g() * spend;
        let commit = (generator_g() * blind) + (generator_h() * Scalar::from(50_000u64));
        let key_image = generator_g() * Scalar::from(13u64);
        OwnedOutput {
            one_time_addr: addr,
            commit,
            value: 50_000,
            blinding: blind,
            one_time_spend: spend,
            key_image,
            tx_id: [0x22u8; 32],
            output_idx: 0,
            height: 3,
        }
    }

    #[test]
    fn stored_owned_round_trip() {
        let o = sample_owned();
        let stored = StoredOwnedOutput::from_owned(&o);
        let back = stored.to_owned().expect("decode");
        assert_eq!(back.utxo_key(), o.utxo_key());
        assert_eq!(back.value, o.value);
        assert_eq!(back.height, o.height);
    }

    #[test]
    fn wallet_load_export_snapshot_round_trip() {
        use crate::Wallet;

        let o = sample_owned();
        let stored = vec![StoredOwnedOutput::from_owned(&o)];
        let mut wallet = Wallet::from_seed(&[3u8; 32]);
        wallet.load_owned_snapshot(&stored, 3).expect("load");
        assert_eq!(wallet.balance(), 50_000);
        assert_eq!(wallet.scan_height(), Some(3));
        let exported = wallet.export_owned_snapshot();
        assert_eq!(exported.len(), 1);
        assert_eq!(exported[0].value, 50_000);
    }
}
