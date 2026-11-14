//! Spend defaults that stay at the strongest shape the chain allows.
//!
//! The wallet does not pick a smaller ring or a public fee when a stronger
//! legal shape exists. Asking for a shape the chain would reject is a
//! refusal, not a silent fallback.

use mfn_consensus::{tier2_ring_size_allowed, HEADER_VERSION_HIDDEN_FEES, HEADER_VERSION_TIER2};

use crate::error::WalletError;
use crate::WALLET_MIN_RING_SIZE;

/// What a spend will actually use.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SpendPrivacy {
    /// Ring size, including the real input.
    pub ring_size: usize,
    /// Fee is a commitment. Legal only at header version 6 and above.
    pub hidden_fee: bool,
    /// Output count is padded to at least two. This is not optional.
    pub output_padding: bool,
}

/// Choose the strongest legal spend for this chain and decoy pool.
///
/// `explicit_ring` is set only when the person named a ring. `public_fee`
/// is set only when they asked to publish the fee.
pub fn choose_spend_privacy(
    header_version: u32,
    decoy_candidates: usize,
    explicit_ring: Option<usize>,
    public_fee: bool,
) -> Result<SpendPrivacy, WalletError> {
    let hidden_fee = header_version >= HEADER_VERSION_HIDDEN_FEES;
    if public_fee && hidden_fee {
        return Err(WalletError::PrivacyRefused(
            "this chain hides fees. Refusing to publish the fee.".into(),
        ));
    }
    let ring_size = match explicit_ring {
        Some(ring) => explicit_legal_ring(header_version, decoy_candidates, ring)?,
        None => largest_legal_ring(header_version, decoy_candidates)?,
    };
    Ok(SpendPrivacy {
        ring_size,
        hidden_fee,
        output_padding: true,
    })
}

fn explicit_legal_ring(
    header_version: u32,
    decoy_candidates: usize,
    ring: usize,
) -> Result<usize, WalletError> {
    if ring < WALLET_MIN_RING_SIZE {
        return Err(WalletError::RingSizeBelowMinimum {
            got: ring,
            min: WALLET_MIN_RING_SIZE,
        });
    }
    if let Err(msg) = tier2_ring_size_allowed(header_version, ring as u32) {
        return Err(WalletError::PrivacyRefused(format!(
            "{msg}. The wallet will not substitute a different ring."
        )));
    }
    if decoy_candidates + 1 < ring {
        return Err(WalletError::PrivacyRefused(format!(
            "not enough other outputs for a ring of {ring} (pool {decoy_candidates}). The wallet will not shrink the ring."
        )));
    }
    Ok(ring)
}

fn largest_legal_ring(header_version: u32, decoy_candidates: usize) -> Result<usize, WalletError> {
    let candidates: &[usize] = if header_version >= HEADER_VERSION_TIER2 {
        &[64, 32]
    } else {
        &[WALLET_MIN_RING_SIZE]
    };
    for &ring in candidates {
        if decoy_candidates + 1 >= ring {
            return Ok(ring);
        }
    }
    let wanted = candidates[0];
    Err(WalletError::PrivacyRefused(format!(
        "not enough other outputs for the largest legal ring {wanted} (pool {decoy_candidates}). The wallet will not use a smaller ring."
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn path_a_stays_at_ring_16_and_a_public_fee() {
        let choice = choose_spend_privacy(1, 100, None, false).expect("v1");
        assert_eq!(choice.ring_size, 16);
        assert!(!choice.hidden_fee);
        assert!(choice.output_padding);
        let err = choose_spend_privacy(1, 100, Some(64), false).expect_err("no silent 16");
        assert!(err.to_string().contains("will not substitute"));
    }

    #[test]
    fn tier2_picks_64_then_32_and_refuses_to_shrink() {
        let big = choose_spend_privacy(5, 80, None, false).expect("64");
        assert_eq!(big.ring_size, 64);
        assert!(!big.hidden_fee);
        let mid = choose_spend_privacy(5, 40, None, false).expect("32");
        assert_eq!(mid.ring_size, 32);
        let err = choose_spend_privacy(5, 10, None, false).expect_err("pool");
        assert!(err.to_string().contains("will not use a smaller ring"));
    }

    #[test]
    fn hidden_fees_turn_on_at_v6_and_a_public_fee_is_refused() {
        let choice = choose_spend_privacy(6, 80, None, false).expect("v6");
        assert!(choice.hidden_fee);
        assert_eq!(choice.ring_size, 64);
        let err = choose_spend_privacy(6, 80, None, true).expect_err("public");
        assert!(err.to_string().contains("Refusing to publish"));
    }
}
