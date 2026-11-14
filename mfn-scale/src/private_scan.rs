//! Local stealth scan.
//!
//! The network request is a height window. It has no view key, no spend
//! key, and no bloom filter. The wallet downloads the outputs in that
//! window and runs [`scan_owned`] on the device. Two wallets asking for
//! the same window produce the same bytes.

use mfn_crypto::{stealth_detect, StealthOutput, StealthWallet};

/// Inclusive height window. The only thing a scan asks the network for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OutputWindowRequest {
    start_height: u32,
    end_height: u32,
}

/// Why a window was rejected.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ScanError {
    /// `end_height` was below `start_height`.
    #[error("end height {end} is below start height {start}")]
    Inverted {
        /// First height.
        start: u32,
        /// Last height.
        end: u32,
    },
}

impl OutputWindowRequest {
    /// Window from `start_height` through `end_height`, inclusive.
    ///
    /// # Errors
    ///
    /// [`ScanError::Inverted`] when `end_height < start_height`.
    pub fn new(start_height: u32, end_height: u32) -> Result<Self, ScanError> {
        if end_height < start_height {
            return Err(ScanError::Inverted {
                start: start_height,
                end: end_height,
            });
        }
        Ok(Self {
            start_height,
            end_height,
        })
    }

    /// First height.
    #[must_use]
    pub fn start_height(&self) -> u32 {
        self.start_height
    }

    /// Last height.
    #[must_use]
    pub fn end_height(&self) -> u32 {
        self.end_height
    }

    /// Eight bytes: start height, then end height, both big-endian.
    ///
    /// There is no key material in this encoding.
    #[must_use]
    pub fn encode(self) -> [u8; 8] {
        let mut out = [0u8; 8];
        out[..4].copy_from_slice(&self.start_height.to_be_bytes());
        out[4..].copy_from_slice(&self.end_height.to_be_bytes());
        out
    }
}

/// Indexes of `outputs` that `wallet` can detect. Detection stays local.
#[must_use]
pub fn scan_owned(outputs: &[StealthOutput], wallet: &StealthWallet) -> Vec<usize> {
    outputs
        .iter()
        .enumerate()
        .filter_map(|(index, output)| stealth_detect(output, wallet).then_some(index))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use mfn_crypto::stealth::StealthPubKeys;
    use mfn_crypto::{point_to_bytes, stealth_gen, stealth_send_to};

    #[test]
    fn two_wallets_share_a_request_and_not_an_output_set() {
        let alice = stealth_gen();
        let bob = stealth_gen();
        let carol = stealth_gen();
        let outputs = vec![
            stealth_send_to(&StealthPubKeys::from(&alice)),
            stealth_send_to(&StealthPubKeys::from(&bob)),
            stealth_send_to(&StealthPubKeys::from(&alice)),
            stealth_send_to(&StealthPubKeys::from(&carol)),
        ];
        let alice_owned = scan_owned(&outputs, &alice);
        let bob_owned = scan_owned(&outputs, &bob);
        assert_eq!(alice_owned, vec![0, 2]);
        assert_eq!(bob_owned, vec![1]);
        assert!(alice_owned.iter().all(|index| !bob_owned.contains(index)));

        let alice_req = OutputWindowRequest::new(10, 20).expect("window");
        let bob_req = OutputWindowRequest::new(10, 20).expect("window");
        assert_eq!(alice_req.encode(), bob_req.encode());
        let mut expected = [0u8; 8];
        expected[..4].copy_from_slice(&10u32.to_be_bytes());
        expected[4..].copy_from_slice(&20u32.to_be_bytes());
        assert_eq!(alice_req.encode(), expected);
        let point = point_to_bytes(&alice.view_pub);
        assert!(
            alice_req.encode().len() < point.len(),
            "the request is shorter than a wallet point"
        );
    }

    #[test]
    fn an_inverted_window_is_refused() {
        assert_eq!(
            OutputWindowRequest::new(5, 4).unwrap_err(),
            ScanError::Inverted { start: 5, end: 4 }
        );
    }
}
