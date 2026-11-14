//! Plain-language wording for [`crate::WalletError`].
//!
//! The typed error stays the source of truth. This module only adds a
//! sentence a person can act on, and it never suggests shrinking a ring,
//! dropping a fee check, or attaching a memo that would make one payment
//! look different from the others.

use crate::WalletError;

/// Explain a wallet failure and the next step.
///
/// The string includes the original detail so logs stay searchable.
pub fn explain_wallet_error(err: &WalletError) -> String {
    match err {
        WalletError::NoRecipients => {
            "Name at least one recipient. A payment with nobody to pay is not sent.".into()
        }
        WalletError::StoredOwnedDecode(detail) => format!(
            "The saved wallet scan could not be read, so balances were not trusted. \
             Scan the chain again from the start. Detail: {detail}"
        ),
        WalletError::ClaimMessageTooLong { got, max } => format!(
            "The public note is {got} bytes and the limit is {max}. Shorten the note. \
             A public note names the file; it does not hide who wrote it."
        ),
        WalletError::UploadExtraConflictsWithAuthorshipClaims => {
            "Do not attach your own extra data to an upload. The wallet writes the storage \
             envelope itself. Adding another one would make this upload look different from \
             an ordinary upload."
                .into()
        }
        WalletError::TransferTxExtraNotEmpty { len } => format!(
            "A payment cannot carry a {len}-byte note. Notes on payments make them look \
             different from other payments. Send the payment with an empty note."
        ),
        WalletError::NonCanonicalTxExtra { len } => format!(
            "The extra data ({len} bytes) is not a storage envelope the network accepts. \
             The wallet will not strip it quietly, because a stripped note and a kept note \
             would split the anonymity set. Remove it and try again."
        ),
        WalletError::ClaimKeyReusesWalletKey => {
            "The name used to sign authorship is the same as a wallet key. That would tie \
             your money to a public name. Use the separate claiming key."
                .into()
        }
        WalletError::AuthorshipClaimDataRootMismatch => {
            "The authorship note does not match this file. Attach the note to the file you \
             are actually uploading."
                .into()
        }
        WalletError::AuthorshipClaimCommitHashMismatch => {
            "The authorship note does not match this upload's commitment. Attach it with \
             the upload instead of a standalone claim."
                .into()
        }
        WalletError::AuthorshipClaimMustBeUploadBound => {
            "An authorship note has to be attached to the upload. A loose note is not recorded."
                .into()
        }
        WalletError::StandaloneAuthorshipClaimDisabled => {
            "Standalone claims are off. Add the note when you upload: \
             `wallet upload FILE --message \"...\"`."
                .into()
        }
        WalletError::InsufficientFunds {
            requested,
            available,
        } => format!(
            "The wallet cannot cover this payment. It needs {requested} atomic units and can \
             spend {available}. Scan until the chain is caught up, or send less. \
             insufficient funds: requested {requested}, available {available}"
        ),
        WalletError::UnknownOwnedOutput(label) => format!(
            "That coin is not in this wallet anymore. Refresh the balance and pick a coin \
             the wallet still holds. unknown owned output: {label}"
        ),
        WalletError::RingSizeBelowMinimum { got, min } => format!(
            "The wallet will not shrink the ring from {min} to {got}. A smaller ring makes \
             the payment easier to pick out of the crowd. ring size {got} below \
             wallet/consensus floor {min}"
        ),
        WalletError::TxInputCountBelowMinimum { got, min } => format!(
            "This spend needs {min} separate coins in the wallet and only found {got}. \
             Wait for a second coin (the public faucet sends two transfers), then try again. \
             owned UTXO count {got} below F7 privacy floor {min} \
             (need a second spendable output; public faucet sends two transfers)"
        ),
        WalletError::TxInputCountNotBucket { got, pad_to } => format!(
            "This chain needs {pad_to} real coins in the spend and the wallet could gather {got}. \
             A placeholder coin is never invented. Wait until the wallet holds {pad_to} spendable \
             coins, then try again. input count {got} must be padded to {pad_to} real UTXOs \
             (this chain's header requires a power-of-two bucket)"
        ),
        WalletError::DecoyPoolTooSmall {
            ring_size,
            pool_size,
        } => format!(
            "There are not enough other outputs to fill a ring of {ring_size} (the pool has \
             {pool_size}). The wallet will not quietly use a smaller ring. Wait for more \
             outputs on the chain, then try again."
        ),
        WalletError::PedersenOpenMismatch => {
            "A scanned output decrypted but did not match its amount commitment, so it was \
             not treated as yours."
                .into()
        }
        WalletError::UploadReplicationOutOfRange { got, min, max } => format!(
            "Replication {got} is outside {min} to {max}. Pick a value in that range. \
             The network would reject the upload, and signing it first would publish the \
             coins you meant to spend."
        ),
        WalletError::UploadUnderfunded {
            fee,
            treasury_share,
            burden,
            min_fee,
        } => format!(
            "The fee is too small to pay for keeping this file. The smallest fee that works \
             is {min_fee} atomic units. Raise the fee to at least that and try again. \
             Nothing was signed. upload underfunded: fee {fee}, treasury share {treasury_share}, \
             burden {burden}, minimum fee {min_fee}"
        ),
        WalletError::UploadEndowmentExceedsU64 { burden } => format!(
            "This file is too large for the storage price to fit in one payment \
             (burden {burden}). Upload a smaller file."
        ),
        WalletError::UploadTreasuryRouteDisabled => {
            "This chain is not routing fees into storage, so no fee can pay for the file. \
             The upload was not signed."
                .into()
        }
        WalletError::Endowment(inner) => format!(
            "The storage price could not be calculated, so the upload was not signed. \
             Detail: {inner}"
        ),
        WalletError::Spora(inner) => format!(
            "The file could not be packed for storage, so nothing was signed. Detail: {inner}"
        ),
        WalletError::Crypto(inner) => {
            format!("A cryptographic step failed before anything was broadcast. Detail: {inner}")
        }
        WalletError::TxBuild(inner) => {
            format!("The payment could not be built, so it was not broadcast. Detail: {inner}")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ring_and_input_floor_say_what_to_do_and_keep_the_old_words() {
        let ring = explain_wallet_error(&WalletError::RingSizeBelowMinimum { got: 4, min: 16 });
        assert!(ring.contains("will not shrink"));
        assert!(ring.contains("wallet/consensus floor"));
        assert!(ring.contains("16"));

        let inputs =
            explain_wallet_error(&WalletError::TxInputCountBelowMinimum { got: 1, min: 2 });
        assert!(inputs.contains("F7 privacy floor"));
        assert!(inputs.contains("faucet"));
        assert!(inputs.contains("second"));
    }

    #[test]
    fn privacy_rejects_name_the_leak_they_prevent() {
        let extra = explain_wallet_error(&WalletError::TransferTxExtraNotEmpty { len: 4 });
        assert!(extra.contains("look different"));
        let decoys = explain_wallet_error(&WalletError::DecoyPoolTooSmall {
            ring_size: 16,
            pool_size: 3,
        });
        assert!(decoys.contains("will not quietly use a smaller ring"));
        let fee = explain_wallet_error(&WalletError::UploadUnderfunded {
            fee: 1,
            treasury_share: 0,
            burden: 50,
            min_fee: 100,
        });
        assert!(fee.contains("smallest fee"));
        assert!(fee.contains("100"));
        assert!(fee.contains("Nothing was signed"));
    }
}
