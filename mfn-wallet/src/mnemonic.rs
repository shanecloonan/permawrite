//! 24-word recovery phrase for a wallet seed.
//!
//! The phrase is [BIP-39](https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki)
//! English with 256 bits of entropy (24 words). It encodes the same 32-byte
//! seed [`crate::wallet_from_seed`] uses, so writing the words down and
//! restoring them later yields the same view and spend keys.
//!
//! A 12-word phrase is rejected. User wallets are 32-byte seeds; a shorter
//! phrase would have to be stretched, and two encodings of one backup is
//! how people restore the wrong wallet.

use sha2::{Digest, Sha256};
use std::sync::OnceLock;
use thiserror::Error;

const WORD_COUNT: usize = 24;
const ENTROPY_BYTES: usize = 32;

/// Why a recovery phrase cannot be turned back into a seed.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum MnemonicError {
    /// The phrase was not exactly 24 words.
    #[error(
        "recovery phrase must be 24 English words (got {got}). Copy the words from `wallet new`, in order, separated by spaces"
    )]
    WrongWordCount {
        /// Words after splitting on whitespace.
        got: usize,
    },
    /// One word is not in the English list.
    #[error(
        "recovery phrase has a word that is not in the English list: {word}. Check the spelling and that the words are in the original order"
    )]
    UnknownWord {
        /// The word that failed the list lookup.
        word: String,
    },
    /// The checksum bits do not match the words.
    #[error(
        "recovery phrase checksum does not match. A word is wrong, duplicated, or out of order — do not guess; compare against the paper backup"
    )]
    BadChecksum,
}

/// Encode a 32-byte wallet seed as 24 English words.
pub fn mnemonic_from_seed(seed: &[u8; 32]) -> String {
    let digest = Sha256::digest(seed);
    let mut words = Vec::with_capacity(WORD_COUNT);
    let list = wordlist();
    for i in 0..WORD_COUNT {
        let start = i * 11;
        let mut index: u16 = 0;
        for bit in 0..11 {
            let pos = start + bit;
            let source = if pos < ENTROPY_BYTES * 8 {
                seed[pos / 8]
            } else {
                digest[0]
            };
            let shift = 7 - (pos % 8);
            let one = (source >> shift) & 1;
            index = (index << 1) | u16::from(one);
        }
        words.push(list[index as usize]);
    }
    words.join(" ")
}

/// Decode a 24-word phrase into the 32-byte wallet seed.
///
/// Whitespace is collapsed. Matching is case-insensitive. The checksum is
/// checked before any seed is returned, so a mistyped word cannot silently
/// open a different wallet.
pub fn seed_from_mnemonic(phrase: &str) -> Result<[u8; 32], MnemonicError> {
    let parts: Vec<&str> = phrase.split_whitespace().collect();
    if parts.len() != WORD_COUNT {
        return Err(MnemonicError::WrongWordCount { got: parts.len() });
    }
    let list = wordlist();
    let mut indexes = [0u16; WORD_COUNT];
    for (i, word) in parts.iter().enumerate() {
        let folded = word.to_ascii_lowercase();
        let found = match list.binary_search(&folded.as_str()) {
            Ok(index) => index,
            Err(_) => {
                return Err(MnemonicError::UnknownWord { word: folded });
            }
        };
        indexes[i] = u16::try_from(found).expect("wordlist index fits in u16");
    }

    let mut entropy = [0u8; ENTROPY_BYTES];
    let mut checksum_bits: u8 = 0;
    for (i, index) in indexes.iter().enumerate() {
        for bit in 0..11 {
            let pos = i * 11 + bit;
            let one = ((index >> (10 - bit)) & 1) as u8;
            if pos < ENTROPY_BYTES * 8 {
                let shift = 7 - (pos % 8);
                entropy[pos / 8] |= one << shift;
            } else {
                let shift = 7 - (pos - ENTROPY_BYTES * 8);
                checksum_bits |= one << shift;
            }
        }
    }
    let digest = Sha256::digest(entropy);
    if checksum_bits != digest[0] {
        return Err(MnemonicError::BadChecksum);
    }
    Ok(entropy)
}

fn wordlist() -> &'static [&'static str] {
    static WORDS: OnceLock<Vec<&'static str>> = OnceLock::new();
    WORDS.get_or_init(|| {
        include_str!("bip39_english.txt")
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty())
            .collect()
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn english_list_is_bip39() {
        let list = wordlist();
        assert_eq!(list.len(), 2048);
        assert_eq!(list[0], "abandon");
        assert_eq!(list[2047], "zoo");
        assert!(list.windows(2).all(|w| w[0] < w[1]));
    }

    #[test]
    fn zero_entropy_matches_the_bip39_vector() {
        let seed = [0u8; 32];
        let phrase = mnemonic_from_seed(&seed);
        assert_eq!(
            phrase,
            "abandon abandon abandon abandon abandon abandon abandon abandon \
             abandon abandon abandon abandon abandon abandon abandon abandon \
             abandon abandon abandon abandon abandon abandon abandon art"
        );
        assert_eq!(seed_from_mnemonic(&phrase).expect("decode"), seed);
    }

    #[test]
    fn seven_f_entropy_matches_the_bip39_vector() {
        let seed = [0x7f; 32];
        let phrase = mnemonic_from_seed(&seed);
        assert_eq!(
            phrase,
            "legal winner thank year wave sausage worth useful legal winner \
             thank year wave sausage worth useful legal winner thank year \
             wave sausage worth title"
        );
        assert_eq!(seed_from_mnemonic(&phrase).expect("decode"), seed);
    }

    #[test]
    fn round_trip_is_case_and_whitespace_insensitive() {
        let seed = [0x3cu8; 32];
        let phrase = mnemonic_from_seed(&seed);
        let messy = format!("  {}\n", phrase.to_ascii_uppercase().replace(' ', "  "));
        assert_eq!(seed_from_mnemonic(&messy).expect("decode"), seed);
    }

    #[test]
    fn rejects_a_swapped_word_and_a_short_phrase() {
        let phrase = mnemonic_from_seed(&[9u8; 32]);
        let mut words: Vec<&str> = phrase.split_whitespace().collect();
        words.swap(0, 1);
        let swapped = words.join(" ");
        assert_eq!(
            seed_from_mnemonic(&swapped).expect_err("checksum"),
            MnemonicError::BadChecksum
        );
        assert!(matches!(
            seed_from_mnemonic("abandon abandon"),
            Err(MnemonicError::WrongWordCount { got: 2 })
        ));
        assert!(matches!(
            seed_from_mnemonic(&format!("{phrase} notaword")),
            Err(MnemonicError::WrongWordCount { got: 25 })
        ));
        let mut broken: Vec<&str> = phrase.split_whitespace().collect();
        broken[3] = "notaword";
        let err = seed_from_mnemonic(&broken.join(" ")).expect_err("word");
        assert!(matches!(err, MnemonicError::UnknownWord { .. }));
        assert!(err.to_string().contains("notaword"));
    }
}
