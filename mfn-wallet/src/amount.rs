//! Display and parse coin amounts without changing the wire format.
//!
//! The chain counts atomic units. [`ATOMIC_PER_MFN`] matches
//! `mfn_consensus::MFN_BASE` (10<sup>8</sup>). A bare whole number stays
//! atomic so existing scripts keep working. A decimal, or a value ending
//! in `mfn`, is a coin amount. Extra decimal places are refused rather
//! than rounded, so a person cannot send a different amount than the one
//! they typed.

use thiserror::Error;

/// Atomic units in one MFN. Same value as consensus `MFN_BASE`.
pub const ATOMIC_PER_MFN: u64 = 100_000_000;

/// Decimal places in one MFN. Same value as consensus `MFN_DECIMALS`.
pub const MFN_DISPLAY_DECIMALS: u32 = 8;

/// Why an amount string was refused.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum AmountError {
    /// Blank input.
    #[error("amount is empty. Use a whole number of atomic units, or a coin amount like 1.5mfn")]
    Empty,
    /// A leading minus.
    #[error("amount cannot be negative")]
    Negative,
    /// Not a decimal number.
    #[error(
        "amount `{raw}` is not a number. Use atomic units (100000000 = 1 MFN) or a coin amount like 1.5mfn"
    )]
    NotANumber {
        /// The fragment that failed, trimmed for display.
        raw: String,
    },
    /// More fractional digits than the atomic unit can represent.
    #[error(
        "amount has more than {max} decimal places. 1 MFN = {atomic} atomic units; extra digits would change what you send"
    )]
    TooManyDecimals {
        /// Maximum fractional digits.
        max: u32,
        /// Atomic units in one MFN.
        atomic: u64,
    },
    /// The value does not fit in `u64` atomic units.
    #[error("that amount is larger than a balance can hold")]
    Overflow,
    /// A decimal was labeled atomic.
    #[error("atomic amounts are whole numbers. Use 1.5mfn when you mean coins")]
    FractionalAtomic,
}

/// Format atomic units as a fixed 8-decimal coin amount.
pub fn format_mfn(atomic: u64) -> String {
    let whole = atomic / ATOMIC_PER_MFN;
    let frac = atomic % ATOMIC_PER_MFN;
    format!("{whole}.{frac:08} MFN")
}

/// Parse a user amount into atomic units.
///
/// - `10000` and `10000 atomic` are atomic units.
/// - `1.5`, `1.5mfn`, and `1.5 MFN` are coins.
/// - A bare whole number is atomic, so old command lines do not change meaning.
pub fn parse_amount(raw: &str) -> Result<u64, AmountError> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(AmountError::Empty);
    }
    if trimmed.starts_with('-') || trimmed.starts_with('+') {
        return Err(AmountError::Negative);
    }
    let lower = trimmed.to_ascii_lowercase();
    let (body, unit) = if let Some(rest) = lower.strip_suffix("mfn") {
        (rest.trim(), Unit::Mfn)
    } else if let Some(rest) = lower.strip_suffix("atomic") {
        (rest.trim(), Unit::Atomic)
    } else if lower.contains('.') {
        (lower.as_str(), Unit::Mfn)
    } else {
        (lower.as_str(), Unit::Atomic)
    };
    if body.is_empty() {
        return Err(AmountError::Empty);
    }
    match unit {
        Unit::Atomic => parse_atomic(body),
        Unit::Mfn => parse_mfn(body),
    }
}

enum Unit {
    Atomic,
    Mfn,
}

fn parse_atomic(body: &str) -> Result<u64, AmountError> {
    if body.contains('.') {
        return Err(AmountError::FractionalAtomic);
    }
    if !body.chars().all(|c| c.is_ascii_digit()) {
        return Err(AmountError::NotANumber { raw: clip(body) });
    }
    body.parse::<u64>().map_err(|_| AmountError::Overflow)
}

fn parse_mfn(body: &str) -> Result<u64, AmountError> {
    let (whole, frac) = match body.split_once('.') {
        Some((whole, frac)) => (whole, frac),
        None => (body, ""),
    };
    if !whole.chars().all(|c| c.is_ascii_digit()) || !frac.chars().all(|c| c.is_ascii_digit()) {
        return Err(AmountError::NotANumber { raw: clip(body) });
    }
    if whole.is_empty() && frac.is_empty() {
        return Err(AmountError::NotANumber { raw: clip(body) });
    }
    if frac.len() > MFN_DISPLAY_DECIMALS as usize {
        return Err(AmountError::TooManyDecimals {
            max: MFN_DISPLAY_DECIMALS,
            atomic: ATOMIC_PER_MFN,
        });
    }
    let whole_units: u64 = if whole.is_empty() {
        0
    } else {
        whole.parse::<u64>().map_err(|_| AmountError::Overflow)?
    };
    let whole_atomic = whole_units
        .checked_mul(ATOMIC_PER_MFN)
        .ok_or(AmountError::Overflow)?;
    let mut padded = frac.to_string();
    while padded.len() < MFN_DISPLAY_DECIMALS as usize {
        padded.push('0');
    }
    let frac_atomic: u64 = if padded.is_empty() {
        0
    } else {
        padded.parse::<u64>().map_err(|_| AmountError::Overflow)?
    };
    whole_atomic
        .checked_add(frac_atomic)
        .ok_or(AmountError::Overflow)
}

fn clip(raw: &str) -> String {
    let mut out: String = raw.chars().take(64).collect();
    if raw.chars().count() > 64 {
        out.push('…');
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_shows_coins_and_keeps_atomic_dust() {
        assert_eq!(format_mfn(0), "0.00000000 MFN");
        assert_eq!(format_mfn(1), "0.00000001 MFN");
        assert_eq!(format_mfn(ATOMIC_PER_MFN), "1.00000000 MFN");
        assert_eq!(format_mfn(150_000_000), "1.50000000 MFN");
    }

    #[test]
    fn bare_integers_stay_atomic_and_mfn_suffix_is_coins() {
        assert_eq!(parse_amount("10000").expect("atomic"), 10_000);
        assert_eq!(parse_amount("10000 atomic").expect("labeled"), 10_000);
        assert_eq!(parse_amount("1mfn").expect("one"), ATOMIC_PER_MFN);
        assert_eq!(
            parse_amount("1.5 MFN").expect("one and a half"),
            150_000_000
        );
        assert_eq!(parse_amount("1.5").expect("decimal"), 150_000_000);
        assert_eq!(parse_amount(".5mfn").expect("half"), 50_000_000);
        assert_eq!(parse_amount("0.00000001mfn").expect("dust"), 1);
    }

    #[test]
    fn refuses_rounding_negatives_and_junk() {
        assert!(matches!(
            parse_amount("1.000000001mfn"),
            Err(AmountError::TooManyDecimals { .. })
        ));
        assert!(matches!(parse_amount("-1"), Err(AmountError::Negative)));
        assert!(matches!(
            parse_amount("1.5 atomic"),
            Err(AmountError::FractionalAtomic)
        ));
        assert!(matches!(
            parse_amount("lots"),
            Err(AmountError::NotANumber { .. })
        ));
        assert_eq!(parse_amount("  1.50mfn  ").expect("padded"), 150_000_000);
    }

    #[cfg(feature = "full")]
    #[test]
    fn display_unit_matches_consensus() {
        assert_eq!(ATOMIC_PER_MFN, mfn_consensus::MFN_BASE);
        assert_eq!(MFN_DISPLAY_DECIMALS, mfn_consensus::MFN_DECIMALS);
    }
}
