//! The discovery card.

use mfn_crypto::{
    decode_schnorr_signature, encode_schnorr_signature, point_to_bytes, schnorr_sign,
    schnorr_verify, SchnorrKeypair,
};
use thiserror::Error;

/// How to find a copy of the software without a domain.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DiscoveryCard {
    /// v3 onion gateways, `name.onion` or `name.onion:port`.
    pub onions: Vec<String>,
    /// `magnet:?xt=urn:btih:` links.
    pub magnets: Vec<String>,
    /// Optional SHA-256 of a source bundle. Empty if unknown.
    pub source_sha256: String,
    /// Signer. Checked against the key you were shown, not against this field alone.
    pub signer: [u8; 32],
    /// Signature over [`Self::canonical`].
    pub signature: [u8; 64],
}

/// Why a card was refused.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum CardError {
    /// The card has no onion and no magnet.
    #[error("a discovery card needs an onion gateway or a magnet")]
    NoIndependentLocation,
    /// A location is not an onion or a magnet.
    #[error("bad location: {0}")]
    BadLocation(String),
    /// The signature does not match.
    #[error("signature does not match")]
    BadSignature,
    /// The signer is not the key that was shown in person.
    #[error("signer is not the key that was shown")]
    WrongSigner,
}

impl DiscoveryCard {
    /// Bytes that are signed. Locations are sorted.
    pub fn canonical(&self) -> Result<String, CardError> {
        let mut onions = Vec::new();
        for onion in &self.onions {
            onions.push(normalize_onion(onion)?);
        }
        onions.sort();
        onions.dedup();
        let mut magnets = Vec::new();
        for magnet in &self.magnets {
            magnets.push(normalize_magnet(magnet)?);
        }
        magnets.sort();
        magnets.dedup();
        if onions.is_empty() && magnets.is_empty() {
            return Err(CardError::NoIndependentLocation);
        }
        if !self.source_sha256.is_empty()
            && (self.source_sha256.len() != 64
                || !self.source_sha256.chars().all(|c| c.is_ascii_hexdigit()))
        {
            return Err(CardError::BadLocation("source_sha256".into()));
        }
        let mut out = String::from("permawrite-discovery v1\n");
        for onion in &onions {
            out.push_str("onion ");
            out.push_str(onion);
            out.push('\n');
        }
        for magnet in &magnets {
            out.push_str("magnet ");
            out.push_str(magnet);
            out.push('\n');
        }
        if !self.source_sha256.is_empty() {
            out.push_str("source_sha256 ");
            out.push_str(&self.source_sha256.to_ascii_lowercase());
            out.push('\n');
        }
        Ok(out)
    }
}

/// Sign a card. Website URLs are not a location this function accepts.
pub fn sign_card(
    onions: Vec<String>,
    magnets: Vec<String>,
    source_sha256: &str,
    key: &SchnorrKeypair,
) -> Result<DiscoveryCard, CardError> {
    let mut card = DiscoveryCard {
        onions,
        magnets,
        source_sha256: source_sha256.to_string(),
        signer: point_to_bytes(&key.pub_key),
        signature: [0u8; 64],
    };
    let body = card.canonical()?;
    card.signature = encode_schnorr_signature(&schnorr_sign(body.as_bytes(), key));
    card.onions.sort();
    card.magnets.sort();
    Ok(card)
}

/// Check the card against `expected_signer`.
pub fn verify_card(card: &DiscoveryCard, expected_signer: &[u8; 32]) -> Result<(), CardError> {
    if &card.signer != expected_signer {
        return Err(CardError::WrongSigner);
    }
    let body = card.canonical()?;
    let point = mfn_crypto::point_from_bytes(&card.signer).map_err(|_| CardError::BadSignature)?;
    let sig = decode_schnorr_signature(&card.signature).map_err(|_| CardError::BadSignature)?;
    if !schnorr_verify(body.as_bytes(), &sig, &point) {
        return Err(CardError::BadSignature);
    }
    Ok(())
}

fn normalize_onion(value: &str) -> Result<String, CardError> {
    if looks_like_website(value) {
        return Err(CardError::NoIndependentLocation);
    }
    let (host, port) = match value.rsplit_once(':') {
        Some((host, port)) if host.ends_with(".onion") => (host, Some(parse_port(port, value)?)),
        _ => (value, None),
    };
    let name = host
        .strip_suffix(".onion")
        .ok_or_else(|| CardError::BadLocation(value.into()))?;
    if name.len() != 56 || !name.bytes().all(|b| matches!(b, b'a'..=b'z' | b'2'..=b'7')) {
        return Err(CardError::BadLocation(value.into()));
    }
    Ok(format!("{name}.onion:{}", port.unwrap_or(80)))
}

fn normalize_magnet(value: &str) -> Result<String, CardError> {
    if looks_like_website(value) {
        return Err(CardError::NoIndependentLocation);
    }
    let rest = value
        .strip_prefix("magnet:?xt=urn:btih:")
        .ok_or_else(|| CardError::BadLocation(value.into()))?;
    let infohash = rest.split('&').next().unwrap_or(rest);
    if infohash.len() != 40 || !infohash.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(CardError::BadLocation(value.into()));
    }
    Ok(format!(
        "magnet:?xt=urn:btih:{}",
        infohash.to_ascii_lowercase()
    ))
}

fn looks_like_website(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    lower.contains("github.com")
        || lower.starts_with("https://")
        || lower.starts_with("http://")
        || lower.contains("0.0.0.0")
}

fn parse_port(text: &str, original: &str) -> Result<u16, CardError> {
    let port: u16 = text
        .parse()
        .map_err(|_| CardError::BadLocation(original.into()))?;
    if port == 0 {
        return Err(CardError::BadLocation(original.into()));
    }
    Ok(port)
}

#[cfg(test)]
mod tests {
    use super::*;
    use mfn_crypto::schnorr_keygen;

    fn onion() -> String {
        format!("{}.onion:80", "b".repeat(56))
    }

    #[test]
    fn onion_and_magnet_verify_and_a_website_does_not() {
        let key = schnorr_keygen();
        let card = sign_card(
            vec![onion()],
            vec!["magnet:?xt=urn:btih:0123456789abcdef0123456789abcdef01234567".into()],
            "",
            &key,
        )
        .unwrap();
        verify_card(&card, &card.signer).unwrap();
        let err = sign_card(
            vec!["https://github.com/shanecloonan/permawrite".into()],
            vec![],
            "",
            &key,
        );
        assert_eq!(err.unwrap_err(), CardError::NoIndependentLocation);
    }

    #[test]
    fn a_changed_onion_fails_the_signature() {
        let key = schnorr_keygen();
        let mut card = sign_card(vec![onion()], vec![], "", &key).unwrap();
        verify_card(&card, &card.signer).unwrap();
        card.onions[0] = format!("{}.onion:80", "c".repeat(56));
        assert_eq!(
            verify_card(&card, &card.signer),
            Err(CardError::BadSignature)
        );
        let other = schnorr_keygen();
        let card = sign_card(vec![onion()], vec![], "", &key).unwrap();
        assert_eq!(
            verify_card(&card, &point_to_bytes(&other.pub_key)),
            Err(CardError::WrongSigner)
        );
    }
}
