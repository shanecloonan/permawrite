//! Finality bitmap extraction.

#![allow(unused_imports)]

use super::internal::*;

/* ----------------------------------------------------------------------- *
 *  Bitmap extractor                                                         *
 * ----------------------------------------------------------------------- */

/// Extract the finality bitmap from a [`BlockHeader`]'s `producer_proof`.
///
/// Returns `None` for genesis-style headers (empty `producer_proof`)
/// and for headers whose `producer_proof` fails to decode (light
/// clients should normally have already caught this through
/// [`crate::verify_header`]).
///
/// Light clients use this to drive [`apply_liveness_evolution`]
/// without having to decode the finality proof themselves.
#[must_use]
pub fn finality_bitmap_from_header(header: &BlockHeader) -> Option<Vec<u8>> {
    if header.producer_proof.is_empty() {
        return None;
    }
    crate::consensus::decode_finality_proof(&header.producer_proof)
        .ok()
        .map(|fp| fp.finality.bitmap)
}

/* ----------------------------------------------------------------------- *
 *  Unit tests                                                               *
 * ----------------------------------------------------------------------- */
