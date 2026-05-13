//! Decoy-pool construction for transfer building.
//!
//! `mfn_crypto::select_gamma_decoys` works over an explicit
//! `&[DecoyCandidate<T>]` that the *caller* assembles. This module
//! provides the canonical builder that walks a [`ChainState`]'s UTXO
//! set, drops anything we don't want a real input to anonymize with
//! (our own UTXOs, the input we're spending right now), and returns a
//! pool ready to feed the gamma sampler.
//!
//! The pool is parameterised over `T = (one_time_addr, amount_commit)`
//! — that's exactly what each ring slot needs to fill `(P_i, C_i)`. The
//! returned `Vec` is **sorted by height ascending**, the invariant that
//! `select_gamma_decoys` documents.

use std::collections::HashSet;

use curve25519_dalek::edwards::EdwardsPoint;
use mfn_consensus::ChainState;
use mfn_crypto::DecoyCandidate;

use crate::owned::OwnedOutput;

/// Tuple stored inside each [`DecoyCandidate`]: the on-chain
/// one-time-address `P` and Pedersen commitment `C`. These two are
/// exactly what each CLSAG ring slot consumes.
pub type RingMember = (EdwardsPoint, EdwardsPoint);

/// Builder for decoy candidate pools.
///
/// Caller drives the build by calling [`exclude_one_time_addr`] for
/// each address that should never end up in a ring (e.g. the real
/// input we're about to spend, or any other owned output we don't want
/// to risk colliding with), then calls [`build`] to produce a sorted
/// `Vec<DecoyCandidate<RingMember>>`.
///
/// [`exclude_one_time_addr`]: DecoyPoolBuilder::exclude_one_time_addr
/// [`build`]: DecoyPoolBuilder::build
#[derive(Default)]
pub struct DecoyPoolBuilder {
    excludes: HashSet<[u8; 32]>,
}

impl DecoyPoolBuilder {
    /// Empty builder.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a one-time-address to the exclusion set.
    ///
    /// Returns `&mut self` for chaining.
    pub fn exclude_one_time_addr(&mut self, key: [u8; 32]) -> &mut Self {
        self.excludes.insert(key);
        self
    }

    /// Bulk-exclude every key image / one-time-address in an iterator
    /// (matched against the `one_time_addr` key, NOT key images).
    pub fn exclude_keys<I>(&mut self, keys: I) -> &mut Self
    where
        I: IntoIterator<Item = [u8; 32]>,
    {
        self.excludes.extend(keys);
        self
    }

    /// Bulk-exclude every owned output's `one_time_addr`. Use this to
    /// avoid sampling our *own* UTXOs as decoys for our *own* spend —
    /// not a soundness violation, but it slightly weakens the
    /// anonymity set when we spend one of them later.
    pub fn exclude_owned<'a, I>(&mut self, owned: I) -> &mut Self
    where
        I: IntoIterator<Item = &'a OwnedOutput>,
    {
        for o in owned {
            self.excludes.insert(o.utxo_key());
        }
        self
    }

    /// Build the candidate pool from a [`ChainState`] UTXO set.
    ///
    /// The result is sorted by height ascending as
    /// [`mfn_crypto::select_gamma_decoys`] requires. Excluded keys are
    /// filtered out *before* sorting.
    pub fn build(&self, state: &ChainState) -> Vec<DecoyCandidate<RingMember>> {
        let mut pool: Vec<DecoyCandidate<RingMember>> = state
            .utxo
            .iter()
            .filter(|(k, _)| !self.excludes.contains(*k))
            .filter_map(|(k, entry)| {
                let mut buf = [0u8; 32];
                buf.copy_from_slice(k);
                let p = match curve25519_dalek::edwards::CompressedEdwardsY(buf).decompress() {
                    Some(p) => p,
                    None => return None,
                };
                Some(DecoyCandidate {
                    height: u64::from(entry.height),
                    data: (p, entry.commit),
                })
            })
            .collect();
        pool.sort_by_key(|c| c.height);
        pool
    }
}

/// Free-function shorthand for the common case: build a pool from a
/// `ChainState`, excluding the wallet's own outputs and a specific
/// real input.
pub fn build_decoy_pool<'a, I>(
    state: &ChainState,
    owned: I,
    real_input_utxo_key: Option<[u8; 32]>,
) -> Vec<DecoyCandidate<RingMember>>
where
    I: IntoIterator<Item = &'a OwnedOutput>,
{
    let mut b = DecoyPoolBuilder::new();
    b.exclude_owned(owned);
    if let Some(k) = real_input_utxo_key {
        b.exclude_one_time_addr(k);
    }
    b.build(state)
}
