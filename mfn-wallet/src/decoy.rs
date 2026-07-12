//! Decoy-pool construction for transfer building.
//!
//! `mfn_crypto::select_gamma_decoys` works over an explicit
//! `&[DecoyCandidate<T>]` that the *caller* assembles. This module
//! provides the canonical builder that walks a [`ChainState`]'s UTXO
//! set, drops the real input(s) of the current transaction (so a UTXO is
//! never sampled as a decoy for its own spend), and returns a pool ready
//! to feed the gamma sampler. Other owned outputs **remain eligible** —
//! excluding every wallet UTXO globally under-represented them in rings
//! network-wide (B4 / `PRIVACY_HARDENING.md`).
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

/// One public UTXO row for decoy sampling (browser / light-client supplied).
#[derive(Clone, Copy, Debug)]
pub struct UtxoDecoySource {
    /// Height that credited this output.
    pub height: u32,
    /// On-chain one-time address `P`.
    pub one_time_addr: EdwardsPoint,
    /// Pedersen commitment `C`.
    pub commit: EdwardsPoint,
}

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

    /// Bulk-exclude every owned output's `one_time_addr`. Prefer
    /// [`build_decoy_pool`] with only the real input keys instead —
    /// excluding all owned outputs weakens the global anonymity set.
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

    /// Build a decoy pool from an explicit UTXO list (e.g. RPC / checkpoint
    /// export) instead of a live [`ChainState`].
    pub fn build_from_sources(
        &self,
        sources: &[UtxoDecoySource],
    ) -> Vec<DecoyCandidate<RingMember>> {
        let mut pool: Vec<DecoyCandidate<RingMember>> = sources
            .iter()
            .filter(|s| {
                !self
                    .excludes
                    .contains(&s.one_time_addr.compress().to_bytes())
            })
            .map(|s| DecoyCandidate {
                height: u64::from(s.height),
                data: (s.one_time_addr, s.commit),
            })
            .collect();
        pool.sort_by_key(|c| c.height);
        pool
    }
}

/// Free-function shorthand: build a pool from a `ChainState`, excluding
/// only the real input(s) of this transaction.
///
/// Every key in `exclude_utxo_keys` is removed from the candidate set so
/// a UTXO is never sampled as a decoy for its own spend. **Other owned
/// outputs remain eligible** — excluding all wallet UTXOs globally
/// under-represented them in rings network-wide (B4 /
/// `PRIVACY_HARDENING.md`).
pub fn build_decoy_pool(
    state: &ChainState,
    exclude_utxo_keys: impl IntoIterator<Item = [u8; 32]>,
) -> Vec<DecoyCandidate<RingMember>> {
    let mut b = DecoyPoolBuilder::new();
    b.exclude_keys(exclude_utxo_keys);
    b.build(state)
}

/// Build a decoy pool from public UTXO rows, excluding `exclude_keys`.
pub fn build_decoy_pool_from_sources(
    sources: &[UtxoDecoySource],
    exclude_keys: impl IntoIterator<Item = [u8; 32]>,
) -> Vec<DecoyCandidate<RingMember>> {
    let mut b = DecoyPoolBuilder::new();
    b.exclude_keys(exclude_keys);
    b.build_from_sources(sources)
}

#[cfg(test)]
mod tests {
    use super::*;
    use mfn_crypto::point::{generator_g, generator_h};
    use mfn_crypto::scalar::random_scalar;

    #[test]
    fn build_from_sources_respects_excludes_and_sorts() {
        let s0 = UtxoDecoySource {
            height: 5,
            one_time_addr: generator_g() * random_scalar(),
            commit: generator_h() * random_scalar(),
        };
        let s1 = UtxoDecoySource {
            height: 2,
            one_time_addr: generator_g() * random_scalar(),
            commit: generator_h() * random_scalar(),
        };
        let key0 = s0.one_time_addr.compress().to_bytes();
        let pool = build_decoy_pool_from_sources(&[s0, s1], [key0]);
        assert_eq!(pool.len(), 1);
        assert_eq!(pool[0].height, 2);
    }

    #[test]
    fn build_decoy_pool_excludes_only_spent_inputs() {
        use curve25519_dalek::scalar::Scalar;
        use mfn_consensus::{
            apply_genesis, build_genesis, GenesisConfig, GenesisOutput, DEFAULT_EMISSION_PARAMS,
            TEST_CONSENSUS_PARAMS,
        };
        use mfn_crypto::point::{generator_g, generator_h};
        use mfn_storage::DEFAULT_ENDOWMENT_PARAMS;

        let sp0 = random_scalar();
        let sp1 = random_scalar();
        let p0 = generator_g() * sp0;
        let p1 = generator_g() * sp1;
        let c0 = (generator_g() * random_scalar()) + (generator_h() * Scalar::from(100u64));
        let c1 = (generator_g() * random_scalar()) + (generator_h() * Scalar::from(200u64));
        let cfg = GenesisConfig {
            timestamp: 0,
            initial_outputs: vec![
                GenesisOutput {
                    one_time_addr: p0,
                    amount: c0,
                },
                GenesisOutput {
                    one_time_addr: p1,
                    amount: c1,
                },
            ],
            initial_storage: Vec::new(),
            initial_storage_operators: Vec::new(),
            validators: Vec::new(),
            params: TEST_CONSENSUS_PARAMS,
            emission_params: DEFAULT_EMISSION_PARAMS,
            endowment_params: DEFAULT_ENDOWMENT_PARAMS,
            bonding_params: None,
            header_version: 1,
        };
        let g = build_genesis(&cfg);
        let state = apply_genesis(&g, &cfg).expect("genesis");
        let key_spent = p0.compress().to_bytes();
        let key_unspent = p1.compress().to_bytes();

        let pool = build_decoy_pool(&state, [key_spent]);
        assert!(
            pool.iter()
                .any(|c| c.data.0.compress().to_bytes() == key_unspent),
            "unspent owned output must remain in the decoy pool"
        );
        assert!(
            !pool
                .iter()
                .any(|c| c.data.0.compress().to_bytes() == key_spent),
            "real input must be excluded"
        );
    }
}
