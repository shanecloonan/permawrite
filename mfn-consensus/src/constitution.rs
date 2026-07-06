//! Constitutional invariants — the fork-legitimacy test (**F5:PM13**).
//!
//! Permanence is a promise about *governance*, not just disks. This module
//! defines the small set of invariants that reference clients hard-refuse
//! to violate **regardless of any future fork or parameter vote**. A chain
//! that violates one of these is, by definition, not Permawrite — the same
//! way a chain without the 21M cap is not Bitcoin. Ossification here is
//! codified rather than cultural.
//!
//! ## The invariants
//!
//! 1. **`tail_emission > 0`** — storage providers must be paid *forever*
//!    to hold *forever* data. Enforced by
//!    [`validate_emission_params`](crate::validate_emission_params)
//!    (`EmissionError::ZeroTail`), which this check includes wholesale.
//! 2. **Uniform CLSAG rings of at least
//!    [`CONSTITUTIONAL_MIN_RING_SIZE`]** — every spend's anonymity floor.
//!    Both `min_ring_size` and `uniform_ring_size` must be ≥ 16; a genesis
//!    that disables ring uniformity (`uniform_ring_size == 0`) or lowers
//!    the floor partitions the anonymity set and is rejected. Raising the
//!    ring size is constitutional; lowering it is not.
//! 3. **Endowment parameters must be well-formed** — the pricing function
//!    that funds permanence can never be degenerate
//!    ([`mfn_storage::validate_endowment_params`]).
//! 4. **Storage state is never prunable and endowment funds are never
//!    confiscatable** — these are *code-path* invariants rather than
//!    parameters: `ChainState.storage` has no removal path anywhere in
//!    [`apply_block`](crate::apply_block) (entries are only inserted and
//!    updated), and the treasury/endowment settlement in Phase 4 only pays
//!    *out* per accepted proof — no code path reassigns or zeroes an
//!    anchored commitment's funding. The M5 proptest suite pins both
//!    behaviors; any change that introduces a removal or confiscation path
//!    must be treated as a constitution violation in review.
//!
//! ## Where this is enforced
//!
//! [`validate_constitution`] runs when a node materializes a chain from an
//! operator-supplied genesis spec
//! (`mfn_runtime::genesis_spec::genesis_config_from_json_bytes`), i.e. on
//! every `mfnd` startup path. Test harnesses that deliberately use
//! sub-constitutional parameters (`TEST_CONSENSUS_PARAMS`, ring-2 rings)
//! construct `GenesisConfig` programmatically and are unaffected — but no
//! production entry point accepts them.

use crate::block::ConsensusParams;
use crate::emission::{validate_emission_params, EmissionError, EmissionParams};
use mfn_storage::{validate_endowment_params, EndowmentError, EndowmentParams};

/// The constitutional CLSAG ring-size floor. Forks may raise the uniform
/// ring size (privacy Tier 2); no legitimate fork may lower it below 16
/// or disable uniformity.
pub const CONSTITUTIONAL_MIN_RING_SIZE: u32 = 16;

/// A genesis/upgrade configuration violated a constitutional invariant.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ConstitutionError {
    /// Monetary policy violates a permanence invariant (e.g. zero tail
    /// emission).
    #[error("emission params unconstitutional: {0}")]
    Emission(#[from] EmissionError),

    /// Endowment pricing parameters are degenerate.
    #[error("endowment params unconstitutional: {0}")]
    Endowment(#[from] EndowmentError),

    /// Ring policy is below the constitutional floor: both
    /// `min_ring_size` and `uniform_ring_size` must be at least
    /// [`CONSTITUTIONAL_MIN_RING_SIZE`] (uniformity may not be disabled).
    #[error(
        "ring policy unconstitutional: min_ring_size={min_ring_size}, \
         uniform_ring_size={uniform_ring_size}; both must be >= {CONSTITUTIONAL_MIN_RING_SIZE}"
    )]
    RingFloor {
        /// Configured minimum ring size.
        min_ring_size: u32,
        /// Configured uniform ring size (`0` = uniformity disabled).
        uniform_ring_size: u32,
    },
}

/// Validate the constitutional invariants over a full parameter set.
///
/// Reference clients call this before accepting any genesis (or future
/// consensus-version upgrade) so that no deployment of this codebase can
/// ever run a chain that pays storage nothing in the long run, spends
/// behind sub-uniform rings, or prices endowments degenerately.
///
/// # Errors
///
/// [`ConstitutionError`] naming the first violated invariant.
pub fn validate_constitution(
    params: &ConsensusParams,
    emission: &EmissionParams,
    endowment: &EndowmentParams,
) -> Result<(), ConstitutionError> {
    validate_emission_params(emission)?;
    validate_endowment_params(endowment)?;
    if params.min_ring_size < CONSTITUTIONAL_MIN_RING_SIZE
        || params.uniform_ring_size < CONSTITUTIONAL_MIN_RING_SIZE
    {
        return Err(ConstitutionError::RingFloor {
            min_ring_size: params.min_ring_size,
            uniform_ring_size: params.uniform_ring_size,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block::{DEFAULT_CONSENSUS_PARAMS, TEST_CONSENSUS_PARAMS};
    use crate::emission::DEFAULT_EMISSION_PARAMS;
    use mfn_storage::DEFAULT_ENDOWMENT_PARAMS;

    #[test]
    fn default_production_params_are_constitutional() {
        assert_eq!(
            validate_constitution(
                &DEFAULT_CONSENSUS_PARAMS,
                &DEFAULT_EMISSION_PARAMS,
                &DEFAULT_ENDOWMENT_PARAMS,
            ),
            Ok(())
        );
    }

    #[test]
    fn test_params_are_deliberately_unconstitutional() {
        // TEST_CONSENSUS_PARAMS (ring 2, uniformity off) exist for unit
        // tests only; the constitution must reject them so they can never
        // reach a production genesis.
        assert_eq!(
            validate_constitution(
                &TEST_CONSENSUS_PARAMS,
                &DEFAULT_EMISSION_PARAMS,
                &DEFAULT_ENDOWMENT_PARAMS,
            ),
            Err(ConstitutionError::RingFloor {
                min_ring_size: 2,
                uniform_ring_size: 0,
            })
        );
    }

    #[test]
    fn zero_tail_emission_is_unconstitutional() {
        let mut emission = DEFAULT_EMISSION_PARAMS;
        emission.tail_emission = 0;
        assert_eq!(
            validate_constitution(
                &DEFAULT_CONSENSUS_PARAMS,
                &emission,
                &DEFAULT_ENDOWMENT_PARAMS
            ),
            Err(ConstitutionError::Emission(EmissionError::ZeroTail))
        );
    }

    #[test]
    fn disabling_ring_uniformity_is_unconstitutional() {
        let mut params = DEFAULT_CONSENSUS_PARAMS;
        params.uniform_ring_size = 0;
        assert!(matches!(
            validate_constitution(&params, &DEFAULT_EMISSION_PARAMS, &DEFAULT_ENDOWMENT_PARAMS),
            Err(ConstitutionError::RingFloor {
                uniform_ring_size: 0,
                ..
            })
        ));
    }

    #[test]
    fn lowering_the_ring_floor_is_unconstitutional() {
        let mut params = DEFAULT_CONSENSUS_PARAMS;
        params.min_ring_size = 8;
        params.uniform_ring_size = 8;
        assert!(matches!(
            validate_constitution(&params, &DEFAULT_EMISSION_PARAMS, &DEFAULT_ENDOWMENT_PARAMS),
            Err(ConstitutionError::RingFloor {
                min_ring_size: 8,
                uniform_ring_size: 8,
            })
        ));
    }

    #[test]
    fn raising_the_ring_size_is_constitutional() {
        // Tier 2 (ring 32-64) must pass — only lowering is forbidden.
        let mut params = DEFAULT_CONSENSUS_PARAMS;
        params.min_ring_size = 32;
        params.uniform_ring_size = 32;
        assert_eq!(
            validate_constitution(&params, &DEFAULT_EMISSION_PARAMS, &DEFAULT_ENDOWMENT_PARAMS),
            Ok(())
        );
    }
}
