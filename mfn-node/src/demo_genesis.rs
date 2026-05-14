//! Demonstration [`GenesisConfig`] for local single-node tooling.
//!
//! This is the fixed empty-validator genesis used by the [`crate::mfnd_main`]
//! reference binary so operators can boot a chain without supplying a
//! separate genesis file yet. **It is not appropriate for production
//! networks** — production deployments must load a deployment-specific
//! genesis from an out-of-band config source (JSON file, embedded
//! chain-spec, …) so every participant agrees on initial validators,
//! params, and timestamp.

use mfn_consensus::{ConsensusParams, GenesisConfig, DEFAULT_EMISSION_PARAMS};
use mfn_storage::DEFAULT_ENDOWMENT_PARAMS;

/// Empty-validator genesis with default emission and endowment params.
///
/// Matches the empty genesis harness used throughout `mfn-node` unit
/// tests so checkpoint round-trips and daemon smoke tests stay aligned.
#[must_use]
pub fn empty_local_dev_genesis() -> GenesisConfig {
    GenesisConfig {
        timestamp: 0,
        initial_outputs: Vec::new(),
        initial_storage: Vec::new(),
        validators: Vec::new(),
        params: ConsensusParams {
            expected_proposers_per_slot: 1.0,
            quorum_stake_bps: 6667,
            ..ConsensusParams::default()
        },
        emission_params: DEFAULT_EMISSION_PARAMS,
        endowment_params: DEFAULT_ENDOWMENT_PARAMS,
        bonding_params: None,
    }
}
