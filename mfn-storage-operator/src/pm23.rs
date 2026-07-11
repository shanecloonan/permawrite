//! PM23 operator-manifest separation startup lint (**P32** phase 4b).

use std::env;

fn env_nonempty(name: &str) -> bool {
    env::var(name)
        .ok()
        .is_some_and(|raw| !raw.trim().is_empty())
}

/// Warn when validator seed env colocates with a storage-operator process.
#[must_use]
pub fn pm23_storage_operator_env_warnings() -> Vec<String> {
    let has_validator_index = env_nonempty("MFND_VALIDATOR_INDEX");
    let has_vrf_seed = env_nonempty("MFND_VRF_SEED_HEX");
    let has_bls_seed = env_nonempty("MFND_BLS_SEED_HEX");
    if has_validator_index || has_vrf_seed || has_bls_seed {
        return vec![
            "mfn_storage_operator_pm23_warning env has MFND_VALIDATOR_INDEX or validator seed \
             hex; operator hosts must not colocate validator keys (PM23; see REFERENCE_TOPOLOGY.md)"
                .to_string(),
        ];
    }
    Vec::new()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validator_seed_env_warns() {
        env::set_var("MFND_VRF_SEED_HEX", "aa".repeat(32));
        let warnings = pm23_storage_operator_env_warnings();
        env::remove_var("MFND_VRF_SEED_HEX");
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].contains("mfn_storage_operator_pm23_warning"));
    }
}
