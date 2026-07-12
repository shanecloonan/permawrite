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

/// True when `MFN_STORAGE_OPERATOR_PM23_HARD_FAIL=1` (or `MFND_PM23_HARD_FAIL=1`) and PM23
/// warnings should abort startup.
#[must_use]
pub fn pm23_hard_fail_enabled() -> bool {
    for name in ["MFN_STORAGE_OPERATOR_PM23_HARD_FAIL", "MFND_PM23_HARD_FAIL"] {
        if env::var(name)
            .ok()
            .is_some_and(|raw| matches!(raw.trim(), "1" | "true" | "yes" | "on"))
        {
            return true;
        }
    }
    false
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

    #[test]
    fn hard_fail_reads_operator_or_mfnd_env() {
        env::remove_var("MFN_STORAGE_OPERATOR_PM23_HARD_FAIL");
        env::remove_var("MFND_PM23_HARD_FAIL");
        assert!(!pm23_hard_fail_enabled());

        env::set_var("MFN_STORAGE_OPERATOR_PM23_HARD_FAIL", "1");
        assert!(pm23_hard_fail_enabled());
        env::remove_var("MFN_STORAGE_OPERATOR_PM23_HARD_FAIL");

        env::set_var("MFND_PM23_HARD_FAIL", "yes");
        assert!(pm23_hard_fail_enabled());
        env::remove_var("MFND_PM23_HARD_FAIL");
    }
}
