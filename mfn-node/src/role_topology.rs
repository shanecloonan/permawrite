//! Role-separated topology startup lint (**P32** phase 0).
//!
//! Warn when validator, storage-operator, and public wallet RPC surfaces
//! colocate on the same advertised host in one `mfnd serve` process.

use mfn_runtime::Chain;
use mfn_storage::operator_identity_from_payout;

/// Extract normalized listen host from `HOST:PORT` (or bracketed IPv6).
#[must_use]
pub fn normalized_listen_host(addr: &str) -> Option<String> {
    let trimmed = addr.trim();
    let host = if trimmed.starts_with('[') {
        let end = trimmed.find(']')?;
        trimmed.get(1..end)?.to_string()
    } else {
        trimmed.rsplit_once(':')?.0.to_string()
    };
    let host = host.trim();
    if host.is_empty() {
        return None;
    }
    let normalized = match host {
        "0.0.0.0" | "::" | "[::]" => "unspecified".to_string(),
        other => other.to_ascii_lowercase(),
    };
    Some(normalized)
}

/// True when `addr` binds loopback-only (wallet RPC should stay here in production).
#[must_use]
pub fn listen_is_loopback(addr: &str) -> bool {
    let Some(host) = normalized_listen_host(addr) else {
        return false;
    };
    host == "localhost"
        || host == "::1"
        || host.starts_with("127.")
        || host == "unspecified" && addr.contains("127.")
}

/// True when the local validator payout is registered as a storage operator.
#[must_use]
pub fn chain_validator_is_storage_operator(chain: &Chain, validator_index: u32) -> bool {
    let Some(validator) = chain
        .validators()
        .iter()
        .find(|v| v.index == validator_index)
    else {
        return false;
    };
    let Some(payout) = validator.payout.as_ref() else {
        return false;
    };
    let op_id = operator_identity_from_payout(&payout.view_pub, &payout.spend_pub);
    chain.state().storage_operators.contains_key(&op_id)
}

/// Read optional `MFND_VALIDATOR_INDEX` for topology checks before producer env validation.
#[must_use]
pub fn validator_index_from_env() -> Option<u32> {
    std::env::var("MFND_VALIDATOR_INDEX")
        .ok()
        .and_then(|raw| raw.trim().parse().ok())
}

/// Warn when ≥2 of {validator, operator, wallet_rpc} colocate on the same advertised host.
#[must_use]
pub fn role_topology_colocation_warning(
    produce: bool,
    committee_vote: bool,
    rpc_listen: &str,
    p2p_listen: Option<&str>,
    is_storage_operator: bool,
) -> Option<String> {
    let validator = produce || committee_vote;
    let wallet_rpc = !listen_is_loopback(rpc_listen);
    if !validator || !wallet_rpc {
        return None;
    }

    let mut roles = vec!["validator", "wallet_rpc"];
    if is_storage_operator {
        roles.push("operator");
    }
    if roles.len() < 2 {
        return None;
    }

    let rpc_host = normalized_listen_host(rpc_listen)?;
    let p2p_host = p2p_listen.and_then(normalized_listen_host);
    let same_advertised = match p2p_host.as_deref() {
        None => true,
        Some(p) => p == rpc_host,
    };
    if !same_advertised {
        return None;
    }

    Some(format!(
        "mfnd_role_topology_warning roles={} rpc_listen={rpc_listen} p2p_listen={} host={rpc_host}; split validator, operator, and wallet RPC across hosts (P32)",
        roles.join("+"),
        p2p_listen.unwrap_or("none")
    ))
}

/// Hint when a non-validator node advertises public P2P but keeps RPC loopback-only.
///
/// Community observers typically expose public RPC for wallets; loopback-only is fine on
/// local devnet meshes where both listeners bind `127.0.0.1`.
#[must_use]
pub fn observer_loopback_rpc_hint_warning(
    produce: bool,
    committee_vote: bool,
    rpc_listen: &str,
    p2p_listen: Option<&str>,
) -> Option<String> {
    if produce || committee_vote {
        return None;
    }
    if !listen_is_loopback(rpc_listen) {
        return None;
    }
    let p2p = p2p_listen?;
    if listen_is_loopback(p2p) {
        return None;
    }
    Some(format!(
        "mfnd_role_topology_warning roles=observer rpc_listen={rpc_listen} p2p_listen={p2p}; community observers usually expose public RPC (see REFERENCE_TOPOLOGY.md); loopback RPC is OK with SSH tunnel"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalized_listen_host_parses_ipv4_and_wildcard() {
        assert_eq!(
            normalized_listen_host("203.0.113.5:18731").as_deref(),
            Some("203.0.113.5")
        );
        assert_eq!(
            normalized_listen_host("0.0.0.0:8333").as_deref(),
            Some("unspecified")
        );
    }

    #[test]
    fn loopback_rpc_skips_topology_warning() {
        assert!(role_topology_colocation_warning(
            true,
            false,
            "127.0.0.1:18731",
            Some("127.0.0.1:8333"),
            true
        )
        .is_none());
    }

    #[test]
    fn public_rpc_validator_operator_warns() {
        let msg = role_topology_colocation_warning(
            true,
            false,
            "0.0.0.0:18731",
            Some("0.0.0.0:8333"),
            true,
        )
        .expect("warning");
        assert!(msg.contains("mfnd_role_topology_warning"));
        assert!(msg.contains("validator+wallet_rpc+operator"));
    }

    #[test]
    fn public_rpc_validator_without_operator_warns_two_roles() {
        let msg = role_topology_colocation_warning(
            false,
            true,
            "203.0.113.1:18731",
            Some("203.0.113.1:8333"),
            false,
        )
        .expect("warning");
        assert!(msg.contains("roles=validator+wallet_rpc"));
        assert!(!msg.contains("+operator"));
    }

    #[test]
    fn observer_public_p2p_loopback_rpc_hints() {
        let msg = observer_loopback_rpc_hint_warning(
            false,
            false,
            "127.0.0.1:18731",
            Some("0.0.0.0:19004"),
        )
        .expect("hint");
        assert!(msg.contains("roles=observer"));
    }

    #[test]
    fn observer_loopback_mesh_skips_hint() {
        assert!(observer_loopback_rpc_hint_warning(
            false,
            false,
            "127.0.0.1:18731",
            Some("127.0.0.1:8333"),
        )
        .is_none());
    }

    #[test]
    fn validator_skips_observer_hint() {
        assert!(observer_loopback_rpc_hint_warning(
            true,
            false,
            "127.0.0.1:18731",
            Some("0.0.0.0:19004"),
        )
        .is_none());
    }

    #[test]
    fn different_public_hosts_skip_warning() {
        assert!(role_topology_colocation_warning(
            true,
            false,
            "203.0.113.1:18731",
            Some("203.0.113.2:8333"),
            true
        )
        .is_none());
    }
}
