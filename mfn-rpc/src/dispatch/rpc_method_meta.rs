//! RPC method classification and API-key authorization.

use serde_json::{json, Map, Value};

use super::rpc_codes;
use super::rpc_error;
use super::ServeDispatchOpts;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RpcMethodClass {
    PublicSafe,
    WalletWrite,
    OperatorAdmin,
}

impl RpcMethodClass {
    fn as_str(self) -> &'static str {
        match self {
            RpcMethodClass::PublicSafe => "public-safe",
            RpcMethodClass::WalletWrite => "wallet-write",
            RpcMethodClass::OperatorAdmin => "operator-admin",
        }
    }
}

pub(super) fn serve_rpc_method_names() -> Vec<&'static str> {
    let mut methods: Vec<&'static str> = vec![
        "clear_mempool",
        "clear_proof_pool",
        "get_block",
        "get_block_header",
        "get_block_evolution",
        "get_block_headers",
        "get_block_txs",
        "get_chain_params",
        "get_light_snapshot",
        "get_light_checkpoint_summary",
        "get_light_follow",
        "get_light_follow_p2p",
        "get_light_follow_quorum_p2p",
        "get_claims_by_pubkey",
        "get_claims_for",
        "get_checkpoint",
        "get_mempool",
        "get_mempool_tx",
        "get_proof_pool",
        "get_storage_challenge",
        "get_status",
        "get_tip",
        "list_data_roots_with_claims",
        "list_fraud_contests",
        "list_methods",
        "list_recent_claims",
        "list_recent_uploads",
        "list_utxos",
        "remove_mempool_tx",
        "save_checkpoint",
        "submit_storage_proof",
        "submit_tx",
    ];
    methods.sort_unstable();
    methods
}

fn rpc_method_class(method: &str) -> Option<RpcMethodClass> {
    match method {
        "submit_tx" | "submit_storage_proof" => Some(RpcMethodClass::WalletWrite),
        "clear_mempool"
        | "clear_proof_pool"
        | "get_light_follow_p2p"
        | "get_light_follow_quorum_p2p"
        | "remove_mempool_tx"
        | "save_checkpoint" => Some(RpcMethodClass::OperatorAdmin),
        "get_block"
        | "get_block_header"
        | "get_block_evolution"
        | "get_block_headers"
        | "get_block_txs"
        | "get_chain_params"
        | "get_claims_by_pubkey"
        | "get_claims_for"
        | "get_checkpoint"
        | "get_light_checkpoint_summary"
        | "get_light_follow"
        | "get_light_snapshot"
        | "get_mempool"
        | "get_mempool_tx"
        | "get_proof_pool"
        | "get_storage_challenge"
        | "get_status"
        | "get_tip"
        | "list_data_roots_with_claims"
        | "list_fraud_contests"
        | "list_methods"
        | "list_recent_claims"
        | "list_recent_uploads"
        | "list_utxos" => Some(RpcMethodClass::PublicSafe),
        _ => None,
    }
}

/// Method names implemented by [`dispatch_serve_methods`], sorted for a stable wire shape.
///
/// **Keep in sync** when adding a new `match` arm (include the new name here).
pub(super) fn serve_rpc_methods_json_result() -> Value {
    let methods = serve_rpc_method_names();
    let mut method_classes = Map::new();
    for method in &methods {
        let class = rpc_method_class(method).expect("all listed methods are classified");
        method_classes.insert((*method).to_string(), json!(class.as_str()));
    }
    json!({ "methods": methods, "method_classes": method_classes })
}
pub(super) fn request_api_key(req: &Value) -> Option<&str> {
    req.get("api_key")
        .and_then(Value::as_str)
        .or_else(|| req.get("auth")?.get("api_key")?.as_str())
}

pub(super) fn api_key_matches(expected: &str, got: &str) -> bool {
    let expected = expected.as_bytes();
    let got = got.as_bytes();
    if expected.len() != got.len() {
        return false;
    }
    let mut diff = 0u8;
    for (a, b) in expected.iter().zip(got) {
        diff |= a ^ b;
    }
    diff == 0
}

pub(super) fn authorize_rpc_method(
    method: &str,
    req: &Value,
    id: &Value,
    opts: &ServeDispatchOpts,
) -> Option<Value> {
    let expected = opts.rpc_api_key.as_deref()?;
    let class = rpc_method_class(method)?;
    if class == RpcMethodClass::PublicSafe {
        return None;
    }
    match request_api_key(req) {
        Some(got) if api_key_matches(expected, got) => None,
        _ => Some(rpc_error(
            id,
            rpc_codes::AUTH_REQUIRED,
            format!(
                "method `{method}` is `{}` and requires a valid RPC API key",
                class.as_str()
            ),
        )),
    }
}
