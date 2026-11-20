//! Bounds for a JSON-RPC request value before method dispatch.
//!
//! `serde_json` stops extreme nesting, but a request can still be a wide
//! tree of objects and arrays. Handlers that walk `params` should not be
//! the first line of defense.

use serde_json::Value;

/// Maximum nesting of arrays and objects, counting the root as depth 1.
pub const MAX_RPC_JSON_DEPTH: usize = 32;
/// Maximum number of JSON values in one request, including the root.
pub const MAX_RPC_JSON_NODES: usize = 4_096;

/// Reject a request whose tree is deeper or wider than the caps above.
pub fn enforce_request_bounds(value: &Value) -> Result<(), &'static str> {
    let mut nodes = 0usize;
    walk(value, 1, &mut nodes)
}

fn walk(value: &Value, depth: usize, nodes: &mut usize) -> Result<(), &'static str> {
    *nodes = nodes.saturating_add(1);
    if *nodes > MAX_RPC_JSON_NODES {
        return Err("request has too many JSON values");
    }
    if depth > MAX_RPC_JSON_DEPTH {
        return Err("request JSON is nested too deeply");
    }
    match value {
        Value::Array(items) => {
            for item in items {
                walk(item, depth + 1, nodes)?;
            }
        }
        Value::Object(map) => {
            for item in map.values() {
                walk(item, depth + 1, nodes)?;
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {}
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn ordinary_request_is_accepted() {
        let v = json!({"jsonrpc":"2.0","method":"get_tip","id":1});
        assert!(enforce_request_bounds(&v).is_ok());
    }

    #[test]
    fn deep_nesting_is_rejected() {
        let mut v = json!(0);
        for _ in 0..MAX_RPC_JSON_DEPTH + 2 {
            v = json!([v]);
        }
        assert_eq!(
            enforce_request_bounds(&v),
            Err("request JSON is nested too deeply")
        );
    }

    #[test]
    fn wide_object_is_rejected() {
        let mut map = serde_json::Map::new();
        for i in 0..MAX_RPC_JSON_NODES {
            map.insert(format!("k{i}"), json!(1));
        }
        let v = Value::Object(map);
        assert_eq!(
            enforce_request_bounds(&v),
            Err("request has too many JSON values")
        );
    }
}
