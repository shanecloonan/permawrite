//! Outbound P2P fetch for light-follow batches (**M4.15**).

use mfn_net::{
    light_follow_rows_quorum, recv_light_follow_v1, send_get_light_follow_v1,
    tcp_connect_peer_v1_handshake_with_tip_exchange, ChainTipV1, GetLightFollowV1, LightFollowV1,
    MAX_LIGHT_FOLLOW_PER_GET_V1,
};
use mfn_rpc::light_follow_v1_to_json;
use serde_json::{json, Value};
use std::thread;

/// Maximum P2P peers per quorum fetch (DoS cap, **M4.16**).
pub const MAX_QUORUM_P2P_PEERS: usize = 8;

/// Dial `peer`, handshake, pull [`LightFollowV1`], return JSON-RPC-shaped result.
pub fn fetch_light_follow_json(
    peer: &str,
    genesis_id: &[u8; 32],
    local_tip: ChainTipV1,
    from_height: u32,
    to_height: u32,
) -> Result<Value, String> {
    if from_height < 1 {
        return Err("from_height must be ≥ 1".into());
    }
    if to_height < from_height {
        return Err("to_height must be ≥ from_height".into());
    }
    let span = to_height - from_height + 1;
    let count = span.min(MAX_LIGHT_FOLLOW_PER_GET_V1);
    let follow = fetch_light_follow_v1(peer, genesis_id, &local_tip, from_height, count)?;
    if follow.genesis_id != *genesis_id {
        return Err("peer genesis_id does not match local chain".into());
    }
    let page_to_height = capped_page_to_height(from_height, to_height);
    let mut page = light_follow_v1_to_json(&follow, from_height, page_to_height);
    if let Some(obj) = page.as_object_mut() {
        obj.insert("peer".into(), Value::String(peer.to_string()));
        obj.insert("source".into(), Value::String("p2p".into()));
    }
    Ok(page)
}

/// Dial each `peers` entry, require byte-identical light-follow rows (**M4.16**).
pub fn fetch_light_follow_quorum_json(
    peers: &[String],
    genesis_id: &[u8; 32],
    local_tip: ChainTipV1,
    from_height: u32,
    to_height: u32,
) -> Result<Value, String> {
    if peers.len() < 2 {
        return Err("quorum requires at least 2 peers".into());
    }
    if peers.len() > MAX_QUORUM_P2P_PEERS {
        return Err(format!(
            "at most {MAX_QUORUM_P2P_PEERS} peers per quorum fetch (got {})",
            peers.len()
        ));
    }
    if from_height < 1 {
        return Err("from_height must be ≥ 1".into());
    }
    if to_height < from_height {
        return Err("to_height must be ≥ from_height".into());
    }
    let span = to_height - from_height + 1;
    let count = span.min(MAX_LIGHT_FOLLOW_PER_GET_V1);
    let genesis_id_val = *genesis_id;

    let mut handles = Vec::with_capacity(peers.len());
    for peer in peers {
        let peer = peer.clone();
        handles.push(thread::spawn(move || {
            fetch_light_follow_v1(&peer, &genesis_id_val, &local_tip, from_height, count)
        }));
    }

    let mut wire_batches = Vec::with_capacity(peers.len());
    for (i, handle) in handles.into_iter().enumerate() {
        let follow = handle
            .join()
            .map_err(|_| format!("peer fetch thread {} panicked", i))??;
        if follow.genesis_id != genesis_id_val {
            return Err(format!(
                "peer {} genesis_id does not match local chain",
                peers[i]
            ));
        }
        wire_batches.push(follow.rows);
    }

    let refs: Vec<&[mfn_net::LightFollowRow]> =
        wire_batches.iter().map(|rows| rows.as_slice()).collect();
    light_follow_rows_quorum(&refs).map_err(|e| format!("{e}"))?;

    let first_batch = wire_batches
        .into_iter()
        .next()
        .ok_or_else(|| "quorum fetch produced no batches".to_string())?;
    let page_follow = LightFollowV1 {
        genesis_id: genesis_id_val,
        rows: first_batch,
    };
    let page_to_height = capped_page_to_height(from_height, to_height);
    let mut page = light_follow_v1_to_json(&page_follow, from_height, page_to_height);
    if let Some(obj) = page.as_object_mut() {
        obj.insert("quorum".into(), json!(true));
        obj.insert("peer_count".into(), json!(peers.len()));
        obj.insert(
            "peers".into(),
            Value::Array(peers.iter().map(|p| json!(p)).collect()),
        );
        obj.insert("source".into(), Value::String("p2p_quorum".into()));
    }
    Ok(page)
}

fn fetch_light_follow_v1(
    peer: &str,
    genesis_id: &[u8; 32],
    local_tip: &ChainTipV1,
    start_height: u32,
    count: u32,
) -> Result<LightFollowV1, String> {
    let (mut stream, _remote_tip) =
        tcp_connect_peer_v1_handshake_with_tip_exchange(peer, genesis_id, local_tip)
            .map_err(|e| format!("p2p handshake with {peer}: {e}"))?;
    let req = GetLightFollowV1 {
        start_height,
        count,
    };
    send_get_light_follow_v1(&mut stream, req)
        .map_err(|e| format!("send GetLightFollowV1 to {peer}: {e}"))?;
    let follow = recv_light_follow_v1(&mut stream)
        .map_err(|e| format!("recv LightFollowV1 from {peer}: {e}"))?;
    validate_light_follow_response(&follow, start_height, count)
        .map_err(|e| format!("invalid LightFollowV1 from {peer}: {e}"))?;
    Ok(follow)
}

fn validate_light_follow_response(
    follow: &LightFollowV1,
    start_height: u32,
    requested_count: u32,
) -> Result<(), String> {
    let got = follow.rows.len();
    if got > requested_count as usize {
        return Err(format!("returned {got} rows, requested {requested_count}"));
    }
    for (idx, row) in follow.rows.iter().enumerate() {
        let idx = u32::try_from(idx).map_err(|_| "row index overflow".to_string())?;
        let expected = start_height
            .checked_add(idx)
            .ok_or_else(|| "row height overflow".to_string())?;
        if row.height != expected {
            return Err(format!(
                "non-sequential row height: expected {expected}, got {}",
                row.height
            ));
        }
    }
    Ok(())
}

fn capped_page_to_height(from_height: u32, to_height: u32) -> u32 {
    let span = to_height - from_height + 1;
    let capped = span.min(MAX_LIGHT_FOLLOW_PER_GET_V1);
    from_height + capped - 1
}

#[cfg(test)]
mod tests {
    use super::*;
    use mfn_net::LightFollowRow;

    fn row(height: u32) -> LightFollowRow {
        LightFollowRow {
            height,
            block_id: [height as u8; 32],
            header_wire: vec![0xab, height as u8],
            slashings: Vec::new(),
            bond_ops: Vec::new(),
        }
    }

    #[test]
    fn validate_light_follow_response_accepts_prefix() {
        let follow = LightFollowV1 {
            genesis_id: [7u8; 32],
            rows: vec![row(10), row(11)],
        };

        validate_light_follow_response(&follow, 10, 4).expect("prefix may be shorter than request");
    }

    #[test]
    fn validate_light_follow_response_rejects_more_rows_than_requested() {
        let follow = LightFollowV1 {
            genesis_id: [7u8; 32],
            rows: vec![row(10), row(11)],
        };

        let err = validate_light_follow_response(&follow, 10, 1)
            .expect_err("oversized response must reject");

        assert!(err.contains("returned 2 rows, requested 1"), "err={err}");
    }

    #[test]
    fn validate_light_follow_response_rejects_skipped_height() {
        let follow = LightFollowV1 {
            genesis_id: [7u8; 32],
            rows: vec![row(10), row(12)],
        };

        let err = validate_light_follow_response(&follow, 10, 2)
            .expect_err("skipped row height must reject");

        assert!(
            err.contains("non-sequential row height: expected 11, got 12"),
            "err={err}"
        );
    }

    #[test]
    fn capped_page_to_height_preserves_short_range() {
        assert_eq!(capped_page_to_height(10, 12), 12);
    }

    #[test]
    fn capped_page_to_height_limits_long_range_to_wire_request() {
        assert_eq!(
            capped_page_to_height(10, 10 + MAX_LIGHT_FOLLOW_PER_GET_V1 + 99),
            10 + MAX_LIGHT_FOLLOW_PER_GET_V1 - 1
        );
    }
}
