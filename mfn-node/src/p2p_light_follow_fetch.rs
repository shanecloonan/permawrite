//! Outbound P2P fetch for light-follow batches (**M4.15**).

use mfn_net::{
    light_follow_rows_quorum, recv_light_follow_v1, send_get_light_follow_v1,
    tcp_connect_peer_v1_handshake_with_tip_exchange, ChainTipV1, GetLightFollowV1, LightFollowV1,
    MAX_LIGHT_FOLLOW_PER_GET_V1,
};
use mfn_rpc::light_follow_v1_to_json;
use serde_json::{json, Value};
use std::net::ToSocketAddrs;
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
    let mut page = light_follow_v1_to_json(&follow, from_height, to_height);
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

    let page_follow = LightFollowV1 {
        genesis_id: genesis_id_val,
        rows: wire_batches
            .into_iter()
            .next()
            .expect("quorum requires ≥1 batch"),
    };
    let mut page = light_follow_v1_to_json(&page_follow, from_height, to_height);
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
    let addrs = peer
        .to_socket_addrs()
        .map_err(|e| format!("peer address `{peer}`: {e}"))?;
    let mut last_err = String::from("no addresses resolved for peer");
    for addr in addrs {
        match tcp_connect_peer_v1_handshake_with_tip_exchange(addr, genesis_id, local_tip) {
            Ok((mut stream, _remote_tip)) => {
                let req = GetLightFollowV1 {
                    start_height,
                    count,
                };
                if let Err(e) = send_get_light_follow_v1(&mut stream, req) {
                    last_err = format!("send GetLightFollowV1 to {addr}: {e}");
                    continue;
                }
                return recv_light_follow_v1(&mut stream)
                    .map_err(|e| format!("recv LightFollowV1 from {addr}: {e}"));
            }
            Err(e) => {
                last_err = format!("p2p handshake with {addr}: {e}");
            }
        }
    }
    Err(last_err)
}
