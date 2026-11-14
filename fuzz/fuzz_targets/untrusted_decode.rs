//! One libFuzzer target for the bytes a peer or a file can hand the node.
//!
//! The first byte picks a decoder. Inputs are truncated so a single run
//! cannot ask the process for more memory than a frame already allows.
//! Nightly CI runs this target. Pull requests do not.

#![no_main]

use std::io::Cursor;

use libfuzzer_sys::fuzz_target;
use mfn_cli::WalletFile;
use mfn_consensus::{decode_block, decode_block_header, decode_transaction};
use mfn_net::block_sync::{BlocksV1, GetBlocksByHeightV1};
use mfn_net::chunk_v1::ChunkV1;
use mfn_net::chunk_v2::ChunkV2;
use mfn_net::frame::{
    decode_frame_prefix, read_frame, BlockV1, ChainTipV1, GoodbyeV1, HelloV1, PingV1, PongV1,
    TxStemV1, TxV1,
};
const MAX_INPUT: usize = 64 * 1024;

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }
    let data = if data.len() > MAX_INPUT {
        &data[..MAX_INPUT]
    } else {
        data
    };
    let (which, body) = data.split_at(1);
    match which[0] % 4 {
        0 => fuzz_consensus(body),
        1 => fuzz_p2p(body),
        2 => fuzz_rpc(body),
        _ => fuzz_wallet(body),
    }
});

fn fuzz_consensus(body: &[u8]) {
    let _ = decode_transaction(body);
    let _ = decode_block(body);
    let _ = decode_block_header(body);
}

fn fuzz_p2p(body: &[u8]) {
    let _ = decode_frame_prefix(body);
    let _ = read_frame(&mut Cursor::new(body));
    let _ = HelloV1::decode(body);
    let _ = PingV1::decode(body);
    let _ = PongV1::decode(body);
    let _ = ChainTipV1::decode(body);
    let _ = GoodbyeV1::decode(body);
    let _ = TxV1::decode_payload(body);
    let _ = TxStemV1::decode_payload(body);
    let _ = BlockV1::decode_payload(body);
    let _ = GetBlocksByHeightV1::decode_payload(body);
    let _ = BlocksV1::decode_payload(body);
    let _ = ChunkV1::decode_payload(body);
    let _ = ChunkV2::decode_payload(body);
}

fn fuzz_rpc(body: &[u8]) {
    let Ok(text) = std::str::from_utf8(body) else {
        return;
    };
    let Ok(value) = serde_json::from_str::<serde_json::Value>(text) else {
        return;
    };
    let _ = walk(&value, 0);
}

fn walk(value: &serde_json::Value, depth: usize) -> usize {
    if depth > 64 {
        return depth;
    }
    match value {
        serde_json::Value::Array(items) => items.iter().map(|item| walk(item, depth + 1)).sum(),
        serde_json::Value::Object(map) => map.values().map(|item| walk(item, depth + 1)).sum(),
        _ => 1,
    }
}

fn fuzz_wallet(body: &[u8]) {
    let path = std::env::temp_dir().join("permawrite-g9-wallet.json");
    if std::fs::write(&path, body).is_err() {
        return;
    }
    let _ = WalletFile::load(&path);
    let _ = std::fs::remove_file(&path);
}
