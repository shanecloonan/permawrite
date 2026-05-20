//! Light-follow batch quorum for CLI sync (**M3.12**).

use mfn_net::light_follow::{light_follow_rows_quorum, LightFollowRow as WireRow};

use crate::rpc::LightFollowPage;

/// Convert an RPC [`LightFollowPage`] row into a wire [`WireRow`] for byte quorum.
pub fn rpc_page_to_wire_rows(page: &LightFollowPage) -> Result<Vec<WireRow>, String> {
    let mut out = Vec::with_capacity(page.rows.len());
    for row in &page.rows {
        let block_id = decode_hex32(&row.block_id, "block_id")?;
        let header_wire = decode_hex(&row.header_hex, "header_hex")?;
        let slashings = row
            .slashings
            .iter()
            .map(|s| decode_hex(&s.evidence_hex, "evidence_hex"))
            .collect::<Result<Vec<_>, _>>()?;
        let bond_ops = row
            .bond_ops
            .iter()
            .map(|b| decode_hex(&b.op_hex, "op_hex"))
            .collect::<Result<Vec<_>, _>>()?;
        out.push(WireRow {
            height: row.height,
            block_id,
            header_wire,
            slashings,
            bond_ops,
        });
    }
    Ok(out)
}

/// Require every `get_light_follow` page to agree row-for-row (same as P2P / WASM quorum).
pub fn light_follow_pages_quorum(pages: &[LightFollowPage]) -> Result<usize, String> {
    if pages.is_empty() {
        return Err("light-follow quorum requires at least one batch".into());
    }
    if pages.len() == 1 {
        return Ok(1);
    }
    let wire_batches: Vec<Vec<WireRow>> = pages
        .iter()
        .map(rpc_page_to_wire_rows)
        .collect::<Result<Vec<_>, _>>()?;
    let refs: Vec<&[WireRow]> = wire_batches.iter().map(|b| b.as_slice()).collect();
    light_follow_rows_quorum(&refs).map_err(|e| e.to_string())?;
    Ok(pages.len())
}

fn decode_hex(s: &str, label: &str) -> Result<Vec<u8>, String> {
    let t = s
        .trim()
        .strip_prefix("0x")
        .or_else(|| s.trim().strip_prefix("0X"))
        .unwrap_or(s.trim());
    hex::decode(t).map_err(|e| format!("{label}: {e}"))
}

fn decode_hex32(s: &str, label: &str) -> Result<[u8; 32], String> {
    let bytes = decode_hex(s, label)?;
    bytes
        .try_into()
        .map_err(|_| format!("{label} must be 32 bytes"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rpc::{LightFollowBondOp, LightFollowRow, LightFollowSlashing};

    fn sample_page(height: u32, header_hex: &str, block_id: &str) -> LightFollowPage {
        LightFollowPage {
            from_height: height,
            to_height: height,
            rows: vec![LightFollowRow {
                height,
                block_id: block_id.to_string(),
                header_hex: header_hex.to_string(),
                slashings: vec![LightFollowSlashing {
                    evidence_hex: "aa".repeat(32),
                }],
                bond_ops: vec![LightFollowBondOp {
                    op_hex: "bb".repeat(16),
                }],
            }],
        }
    }

    #[test]
    fn quorum_accepts_matching_pages() {
        let a = sample_page(1, &"cc".repeat(40), &"dd".repeat(32));
        let b = sample_page(1, &"cc".repeat(40), &"dd".repeat(32));
        assert_eq!(light_follow_pages_quorum(&[a, b]).unwrap(), 2);
    }

    #[test]
    fn quorum_rejects_header_divergence() {
        let a = sample_page(1, &"cc".repeat(40), &"dd".repeat(32));
        let b = sample_page(1, &"ee".repeat(40), &"dd".repeat(32));
        assert!(light_follow_pages_quorum(&[a, b]).is_err());
    }
}
