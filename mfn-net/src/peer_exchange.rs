//! `getaddr` / `addr` so a node can learn peers from a neighbor when DNS and
//! the seed list are blocked.
//!
//! Tag `0x15` asks. Tag `0x16` answers with up to 16 `host:port` strings.
//! Asking is off unless [`set_asking`] is set (`MFND_P2P_GETADDR=1`), because
//! a peer that rejects unknown tags would drop the session. Answering is
//! always on.

use std::io::Write;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;

use crate::frame::{read_frame, write_frame_io, FrameReadError, FrameWriteError};

/// Ask a neighbor for addresses.
pub const GETADDR_V1_TAG: u8 = 0x15;
/// Addresses in reply to [`GETADDR_V1_TAG`].
pub const ADDR_V1_TAG: u8 = 0x16;

const MAX_ADDRS: usize = 16;
const MAX_ADDR_LEN: usize = 128;

static ASKING: AtomicBool = AtomicBool::new(false);
static KNOWN: Mutex<Vec<String>> = Mutex::new(Vec::new());

/// Turn outbound `getaddr` on or off.
pub fn set_asking(on: bool) {
    ASKING.store(on, Ordering::Relaxed);
}

/// Whether this process sends `getaddr` after the handshake.
#[must_use]
pub fn asking() -> bool {
    ASKING.load(Ordering::Relaxed)
}

/// Remember `addr` so a later `getaddr` can share it. Loopback is kept: tests
/// and local meshes learn `127.0.0.1` listeners this way.
pub fn remember(addr: &str) {
    let Some(addr) = normalize(addr) else {
        return;
    };
    let Ok(mut known) = KNOWN.lock() else {
        return;
    };
    if known.iter().any(|existing| existing == &addr) {
        return;
    }
    if known.len() >= 256 {
        known.remove(0);
    }
    known.push(addr);
}

/// Addresses this process will put in an `addr` frame.
#[must_use]
pub fn known_addrs() -> Vec<String> {
    KNOWN.lock().map(|known| known.clone()).unwrap_or_default()
}

/// `getaddr` frame body.
#[must_use]
pub fn encode_getaddr() -> Vec<u8> {
    vec![GETADDR_V1_TAG]
}

/// `addr` frame body.
#[must_use]
pub fn encode_addr(addrs: &[String]) -> Vec<u8> {
    let mut out = vec![ADDR_V1_TAG, 0];
    let mut n = 0u8;
    for addr in addrs {
        if addr.len() > MAX_ADDR_LEN || n == MAX_ADDRS as u8 {
            break;
        }
        if normalize(addr).is_none() {
            continue;
        }
        out.push(addr.len() as u8);
        out.extend_from_slice(addr.as_bytes());
        n = n.saturating_add(1);
    }
    out[1] = n;
    out
}

/// Decode an `addr` body. Unknown tags and truncated bodies yield an empty list.
#[must_use]
pub fn decode_addr(payload: &[u8]) -> Vec<String> {
    if payload.len() < 2 || payload[0] != ADDR_V1_TAG {
        return Vec::new();
    }
    let mut out = Vec::new();
    let mut i = 2usize;
    let count = payload[1] as usize;
    for _ in 0..count.min(MAX_ADDRS) {
        if i >= payload.len() {
            break;
        }
        let len = payload[i] as usize;
        i = i.saturating_add(1);
        if i.saturating_add(len) > payload.len() {
            break;
        }
        let bytes = &payload[i..i + len];
        i += len;
        if let Ok(text) = std::str::from_utf8(bytes) {
            if let Some(addr) = normalize(text) {
                out.push(addr);
            }
        }
    }
    out
}

/// Write one `getaddr` frame.
pub fn send_getaddr<W: Write>(w: &mut W) -> Result<(), FrameWriteError> {
    write_frame_io(w, &encode_getaddr())?;
    w.flush().map_err(FrameWriteError::Io)
}

/// If `payload` is `getaddr`, write an `addr` reply. If it is `addr`, remember
/// the contents and return them. Other tags return an empty list and write nothing.
pub fn handle_frame<W: Write>(payload: &[u8], w: &mut W) -> Result<Vec<String>, FrameWriteError> {
    if payload.first() == Some(&GETADDR_V1_TAG) {
        write_frame_io(w, &encode_addr(&known_addrs()))?;
        w.flush().map_err(FrameWriteError::Io)?;
        return Ok(Vec::new());
    }
    if payload.first() == Some(&ADDR_V1_TAG) {
        let learned = decode_addr(payload);
        for addr in &learned {
            remember(addr);
        }
        return Ok(learned);
    }
    Ok(Vec::new())
}

/// Read one reply frame after [`send_getaddr`].
pub fn recv_addr<R: std::io::Read>(r: &mut R) -> Result<Vec<String>, FrameReadError> {
    let payload = read_frame(r)?;
    Ok(decode_addr(&payload))
}

fn normalize(addr: &str) -> Option<String> {
    let addr = addr.trim();
    if addr.is_empty() || addr.len() > MAX_ADDR_LEN || addr.chars().any(char::is_whitespace) {
        return None;
    }
    let (host, port) = addr.rsplit_once(':')?;
    if host.is_empty() || port.parse::<u16>().ok()? == 0 {
        return None;
    }
    Some(addr.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::thread;

    #[test]
    fn neighbor_learns_a_third_node_and_dials_it() {
        let learned = TcpListener::bind("127.0.0.1:0").unwrap();
        let learned_addr = learned.local_addr().unwrap();
        let bridge = TcpListener::bind("127.0.0.1:0").unwrap();
        let bridge_addr = bridge.local_addr().unwrap();

        remember(&learned_addr.to_string());

        let server = thread::spawn(move || {
            let (mut sock, _) = bridge.accept().unwrap();
            let payload = read_frame(&mut sock).unwrap();
            handle_frame(&payload, &mut sock).unwrap();
        });

        let mut client = std::net::TcpStream::connect(bridge_addr).unwrap();
        send_getaddr(&mut client).unwrap();
        let got = recv_addr(&mut client).unwrap();
        server.join().unwrap();
        assert!(got.iter().any(|a| a == &learned_addr.to_string()));

        let mut dial = std::net::TcpStream::connect(&got[0]).unwrap();
        dial.write_all(b"ping").unwrap();
        let (mut accepted, _) = learned.accept().unwrap();
        let mut body = [0u8; 4];
        accepted.read_exact(&mut body).unwrap();
        assert_eq!(&body, b"ping");
    }
}
