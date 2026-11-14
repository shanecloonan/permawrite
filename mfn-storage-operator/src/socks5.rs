//! SOCKS5 CONNECT so a chunk fetch can go through Tor.
//!
//! Tor's default listener is a SOCKS5 proxy with no authentication
//! (`127.0.0.1:9050`). This module opens that tunnel and returns the TCP
//! stream. It does not start Tor and it does not change consensus.

use std::io::{Read, Write};
use std::net::{Ipv4Addr, TcpStream};
use std::time::Duration;

/// Why a SOCKS5 tunnel was not opened.
#[derive(Debug, thiserror::Error)]
pub enum SocksError {
    /// TCP or SOCKS I/O.
    #[error("{0}")]
    Io(#[from] std::io::Error),
    /// The proxy or the target address was rejected.
    #[error("{0}")]
    Usage(String),
}

/// Open a TCP connection to `target_host:target_port` through a SOCKS5 proxy.
///
/// `proxy` is `HOST:PORT` with no scheme. No username or password is sent.
///
/// # Errors
///
/// [`SocksError`] when the proxy is unreachable, refuses the method, or
/// refuses the connect.
pub fn socks5_connect(
    proxy: &str,
    target_host: &str,
    target_port: u16,
) -> Result<TcpStream, SocksError> {
    let mut stream = TcpStream::connect(proxy.trim())
        .map_err(|e| SocksError::Usage(format!("connect socks {proxy}: {e}")))?;
    stream.set_read_timeout(Some(Duration::from_secs(30)))?;
    stream.set_write_timeout(Some(Duration::from_secs(30)))?;
    stream.write_all(&[0x05, 0x01, 0x00])?;
    let mut method = [0u8; 2];
    stream.read_exact(&mut method)?;
    if method != [0x05, 0x00] {
        return Err(SocksError::Usage(format!(
            "socks proxy rejected no-auth method {:02x}{:02x}",
            method[0], method[1]
        )));
    }
    let request = connect_request(target_host, target_port)?;
    stream.write_all(&request)?;
    let mut head = [0u8; 4];
    stream.read_exact(&mut head)?;
    if head[0] != 0x05 || head[1] != 0x00 {
        return Err(SocksError::Usage(format!(
            "socks connect failed reply {:02x}",
            head[1]
        )));
    }
    let addr_len = match head[3] {
        0x01 => 4,
        0x03 => {
            let mut len = [0u8; 1];
            stream.read_exact(&mut len)?;
            usize::from(len[0])
        }
        0x04 => 16,
        other => {
            return Err(SocksError::Usage(format!(
                "socks reply address type {other}"
            )))
        }
    };
    let mut rest = vec![0u8; addr_len + 2];
    stream.read_exact(&mut rest)?;
    Ok(stream)
}

fn connect_request(host: &str, port: u16) -> Result<Vec<u8>, SocksError> {
    let port_be = port.to_be_bytes();
    let mut req = vec![0x05, 0x01, 0x00];
    if let Ok(ip) = host.parse::<Ipv4Addr>() {
        req.push(0x01);
        req.extend_from_slice(&ip.octets());
    } else {
        let bytes = host.as_bytes();
        if bytes.is_empty() || bytes.len() > 255 {
            return Err(SocksError::Usage(format!(
                "socks target host length {} is not 1..=255",
                bytes.len()
            )));
        }
        req.push(0x03);
        req.push(u8::try_from(bytes.len()).unwrap_or(0));
        req.extend_from_slice(bytes);
    }
    req.extend_from_slice(&port_be);
    Ok(req)
}
