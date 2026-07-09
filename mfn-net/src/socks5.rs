//! Minimal SOCKS5 client for outbound P2P dials (**B8.1** / `F5:P4`).
//!
//! Supports anonymous auth (`METHOD 0x00`) and `CONNECT` to IPv4/IPv6 targets.
//! Domain-name targets are not required for B8.1 (cleartext `host:port` seed nodes).

use std::io::{Error, ErrorKind, Read, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::time::Duration;

const SOCKS5_VERSION: u8 = 5;
const CMD_CONNECT: u8 = 1;
const ATYP_IPV4: u8 = 1;
const ATYP_IPV6: u8 = 4;
const ATYP_DOMAIN: u8 = 3;
const AUTH_NONE: u8 = 0;
const REP_SUCCEEDED: u8 = 0;

/// Connect to the first resolved `target_addrs` via SOCKS5 `proxy` within `timeout`.
pub fn socks5_connect_with_timeout<A: ToSocketAddrs>(
    proxy: &str,
    target_addrs: A,
    timeout: Duration,
) -> std::io::Result<TcpStream> {
    let proxy_addrs: Vec<SocketAddr> = proxy.to_socket_addrs()?.collect();
    if proxy_addrs.is_empty() {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            "socks5 proxy address resolved to no socket addresses",
        ));
    }

    let targets: Vec<SocketAddr> = target_addrs.to_socket_addrs()?.collect();
    if targets.is_empty() {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            "peer address resolved to no socket addresses",
        ));
    }

    let mut last_err = None;
    for target in targets {
        for proxy_addr in &proxy_addrs {
            match socks5_connect_via_proxy(*proxy_addr, target, timeout) {
                Ok(stream) => return Ok(stream),
                Err(e) => last_err = Some(e),
            }
        }
    }
    Err(last_err.unwrap_or_else(|| {
        Error::new(
            ErrorKind::ConnectionRefused,
            "socks5 connect failed for all proxy/target combinations",
        )
    }))
}

fn socks5_connect_via_proxy(
    proxy: SocketAddr,
    target: SocketAddr,
    timeout: Duration,
) -> std::io::Result<TcpStream> {
    let mut stream = TcpStream::connect_timeout(&proxy, timeout)?;
    stream.set_read_timeout(Some(timeout))?;
    stream.set_write_timeout(Some(timeout))?;
    socks5_handshake(&mut stream)?;
    socks5_request_connect(&mut stream, target)?;
    Ok(stream)
}

fn socks5_handshake(stream: &mut TcpStream) -> std::io::Result<()> {
    stream.write_all(&[SOCKS5_VERSION, 1, AUTH_NONE])?;
    stream.flush()?;
    let mut resp = [0u8; 2];
    stream.read_exact(&mut resp)?;
    if resp[0] != SOCKS5_VERSION {
        return Err(Error::new(
            ErrorKind::InvalidData,
            format!("socks5: expected version 5, got {}", resp[0]),
        ));
    }
    if resp[1] != AUTH_NONE {
        return Err(Error::new(
            ErrorKind::PermissionDenied,
            format!("socks5: unsupported auth method {}", resp[1]),
        ));
    }
    Ok(())
}

fn socks5_request_connect(stream: &mut TcpStream, target: SocketAddr) -> std::io::Result<()> {
    let mut req = Vec::with_capacity(22);
    req.push(SOCKS5_VERSION);
    req.push(CMD_CONNECT);
    req.push(0);
    match target {
        SocketAddr::V4(v4) => {
            req.push(ATYP_IPV4);
            req.extend_from_slice(&v4.ip().octets());
        }
        SocketAddr::V6(v6) => {
            req.push(ATYP_IPV6);
            req.extend_from_slice(&v6.ip().octets());
        }
    }
    req.push((target.port() >> 8) as u8);
    req.push((target.port() & 0xff) as u8);
    stream.write_all(&req)?;
    stream.flush()?;

    let mut head = [0u8; 4];
    stream.read_exact(&mut head)?;
    if head[0] != SOCKS5_VERSION {
        return Err(Error::new(
            ErrorKind::InvalidData,
            format!("socks5: bad connect reply version {}", head[0]),
        ));
    }
    if head[1] != REP_SUCCEEDED {
        return Err(Error::new(
            ErrorKind::ConnectionRefused,
            format!("socks5: CONNECT failed rep={}", head[1]),
        ));
    }
    socks5_skip_bind_addr(stream, head[3])?;
    Ok(())
}

fn socks5_skip_bind_addr(stream: &mut TcpStream, atyp: u8) -> std::io::Result<()> {
    match atyp {
        ATYP_IPV4 => {
            let mut buf = [0u8; 4 + 2];
            stream.read_exact(&mut buf)?;
        }
        ATYP_IPV6 => {
            let mut buf = [0u8; 16 + 2];
            stream.read_exact(&mut buf)?;
        }
        ATYP_DOMAIN => {
            let mut len = [0u8; 1];
            stream.read_exact(&mut len)?;
            let domain_len = len[0] as usize;
            let mut rest = vec![0u8; domain_len + 2];
            stream.read_exact(&mut rest)?;
        }
        other => {
            return Err(Error::new(
                ErrorKind::InvalidData,
                format!("socks5: unknown bind addr type {other}"),
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::thread;

    fn run_minimal_socks5_proxy(listener: TcpListener, target: SocketAddr) {
        let (mut client, _) = listener.accept().unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        client
            .set_write_timeout(Some(Duration::from_secs(5)))
            .unwrap();

        let mut buf = [0u8; 3];
        client.read_exact(&mut buf).unwrap();
        assert_eq!(buf, [SOCKS5_VERSION, 1, AUTH_NONE]);
        client.write_all(&[SOCKS5_VERSION, AUTH_NONE]).unwrap();

        let mut hdr = [0u8; 4];
        client.read_exact(&mut hdr).unwrap();
        assert_eq!(hdr[0], SOCKS5_VERSION);
        assert_eq!(hdr[1], CMD_CONNECT);
        let atyp = hdr[3];
        match atyp {
            ATYP_IPV4 => {
                let mut rest = [0u8; 4 + 2];
                client.read_exact(&mut rest).unwrap();
            }
            ATYP_IPV6 => {
                let mut rest = [0u8; 16 + 2];
                client.read_exact(&mut rest).unwrap();
            }
            _ => panic!("unexpected atyp {atyp}"),
        }

        let mut upstream = TcpStream::connect_timeout(&target, Duration::from_secs(5)).unwrap();
        client
            .write_all(&[
                SOCKS5_VERSION,
                REP_SUCCEEDED,
                0,
                ATYP_IPV4,
                127,
                0,
                0,
                1,
                0,
                0,
            ])
            .unwrap();

        let mut buf = [0u8; 9];
        client.read_exact(&mut buf).unwrap();
        upstream.write_all(&buf).unwrap();
        upstream.flush().unwrap();
    }

    #[test]
    fn socks5_connect_ipv4_round_trip() {
        use std::sync::mpsc;

        let echo = TcpListener::bind("127.0.0.1:0").unwrap();
        let echo_addr = echo.local_addr().unwrap();
        let proxy = TcpListener::bind("127.0.0.1:0").unwrap();
        let proxy_addr = proxy.local_addr().unwrap();

        let server = thread::spawn(move || {
            let (mut sock, _) = echo.accept().unwrap();
            sock.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
            let mut buf = [0u8; 9];
            sock.read_exact(&mut buf).unwrap();
            assert_eq!(&buf, b"socks5-ok");
        });

        let (ready_tx, ready_rx) = mpsc::channel();
        let proxy_thread = thread::spawn(move || {
            ready_tx.send(()).ok();
            run_minimal_socks5_proxy(proxy, echo_addr);
        });
        ready_rx.recv().unwrap();

        let mut stream =
            socks5_connect_with_timeout(&proxy_addr.to_string(), echo_addr, Duration::from_secs(5))
                .unwrap();
        stream.write_all(b"socks5-ok").unwrap();
        stream.flush().unwrap();

        proxy_thread.join().unwrap();
        server.join().unwrap();
    }
}
