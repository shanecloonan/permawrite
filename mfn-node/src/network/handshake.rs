//! Symmetric [`HelloV1`](super::HelloV1) exchange over a duplex byte stream (**M2.3.2**).
//! **M2.3.4** adds [`tcp_connect_hello_v1_handshake`] for outbound TCP dials.
//! **M2.3.5** adds [`send_ping_recv_pong`] / [`recv_ping_send_pong`] after hello (dialer → listener),
//! and [`tcp_connect_peer_v1_handshake`] (connect + hello + ping/pong as dialer).
//! **M2.3.7** applies [`P2P_HANDSHAKE_IO_TIMEOUT`] on outbound [`TcpStream`]s from those dial helpers
//! (same default as `mfnd serve --p2p-listen` per accepted socket).
//! **M2.3.8** adds [`ChainTipV1`] exchange after ping/pong ([`exchange_chain_tip_v1_as_listener`]) and [`tcp_connect_peer_v1_handshake_with_tip_exchange`].
//! **M2.3.10** adds [`GoodbyeV1`] after the tip exchange on that full peer path (symmetric one-byte frame; dialer sends first).
//!
//! Each side sends one length-prefixed [`HelloV1`] frame, then reads the peer's frame and
//! checks the advertised genesis id matches the chain id both sides intend to speak.

use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration;

/// Read/write timeout for P2P handshake framing on [`TcpStream`] (dial + `mfnd serve` accept path).
pub const P2P_HANDSHAKE_IO_TIMEOUT: Duration = Duration::from_secs(30);

use super::frame::{
    read_frame, write_frame_io, ChainTipV1, FrameReadError, FrameWriteError, GoodbyeV1,
    GoodbyeV1DecodeError, HelloDecodeError, HelloV1, PingPongDecodeError, PingV1, PongV1,
    TipV1DecodeError,
};

/// Failed to complete a [`hello_v1_handshake`].
#[derive(Debug, thiserror::Error)]
pub enum HelloHandshakeError {
    /// Underlying `Read` / `Write` outside framed decode (e.g. [`Write::flush`]).
    #[error(transparent)]
    Io(#[from] std::io::Error),
    /// Could not read a full frame or declared length was illegal.
    #[error(transparent)]
    Read(#[from] FrameReadError),
    /// Could not write our hello frame.
    #[error(transparent)]
    Write(#[from] FrameWriteError),
    /// Peer's first frame was not a valid [`HelloV1`] payload.
    #[error(transparent)]
    Hello(#[from] HelloDecodeError),
    /// Ping / pong frame after hello was malformed.
    #[error(transparent)]
    PingPong(#[from] PingPongDecodeError),
    /// [`ChainTipV1`] frame after ping/pong was malformed.
    #[error(transparent)]
    Tip(#[from] TipV1DecodeError),
    /// [`GoodbyeV1`] frame after the tip exchange was malformed.
    #[error(transparent)]
    Goodbye(#[from] GoodbyeV1DecodeError),
    /// Peer's genesis id differs from `genesis_id` passed to [`hello_v1_handshake`].
    #[error("peer genesis id does not match expected chain genesis")]
    GenesisMismatch {
        /// Genesis id this node expects (`Chain::genesis_id()`).
        expected: [u8; 32],
        /// Genesis id advertised by the peer.
        got: [u8; 32],
    },
}

/// Write one framed [`HelloV1`] (length prefix + payload) and flush `w`.
pub fn send_hello<W: Write>(w: &mut W, genesis_id: &[u8; 32]) -> Result<(), HelloHandshakeError> {
    let hello = HelloV1 {
        genesis_id: *genesis_id,
    };
    write_frame_io(w, &hello.encode())?;
    w.flush()?;
    Ok(())
}

/// Read one frame and decode it as [`HelloV1`] (no genesis check).
pub fn recv_hello<R: Read>(r: &mut R) -> Result<HelloV1, HelloHandshakeError> {
    let payload = read_frame(r)?;
    Ok(HelloV1::decode(&payload)?)
}

/// Read one [`HelloV1`] and require `hello.genesis_id == *expected_genesis`.
pub fn recv_hello_expect<R: Read>(
    r: &mut R,
    expected_genesis: &[u8; 32],
) -> Result<HelloV1, HelloHandshakeError> {
    let h = recv_hello(r)?;
    if h.genesis_id != *expected_genesis {
        return Err(HelloHandshakeError::GenesisMismatch {
            expected: *expected_genesis,
            got: h.genesis_id,
        });
    }
    Ok(h)
}

/// Symmetric handshake: send our [`HelloV1`], then read the peer's and verify same genesis.
///
/// Both peers must call this with the same `genesis_id` (typically `Chain::genesis_id()`).
/// Ordering is send-then-recv on each side; TCP full-duplex allows both sends to complete
/// before either read blocks.
pub fn hello_v1_handshake<S: Read + Write>(
    stream: &mut S,
    genesis_id: &[u8; 32],
) -> Result<(), HelloHandshakeError> {
    send_hello(stream, genesis_id)?;
    recv_hello_expect(stream, genesis_id)?;
    Ok(())
}

/// [`TcpStream::connect`] to `addrs`, then run [`hello_v1_handshake`] on the connected stream.
///
/// On success returns the open `TcpStream` positioned after the handshake (no extra bytes
/// consumed beyond the peer's hello frame).
pub fn tcp_connect_hello_v1_handshake<A: ToSocketAddrs>(
    addrs: A,
    genesis_id: &[u8; 32],
) -> Result<TcpStream, HelloHandshakeError> {
    let mut stream = TcpStream::connect(addrs)?;
    let _ = stream.set_read_timeout(Some(P2P_HANDSHAKE_IO_TIMEOUT));
    let _ = stream.set_write_timeout(Some(P2P_HANDSHAKE_IO_TIMEOUT));
    hello_v1_handshake(&mut stream, genesis_id)?;
    Ok(stream)
}

/// After [`hello_v1_handshake`], **dialer** sends [`PingV1`] and reads [`PongV1`].
pub fn send_ping_recv_pong<S: Read + Write>(stream: &mut S) -> Result<(), HelloHandshakeError> {
    write_frame_io(stream, &PingV1.encode())?;
    stream.flush()?;
    let payload = read_frame(stream)?;
    PongV1::decode(&payload)?;
    Ok(())
}

/// After [`hello_v1_handshake`], **listener** reads [`PingV1`] and sends [`PongV1`].
pub fn recv_ping_send_pong<S: Read + Write>(stream: &mut S) -> Result<(), HelloHandshakeError> {
    let payload = read_frame(stream)?;
    PingV1::decode(&payload)?;
    write_frame_io(stream, &PongV1.encode())?;
    stream.flush()?;
    Ok(())
}

/// Write one framed [`ChainTipV1`] after ping/pong (**M2.3.8**).
pub fn send_chain_tip_v1<W: Write>(w: &mut W, tip: &ChainTipV1) -> Result<(), HelloHandshakeError> {
    write_frame_io(w, &tip.encode())?;
    w.flush()?;
    Ok(())
}

/// Read one [`ChainTipV1`] frame after ping/pong.
pub fn recv_chain_tip_v1<R: Read>(r: &mut R) -> Result<ChainTipV1, HelloHandshakeError> {
    let payload = read_frame(r)?;
    Ok(ChainTipV1::decode(&payload)?)
}

/// Dialer order after pong: send local tip, read peer tip.
pub fn exchange_chain_tip_v1_as_dialer<S: Read + Write>(
    stream: &mut S,
    local: &ChainTipV1,
) -> Result<ChainTipV1, HelloHandshakeError> {
    send_chain_tip_v1(stream, local)?;
    recv_chain_tip_v1(stream)
}

/// Listener order after pong: read peer tip, send local tip.
pub fn exchange_chain_tip_v1_as_listener<S: Read + Write>(
    stream: &mut S,
    local: &ChainTipV1,
) -> Result<ChainTipV1, HelloHandshakeError> {
    let remote = recv_chain_tip_v1(stream)?;
    send_chain_tip_v1(stream, local)?;
    Ok(remote)
}

/// After [`exchange_chain_tip_v1_as_dialer`], **dialer** sends [`GoodbyeV1`] then reads one back (**M2.3.10**).
pub fn exchange_goodbye_v1_as_dialer<S: Read + Write>(
    stream: &mut S,
) -> Result<(), HelloHandshakeError> {
    write_frame_io(stream, &GoodbyeV1.encode())?;
    stream.flush()?;
    let payload = read_frame(stream)?;
    GoodbyeV1::decode(&payload)?;
    Ok(())
}

/// After [`exchange_chain_tip_v1_as_listener`], **listener** reads [`GoodbyeV1`] then sends one (**M2.3.10**).
pub fn exchange_goodbye_v1_as_listener<S: Read + Write>(
    stream: &mut S,
) -> Result<(), HelloHandshakeError> {
    let payload = read_frame(stream)?;
    GoodbyeV1::decode(&payload)?;
    write_frame_io(stream, &GoodbyeV1.encode())?;
    stream.flush()?;
    Ok(())
}

/// [`TcpStream::connect`] + [`hello_v1_handshake`] + [`send_ping_recv_pong`] (full dialer path).
pub fn tcp_connect_peer_v1_handshake<A: ToSocketAddrs>(
    addrs: A,
    genesis_id: &[u8; 32],
) -> Result<TcpStream, HelloHandshakeError> {
    let mut stream = TcpStream::connect(addrs)?;
    let _ = stream.set_read_timeout(Some(P2P_HANDSHAKE_IO_TIMEOUT));
    let _ = stream.set_write_timeout(Some(P2P_HANDSHAKE_IO_TIMEOUT));
    hello_v1_handshake(&mut stream, genesis_id)?;
    send_ping_recv_pong(&mut stream)?;
    Ok(stream)
}

/// Like [`tcp_connect_peer_v1_handshake`], then exchanges [`ChainTipV1`] with the peer (**M2.3.8**),
/// then runs [`exchange_goodbye_v1_as_dialer`] (**M2.3.10**).
///
/// Returns the open stream (positioned after the peer's goodbye frame) and the **remote** tip.
pub fn tcp_connect_peer_v1_handshake_with_tip_exchange<A: ToSocketAddrs>(
    addrs: A,
    genesis_id: &[u8; 32],
    local_tip: &ChainTipV1,
) -> Result<(TcpStream, ChainTipV1), HelloHandshakeError> {
    let mut stream = TcpStream::connect(addrs)?;
    let _ = stream.set_read_timeout(Some(P2P_HANDSHAKE_IO_TIMEOUT));
    let _ = stream.set_write_timeout(Some(P2P_HANDSHAKE_IO_TIMEOUT));
    hello_v1_handshake(&mut stream, genesis_id)?;
    send_ping_recv_pong(&mut stream)?;
    let remote = exchange_chain_tip_v1_as_dialer(&mut stream, local_tip)?;
    exchange_goodbye_v1_as_dialer(&mut stream)?;
    Ok((stream, remote))
}

#[cfg(test)]
mod tests {
    use super::super::frame::{write_frame_io, HelloV1 as FrameHello};
    use super::*;
    use std::net::{TcpListener, TcpStream};
    use std::thread;
    use std::time::Duration;

    #[test]
    fn hello_v1_handshake_tcp_round_trip() {
        let genesis = [0xabu8; 32];
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        let server = thread::spawn(move || {
            let (mut sock, _) = listener.accept().unwrap();
            sock.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
            sock.set_write_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            hello_v1_handshake(&mut sock, &genesis)
        });

        let mut client = TcpStream::connect(addr).unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        client
            .set_write_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        hello_v1_handshake(&mut client, &genesis).unwrap();

        server.join().unwrap().unwrap();
    }

    #[test]
    fn tcp_connect_hello_v1_handshake_round_trip() {
        let genesis = [0xcdu8; 32];
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        let server = thread::spawn(move || {
            let (mut sock, _) = listener.accept().unwrap();
            sock.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
            sock.set_write_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            hello_v1_handshake(&mut sock, &genesis)
        });

        let client = tcp_connect_hello_v1_handshake(addr, &genesis).unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        client
            .set_write_timeout(Some(Duration::from_secs(5)))
            .unwrap();

        server.join().unwrap().unwrap();
    }

    #[test]
    fn tcp_peer_v1_handshake_round_trip() {
        let genesis = [0x11u8; 32];
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        let server = thread::spawn(move || {
            let (mut sock, _) = listener.accept().unwrap();
            sock.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
            sock.set_write_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            hello_v1_handshake(&mut sock, &genesis)?;
            recv_ping_send_pong(&mut sock)
        });

        let _ = tcp_connect_peer_v1_handshake(addr, &genesis).unwrap();

        server.join().unwrap().unwrap();
    }

    #[test]
    fn tcp_peer_v1_handshake_with_tip_exchange_round_trip() {
        use super::super::frame::ChainTipV1;
        let genesis = [0x33u8; 32];
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        let listener_tip = ChainTipV1 {
            height: 100,
            tip_id: [0xaau8; 32],
        };
        let dial_tip = ChainTipV1 {
            height: 7,
            tip_id: [0xbbu8; 32],
        };
        let expect_remote = listener_tip;

        let server = thread::spawn(move || {
            let (mut sock, _) = listener.accept().unwrap();
            sock.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
            sock.set_write_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            hello_v1_handshake(&mut sock, &genesis)?;
            recv_ping_send_pong(&mut sock)?;
            let remote = exchange_chain_tip_v1_as_listener(&mut sock, &listener_tip)?;
            exchange_goodbye_v1_as_listener(&mut sock)?;
            assert_eq!(remote, dial_tip);
            Ok::<(), HelloHandshakeError>(())
        });

        let (_stream, remote) =
            tcp_connect_peer_v1_handshake_with_tip_exchange(addr, &genesis, &dial_tip).unwrap();
        assert_eq!(remote, expect_remote);
        server.join().unwrap().unwrap();
    }

    #[test]
    fn tcp_connect_peer_v1_handshake_sets_io_timeouts() {
        let genesis = [0x22u8; 32];
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        let server = thread::spawn(move || {
            let (mut sock, _) = listener.accept().unwrap();
            sock.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
            sock.set_write_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            hello_v1_handshake(&mut sock, &genesis)?;
            recv_ping_send_pong(&mut sock)
        });

        let sock = tcp_connect_peer_v1_handshake(addr, &genesis).unwrap();
        assert_eq!(
            sock.read_timeout().expect("read_timeout"),
            Some(P2P_HANDSHAKE_IO_TIMEOUT)
        );
        assert_eq!(
            sock.write_timeout().expect("write_timeout"),
            Some(P2P_HANDSHAKE_IO_TIMEOUT)
        );

        server.join().unwrap().unwrap();
    }

    #[test]
    fn recv_hello_expect_rejects_foreign_genesis() {
        let local = [1u8; 32];
        let foreign = [2u8; 32];
        let mut buf: Vec<u8> = Vec::new();
        write_frame_io(
            &mut buf,
            &FrameHello {
                genesis_id: foreign,
            }
            .encode(),
        )
        .unwrap();
        let mut cur = std::io::Cursor::new(buf);
        let err = recv_hello_expect(&mut cur, &local).unwrap_err();
        match err {
            HelloHandshakeError::GenesisMismatch { expected, got } => {
                assert_eq!(expected, local);
                assert_eq!(got, foreign);
            }
            e => panic!("unexpected error: {e:?}"),
        }
    }

    #[test]
    fn recv_hello_rejects_non_hello_payload() {
        let mut buf: Vec<u8> = Vec::new();
        write_frame_io(&mut buf, b"not-a-hello").unwrap();
        let mut cur = std::io::Cursor::new(buf);
        assert!(recv_hello(&mut cur)
            .unwrap_err()
            .to_string()
            .contains("hello"));
    }
}
