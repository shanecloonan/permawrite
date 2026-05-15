//! Symmetric [`HelloV1`](super::HelloV1) exchange over a duplex byte stream (**M2.3.2**).
//! **M2.3.4** adds [`tcp_connect_hello_v1_handshake`] for outbound TCP dials.
//!
//! Each side sends one length-prefixed [`HelloV1`] frame, then reads the peer's frame and
//! checks the advertised genesis id matches the chain id both sides intend to speak.

use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};

use super::frame::{
    read_frame, write_frame_io, FrameReadError, FrameWriteError, HelloDecodeError, HelloV1,
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
    hello_v1_handshake(&mut stream, genesis_id)?;
    Ok(stream)
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
