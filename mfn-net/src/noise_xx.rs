//! Noise_XX_25519_ChaChaPoly_SHA256 session for P2P (**Seat D**).
//!
//! The pattern is the Noise XX handshake: each side has a static X25519 key and
//! an ephemeral. After three messages the transport keys are split and every
//! later byte is ChaCha20-Poly1305. A passive recorder sees the ephemeral
//! publics and ciphertext. A peer who does not hold the static secret cannot
//! finish the handshake, so it cannot impersonate that node.
//!
//! Cleartext peers stay on the existing hello path. Encrypted peers send the
//! four-byte marker [`SESSION_MARKER`] first.

use std::io::{Read, Write};
use std::path::Path;
use std::sync::{Mutex, OnceLock};

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use hkdf::Hkdf;
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroize;

/// First four bytes on the socket when this session is encrypted.
pub const SESSION_MARKER: &[u8; 4] = b"MFNS";
/// Environment flag. `1` / `true` / `yes` / `on` installs a static key.
pub const MFND_P2P_ENCRYPT_ENV: &str = "MFND_P2P_ENCRYPT";

const PROTOCOL: &str = "Noise_XX_25519_ChaChaPoly_SHA256";
const MAX_TRANSPORT_PLAINTEXT: usize = 64 * 1024;

static LOCAL_IDENTITY: OnceLock<StaticSecret> = OnceLock::new();
static PINNED_PEERS: Mutex<Vec<([u8; 32], [u8; 32])>> = Mutex::new(Vec::new());

/// A node's long-term X25519 secret.
pub struct SessionIdentity {
    secret: StaticSecret,
}

impl SessionIdentity {
    /// 32-byte secret. The public key is [`SessionIdentity::public_bytes`].
    pub fn from_secret_bytes(bytes: [u8; 32]) -> Self {
        Self {
            secret: StaticSecret::from(bytes),
        }
    }

    /// Fresh key from the operating system RNG.
    pub fn generate() -> Result<Self, String> {
        let mut bytes = [0u8; 32];
        getrandom::getrandom(&mut bytes).map_err(|e| format!("session key rng: {e}"))?;
        let identity = Self::from_secret_bytes(bytes);
        bytes.zeroize();
        Ok(identity)
    }

    /// X25519 public key.
    pub fn public_bytes(&self) -> [u8; 32] {
        PublicKey::from(&self.secret).to_bytes()
    }

    fn secret(&self) -> &StaticSecret {
        &self.secret
    }
}

/// Install `identity` as the process session key. A second call keeps the first.
pub fn install_session_identity(identity: SessionIdentity) {
    let _ = LOCAL_IDENTITY.set(identity.secret);
}

/// Whether [`install_session_identity`] has run.
pub fn encryption_configured() -> bool {
    LOCAL_IDENTITY.get().is_some()
}

/// Load or create `path` (32 raw bytes) and install it. No-op when the flag is off.
pub fn install_session_key_file(path: &Path) -> Result<bool, String> {
    if !encrypt_flag_on()? {
        return Ok(false);
    }
    if encryption_configured() {
        return Ok(true);
    }
    let identity = if path.is_file() {
        let bytes = std::fs::read(path).map_err(|e| format!("read session key: {e}"))?;
        if bytes.len() != 32 {
            return Err(format!("session key {} must be 32 bytes", path.display()));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        SessionIdentity::from_secret_bytes(arr)
    } else {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| format!("session key dir: {e}"))?;
        }
        let identity = SessionIdentity::generate()?;
        std::fs::write(path, identity.secret().to_bytes())
            .map_err(|e| format!("write session key: {e}"))?;
        identity
    };
    install_session_identity(identity);
    Ok(true)
}

fn encrypt_flag_on() -> Result<bool, String> {
    match std::env::var(MFND_P2P_ENCRYPT_ENV) {
        Ok(raw) => match raw.trim().to_ascii_lowercase().as_str() {
            "1" | "true" | "yes" | "on" => Ok(true),
            "0" | "false" | "no" | "off" | "" => Ok(false),
            other => Err(format!(
                "{MFND_P2P_ENCRYPT_ENV}={other:?} must be 1/0, true/false, yes/no, or on/off"
            )),
        },
        Err(std::env::VarError::NotPresent) => Ok(false),
        Err(std::env::VarError::NotUnicode(_)) => {
            Err(format!("{MFND_P2P_ENCRYPT_ENV} must be valid UTF-8"))
        }
    }
}

fn local_secret() -> Option<StaticSecret> {
    LOCAL_IDENTITY
        .get()
        .map(|s| StaticSecret::from(s.to_bytes()))
}

/// Remember `remote_static` for `peer`. A different key later is impersonation.
pub fn pin_remote_static(peer: &[u8; 32], remote_static: &[u8; 32]) -> Result<(), String> {
    let Ok(mut guard) = PINNED_PEERS.lock() else {
        return Err("session pin lock poisoned".into());
    };
    if let Some((_, pinned)) = guard.iter().find(|(id, _)| id == peer) {
        if pinned != remote_static {
            return Err("remote static key changed; refusing the new key".into());
        }
        return Ok(());
    }
    guard.push((*peer, *remote_static));
    Ok(())
}

/// Bidirectional encrypted pipe. Each `write` is one Noise transport message.
pub struct SealedStream<S> {
    inner: S,
    send_key: [u8; 32],
    send_n: u64,
    recv_key: [u8; 32],
    recv_n: u64,
    pending: Vec<u8>,
    pending_at: usize,
    remote: [u8; 32],
}

impl<S> SealedStream<S> {
    fn new(inner: S, send_key: [u8; 32], recv_key: [u8; 32], remote: [u8; 32]) -> Self {
        Self {
            inner,
            send_key,
            send_n: 0,
            recv_key,
            recv_n: 0,
            pending: Vec::new(),
            pending_at: 0,
            remote,
        }
    }

    /// Static public key authenticated by the handshake.
    pub fn remote_static(&self) -> [u8; 32] {
        self.remote
    }
}

impl<S> Drop for SealedStream<S> {
    fn drop(&mut self) {
        self.send_key.zeroize();
        self.recv_key.zeroize();
    }
}

impl<S: Write> Write for SealedStream<S> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let mut offset = 0;
        while offset < buf.len() {
            let end = (offset + MAX_TRANSPORT_PLAINTEXT).min(buf.len());
            write_transport(
                &mut self.inner,
                &self.send_key,
                &mut self.send_n,
                &buf[offset..end],
            )?;
            offset = end;
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

impl<S: Read> Read for SealedStream<S> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.pending_at >= self.pending.len() {
            self.pending = read_transport(&mut self.inner, &self.recv_key, &mut self.recv_n)?;
            self.pending_at = 0;
            if self.pending.is_empty() {
                return Ok(0);
            }
        }
        let available = &self.pending[self.pending_at..];
        let n = available.len().min(buf.len());
        buf[..n].copy_from_slice(&available[..n]);
        self.pending_at += n;
        Ok(n)
    }
}

/// Dial-side handshake. `expected_remote` rejects any other static key.
pub fn handshake_initiator<S: Read + Write>(
    mut stream: S,
    local: &StaticSecret,
    ephemeral: &StaticSecret,
    expected_remote: Option<&[u8; 32]>,
) -> Result<SealedStream<S>, String> {
    let mut hs = Handshake::new(true, local, ephemeral);
    let msg1 = hs.write_initiator_msg1();
    write_exact_all(&mut stream, &msg1)?;
    let mut msg2 = [0u8; 80];
    stream
        .read_exact(&mut msg2)
        .map_err(|e| format!("noise msg2: {e}"))?;
    hs.read_initiator_msg2(&msg2)?;
    let msg3 = hs.write_initiator_msg3()?;
    write_exact_all(&mut stream, &msg3)?;
    finish(stream, hs, expected_remote)
}

/// Listen-side handshake.
pub fn handshake_responder<S: Read + Write>(
    mut stream: S,
    local: &StaticSecret,
    ephemeral: &StaticSecret,
    expected_remote: Option<&[u8; 32]>,
) -> Result<SealedStream<S>, String> {
    let mut hs = Handshake::new(false, local, ephemeral);
    let mut msg1 = [0u8; 32];
    stream
        .read_exact(&mut msg1)
        .map_err(|e| format!("noise msg1: {e}"))?;
    hs.read_responder_msg1(&msg1);
    let msg2 = hs.write_responder_msg2()?;
    write_exact_all(&mut stream, &msg2)?;
    let mut msg3 = [0u8; 48];
    stream
        .read_exact(&mut msg3)
        .map_err(|e| format!("noise msg3: {e}"))?;
    hs.read_responder_msg3(&msg3)?;
    finish(stream, hs, expected_remote)
}

fn finish<S>(
    stream: S,
    hs: Handshake,
    expected_remote: Option<&[u8; 32]>,
) -> Result<SealedStream<S>, String> {
    let remote = hs
        .remote_static
        .ok_or("handshake finished without a remote static key")?
        .to_bytes();
    if let Some(expected) = expected_remote {
        if &remote != expected {
            return Err("remote static key does not match the pinned identity".into());
        }
    }
    let (send, recv) = hs.split();
    Ok(SealedStream::new(stream, send, recv, remote))
}

struct Handshake {
    ck: [u8; 32],
    h: [u8; 32],
    k: Option<[u8; 32]>,
    n: u64,
    initiator: bool,
    local_static: StaticSecret,
    local_ephemeral: StaticSecret,
    remote_ephemeral: Option<PublicKey>,
    remote_static: Option<PublicKey>,
}

impl Handshake {
    fn new(initiator: bool, local_static: &StaticSecret, local_ephemeral: &StaticSecret) -> Self {
        let h = if PROTOCOL.len() <= 32 {
            let mut name = [0u8; 32];
            name[..PROTOCOL.len()].copy_from_slice(PROTOCOL.as_bytes());
            name
        } else {
            Sha256::digest(PROTOCOL.as_bytes()).into()
        };
        Self {
            ck: h,
            h,
            k: None,
            n: 0,
            initiator,
            local_static: StaticSecret::from(local_static.to_bytes()),
            local_ephemeral: StaticSecret::from(local_ephemeral.to_bytes()),
            remote_ephemeral: None,
            remote_static: None,
        }
    }

    fn mix_hash(&mut self, data: &[u8]) {
        let mut hasher = Sha256::new();
        hasher.update(self.h);
        hasher.update(data);
        self.h = hasher.finalize().into();
    }

    fn mix_key(&mut self, ikm: &[u8]) {
        let (ck, temp) = hkdf2(&self.ck, ikm);
        self.ck = ck;
        self.k = Some(temp);
        self.n = 0;
    }

    fn encrypt_and_hash(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, String> {
        let ciphertext = if let Some(key) = self.k {
            let ct = aead_encrypt(&key, self.n, &self.h, plaintext)?;
            self.n = self.n.saturating_add(1);
            ct
        } else {
            plaintext.to_vec()
        };
        self.mix_hash(&ciphertext);
        Ok(ciphertext)
    }

    fn decrypt_and_hash(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, String> {
        let plaintext = if let Some(key) = self.k {
            let pt = aead_decrypt(&key, self.n, &self.h, ciphertext)?;
            self.n = self.n.saturating_add(1);
            pt
        } else {
            ciphertext.to_vec()
        };
        self.mix_hash(ciphertext);
        Ok(plaintext)
    }

    fn write_initiator_msg1(&mut self) -> [u8; 32] {
        let public = PublicKey::from(&self.local_ephemeral);
        self.mix_hash(public.as_bytes());
        public.to_bytes()
    }

    fn read_responder_msg1(&mut self, msg: &[u8; 32]) {
        self.remote_ephemeral = Some(PublicKey::from(*msg));
        self.mix_hash(msg);
    }

    fn write_responder_msg2(&mut self) -> Result<[u8; 80], String> {
        let eph = PublicKey::from(&self.local_ephemeral).to_bytes();
        self.mix_hash(&eph);
        let remote_e = self.remote_ephemeral.ok_or("missing remote ephemeral")?;
        self.mix_key(self.local_ephemeral.diffie_hellman(&remote_e).as_bytes());
        let static_public = PublicKey::from(&self.local_static).to_bytes();
        let encrypted_static = self.encrypt_and_hash(&static_public)?;
        if encrypted_static.len() != 48 {
            return Err("encrypted static key must be 48 bytes".into());
        }
        self.mix_key(self.local_static.diffie_hellman(&remote_e).as_bytes());
        let mut out = [0u8; 80];
        out[..32].copy_from_slice(&eph);
        out[32..].copy_from_slice(&encrypted_static);
        Ok(out)
    }

    fn read_initiator_msg2(&mut self, msg: &[u8; 80]) -> Result<(), String> {
        let mut eph = [0u8; 32];
        eph.copy_from_slice(&msg[..32]);
        self.remote_ephemeral = Some(PublicKey::from(eph));
        self.mix_hash(&eph);
        let remote_e = PublicKey::from(eph);
        self.mix_key(self.local_ephemeral.diffie_hellman(&remote_e).as_bytes());
        let static_public = self.decrypt_and_hash(&msg[32..])?;
        if static_public.len() != 32 {
            return Err("remote static key length".into());
        }
        let mut raw = [0u8; 32];
        raw.copy_from_slice(&static_public);
        let remote_static = PublicKey::from(raw);
        self.remote_static = Some(remote_static);
        self.mix_key(
            self.local_ephemeral
                .diffie_hellman(&remote_static)
                .as_bytes(),
        );
        Ok(())
    }

    fn write_initiator_msg3(&mut self) -> Result<[u8; 48], String> {
        let static_public = PublicKey::from(&self.local_static).to_bytes();
        let encrypted = self.encrypt_and_hash(&static_public)?;
        let remote_e = self.remote_ephemeral.ok_or("missing remote ephemeral")?;
        self.mix_key(self.local_static.diffie_hellman(&remote_e).as_bytes());
        if encrypted.len() != 48 {
            return Err("encrypted static key must be 48 bytes".into());
        }
        let mut out = [0u8; 48];
        out.copy_from_slice(&encrypted);
        Ok(out)
    }

    fn read_responder_msg3(&mut self, msg: &[u8; 48]) -> Result<(), String> {
        let static_public = self.decrypt_and_hash(msg)?;
        if static_public.len() != 32 {
            return Err("remote static key length".into());
        }
        let mut raw = [0u8; 32];
        raw.copy_from_slice(&static_public);
        let remote_static = PublicKey::from(raw);
        self.remote_static = Some(remote_static);
        self.mix_key(
            self.local_ephemeral
                .diffie_hellman(&remote_static)
                .as_bytes(),
        );
        Ok(())
    }

    fn split(&self) -> ([u8; 32], [u8; 32]) {
        let (a, b) = hkdf2(&self.ck, &[]);
        if self.initiator {
            (a, b)
        } else {
            (b, a)
        }
    }
}

fn hkdf2(ck: &[u8; 32], ikm: &[u8]) -> ([u8; 32], [u8; 32]) {
    let hk = Hkdf::<Sha256>::new(Some(ck), ikm);
    let mut okm = [0u8; 64];
    if hk.expand(&[], &mut okm).is_err() {
        okm = [0; 64];
        okm[..32].copy_from_slice(&Sha256::digest(ck));
        okm[32..].copy_from_slice(&Sha256::digest(ikm));
    }
    let mut a = [0u8; 32];
    let mut b = [0u8; 32];
    a.copy_from_slice(&okm[..32]);
    b.copy_from_slice(&okm[32..]);
    (a, b)
}

fn aead_encrypt(key: &[u8; 32], n: u64, ad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, String> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    cipher
        .encrypt(
            Nonce::from_slice(&nonce_bytes(n)),
            Payload {
                msg: plaintext,
                aad: ad,
            },
        )
        .map_err(|_| "transport encrypt failed".to_string())
}

fn aead_decrypt(key: &[u8; 32], n: u64, ad: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, String> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    cipher
        .decrypt(
            Nonce::from_slice(&nonce_bytes(n)),
            Payload {
                msg: ciphertext,
                aad: ad,
            },
        )
        .map_err(|_| "transport decrypt failed".to_string())
}

fn nonce_bytes(n: u64) -> [u8; 12] {
    let mut nonce = [0u8; 12];
    nonce[4..].copy_from_slice(&n.to_le_bytes());
    nonce
}

fn write_transport<S: Write>(
    stream: &mut S,
    key: &[u8; 32],
    n: &mut u64,
    plaintext: &[u8],
) -> std::io::Result<()> {
    let ct = aead_encrypt(key, *n, &[], plaintext)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    *n = n.saturating_add(1);
    let len = u32::try_from(ct.len()).unwrap_or(u32::MAX);
    stream.write_all(&len.to_be_bytes())?;
    stream.write_all(&ct)?;
    Ok(())
}

fn read_transport<S: Read>(
    stream: &mut S,
    key: &[u8; 32],
    n: &mut u64,
) -> std::io::Result<Vec<u8>> {
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf)?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > MAX_TRANSPORT_PLAINTEXT + 16 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "encrypted frame exceeds cap",
        ));
    }
    let mut ct = vec![0u8; len];
    stream.read_exact(&mut ct)?;
    let pt = aead_decrypt(key, *n, &[], &ct)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    *n = n.saturating_add(1);
    Ok(pt)
}

fn write_exact_all<S: Write>(stream: &mut S, bytes: &[u8]) -> Result<(), String> {
    stream
        .write_all(bytes)
        .map_err(|e| format!("noise write: {e}"))?;
    stream.flush().map_err(|e| format!("noise flush: {e}"))?;
    Ok(())
}

/// Run the initiator handshake on `stream` using the installed identity.
pub fn seal_as_initiator<S: Read + Write>(
    stream: S,
    expected_remote: Option<&[u8; 32]>,
) -> Result<SealedStream<S>, String> {
    let local = local_secret().ok_or("P2P session encryption is not configured")?;
    let ephemeral = SessionIdentity::generate()?.secret;
    let ephemeral = StaticSecret::from(ephemeral.to_bytes());
    handshake_initiator(stream, &local, &ephemeral, expected_remote)
}

/// Full dial: Noise handshake, then hello, ping, tip, goodbye, and one tx frame.
pub fn dial_encrypted_tx<S: Read + Write>(
    stream: S,
    genesis_id: &[u8; 32],
    local_tip: &crate::frame::ChainTipV1,
    tx_wire: &[u8],
    stem: bool,
) -> Result<(), String> {
    let mut sealed = seal_as_initiator(stream, None)?;
    crate::handshake::hello_v1_handshake(&mut sealed, genesis_id).map_err(|e| e.to_string())?;
    crate::handshake::send_ping_recv_pong(&mut sealed).map_err(|e| e.to_string())?;
    crate::handshake::exchange_chain_tip_v1_as_dialer(&mut sealed, local_tip)
        .map_err(|e| e.to_string())?;
    crate::handshake::exchange_goodbye_v1_as_dialer(&mut sealed).map_err(|e| e.to_string())?;
    if stem {
        crate::gossip::send_tx_stem_v1(&mut sealed, tx_wire).map_err(|e| e.to_string())?;
    } else {
        crate::gossip::send_tx_v1(&mut sealed, tx_wire).map_err(|e| e.to_string())?;
    }
    crate::gossip::send_gossip_end_v1(&mut sealed).map_err(|e| e.to_string())?;
    Ok(())
}

/// Full accept: Noise handshake, then the listener handshake, then gossip.
pub fn accept_encrypted_session<S: Read + Write>(
    stream: S,
    genesis_id: &[u8; 32],
    local_tip: &crate::frame::ChainTipV1,
    handler: &dyn crate::gossip::GossipHandler,
) -> Result<crate::frame::ChainTipV1, String> {
    let mut sealed = seal_as_responder(stream, None)?;
    crate::handshake::hello_v1_handshake(&mut sealed, genesis_id).map_err(|e| e.to_string())?;
    crate::handshake::recv_ping_send_pong(&mut sealed).map_err(|e| e.to_string())?;
    let remote = crate::handshake::exchange_chain_tip_v1_as_listener(&mut sealed, local_tip)
        .map_err(|e| e.to_string())?;
    crate::handshake::exchange_goodbye_v1_as_listener(&mut sealed).map_err(|e| e.to_string())?;
    crate::gossip::recv_gossip_v1(&mut sealed, handler).map_err(|e| e.to_string())?;
    Ok(remote)
}

/// Run the responder handshake on `stream` using the installed identity.
pub fn seal_as_responder<S: Read + Write>(
    stream: S,
    expected_remote: Option<&[u8; 32]>,
) -> Result<SealedStream<S>, String> {
    let local = local_secret().ok_or("P2P session encryption is not configured")?;
    let ephemeral = SessionIdentity::generate()?.secret;
    let ephemeral = StaticSecret::from(ephemeral.to_bytes());
    handshake_responder(stream, &local, &ephemeral, expected_remote)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    use std::net::TcpListener;
    use std::thread;

    fn secret(byte: u8) -> StaticSecret {
        StaticSecret::from([byte; 32])
    }

    #[test]
    fn both_sides_share_transport_keys_and_reject_a_flipped_bit() {
        let init_static = secret(0x11);
        let resp_static = secret(0x22);
        let init_eph = secret(0x33);
        let resp_eph = secret(0x44);
        let mut initiator_log = Vec::new();
        let mut responder_log = Vec::new();
        let mut hs_i = Handshake::new(true, &init_static, &init_eph);
        let mut hs_r = Handshake::new(false, &resp_static, &resp_eph);
        let msg1 = hs_i.write_initiator_msg1();
        initiator_log.extend_from_slice(&msg1);
        hs_r.read_responder_msg1(&msg1);
        let msg2 = hs_r.write_responder_msg2().unwrap();
        responder_log.extend_from_slice(&msg2);
        hs_i.read_initiator_msg2(&msg2).unwrap();
        let msg3 = hs_i.write_initiator_msg3().unwrap();
        initiator_log.extend_from_slice(&msg3);
        hs_r.read_responder_msg3(&msg3).unwrap();
        let (i_send, i_recv) = hs_i.split();
        let (r_send, r_recv) = hs_r.split();
        assert_eq!(i_send, r_recv);
        assert_eq!(i_recv, r_send);
        let secret_tx = b"mfnd-secret-tx-origin-should-stay-hidden";
        assert!(!initiator_log
            .windows(secret_tx.len())
            .any(|w| w == secret_tx));
        let mut cipher_log = Vec::new();
        {
            let mut n = 0u64;
            write_transport(&mut cipher_log, &i_send, &mut n, secret_tx).unwrap();
        }
        assert!(!cipher_log.windows(secret_tx.len()).any(|w| w == secret_tx));
        let mut n = 0u64;
        let plain = read_transport(&mut Cursor::new(cipher_log.clone()), &r_recv, &mut n).unwrap();
        assert_eq!(plain, secret_tx);
        let mut flipped = cipher_log.clone();
        let last = flipped.len() - 1;
        flipped[last] ^= 0x01;
        let mut n = 0u64;
        assert!(read_transport(&mut Cursor::new(flipped), &r_recv, &mut n).is_err());
        let _ = responder_log;
    }

    #[test]
    fn pinned_static_key_rejects_an_impostor() {
        let alice = secret(0x01);
        let bob = secret(0x02);
        let alice_pub = PublicKey::from(&alice).to_bytes();
        let bob_pub = PublicKey::from(&bob).to_bytes();
        let (client, server) = duplex().unwrap();
        let server_thread = thread::spawn(move || {
            handshake_responder(server, &bob, &secret(0x42), Some(&alice_pub))
                .map(|s| s.remote_static())
        });
        let ok = handshake_initiator(client, &alice, &secret(0x41), Some(&bob_pub)).unwrap();
        assert_eq!(ok.remote_static(), bob_pub);
        assert_eq!(server_thread.join().unwrap().unwrap(), alice_pub);

        let bob = secret(0x02);
        let carol = secret(0x03);
        let (client, server) = duplex().unwrap();
        let server_thread = thread::spawn(move || {
            handshake_responder(server, &bob, &secret(0x52), Some(&alice_pub))
        });
        let _client = handshake_initiator(client, &carol, &secret(0x51), Some(&bob_pub));
        let server_result = server_thread.join().unwrap();
        assert!(server_result.is_err());
    }

    #[test]
    fn two_nodes_hide_the_transaction_from_the_socket_log() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let alice = secret(0x0a);
        let bob = secret(0x0b);
        let alice_pub = PublicKey::from(&alice).to_bytes();
        let bob_pub = PublicKey::from(&bob).to_bytes();
        let secret_tx = b"mfnd-secret-tx-7f3a";
        let joined = thread::spawn(move || {
            let (sock, _) = listener.accept().unwrap();
            let log = ArcLog::new();
            let tee = Tee {
                inner: sock,
                log: log.clone(),
            };
            let mut sealed =
                handshake_responder(tee, &bob, &secret(0x62), Some(&alice_pub)).unwrap();
            let mut got = vec![0u8; secret_tx.len()];
            use std::io::Read as _;
            sealed.read_exact(&mut got).unwrap();
            (log.bytes(), got)
        });
        let sock = std::net::TcpStream::connect(addr).unwrap();
        let log = ArcLog::new();
        let tee = Tee {
            inner: sock,
            log: log.clone(),
        };
        let mut sealed = handshake_initiator(tee, &alice, &secret(0x61), Some(&bob_pub)).unwrap();
        use std::io::Write as _;
        sealed.write_all(secret_tx).unwrap();
        sealed.flush().unwrap();
        drop(sealed);
        let (server_log, got) = joined.join().unwrap();
        assert_eq!(got, secret_tx);
        assert!(!log.bytes().windows(secret_tx.len()).any(|w| w == secret_tx));
        assert!(!server_log.windows(secret_tx.len()).any(|w| w == secret_tx));
    }

    #[test]
    fn wired_dial_and_accept_deliver_the_transaction() {
        install_session_identity(SessionIdentity::from_secret_bytes([0x7e; 32]));
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let genesis = [0x11u8; 32];
        let tip = crate::frame::ChainTipV1 {
            height: 3,
            tip_id: [0x22; 32],
        };
        use std::io::Write as _;
        let tx = b"wired-secret-tx".to_vec();
        let tx_for_server = tx.clone();
        let server = thread::spawn(move || {
            use std::io::Read as _;
            let (mut sock, _) = listener.accept().unwrap();
            let mut magic = [0u8; 4];
            sock.read_exact(&mut magic).unwrap();
            assert_eq!(&magic, SESSION_MARKER);
            struct Collect(std::sync::Mutex<Vec<u8>>);
            impl crate::gossip::GossipHandler for Collect {
                fn on_tx_v1(&self, tx_wire: &[u8]) -> String {
                    *self.0.lock().unwrap() = tx_wire.to_vec();
                    "fresh:abc".into()
                }
                fn on_block_v1(&self, _: &[u8]) -> String {
                    "block".into()
                }
            }
            let collect = Collect(std::sync::Mutex::new(Vec::new()));
            accept_encrypted_session(&mut sock, &genesis, &tip, &collect).unwrap();
            collect.0.into_inner().unwrap()
        });
        let mut sock = std::net::TcpStream::connect(addr).unwrap();
        sock.write_all(SESSION_MARKER).unwrap();
        dial_encrypted_tx(&mut sock, &genesis, &tip, &tx, false).unwrap();
        assert_eq!(server.join().unwrap(), tx_for_server);
    }

    fn duplex() -> std::io::Result<(std::net::TcpStream, std::net::TcpStream)> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let addr = listener.local_addr()?;
        let client = thread::spawn(move || std::net::TcpStream::connect(addr).unwrap());
        let (server, _) = listener.accept()?;
        Ok((client.join().unwrap(), server))
    }

    #[derive(Clone)]
    struct ArcLog(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);
    impl ArcLog {
        fn new() -> Self {
            Self(std::sync::Arc::new(std::sync::Mutex::new(Vec::new())))
        }
        fn bytes(&self) -> Vec<u8> {
            self.0.lock().unwrap().clone()
        }
    }
    struct Tee<S> {
        inner: S,
        log: ArcLog,
    }
    impl<S: Read> Read for Tee<S> {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            let n = self.inner.read(buf)?;
            self.log.0.lock().unwrap().extend_from_slice(&buf[..n]);
            Ok(n)
        }
    }
    impl<S: Write> Write for Tee<S> {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.log.0.lock().unwrap().extend_from_slice(buf);
            self.inner.write(buf)
        }
        fn flush(&mut self) -> std::io::Result<()> {
            self.inner.flush()
        }
    }
}
