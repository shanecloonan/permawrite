//! Persistent peer bans.
//!
//! Repeated protocol failures move a remote IP from a short quarantine to a
//! ban that survives process restart. Inbound sockets from a banned IP are
//! closed before the hello handshake. Loopback is never banned so local
//! meshes keep working.

use std::collections::BTreeMap;
use std::net::{IpAddr, SocketAddr};
use std::path::Path;
use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Failures before a ban.
pub const BAN_AFTER_FAILURES: u32 = 5;
/// How long a ban lasts.
pub const BAN_DURATION: Duration = Duration::from_secs(60 * 60);

#[derive(Clone, Debug, Eq, PartialEq)]
struct BanEntry {
    failures: u32,
    until_unix: u64,
}

/// In-memory ban table.
#[derive(Clone, Debug, Default)]
pub struct BanTable {
    entries: BTreeMap<String, BanEntry>,
}

impl BanTable {
    /// Empty table.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record one protocol failure. Returns true when this call starts a ban.
    pub fn note_failure(&mut self, peer: &str, now: SystemTime) -> bool {
        let Some(host) = host_key(peer) else {
            return false;
        };
        if is_loopback_host(&host) {
            return false;
        }
        let now_unix = unix_secs(now);
        let entry = self.entries.entry(host).or_insert(BanEntry {
            failures: 0,
            until_unix: 0,
        });
        if entry.until_unix > now_unix {
            return false;
        }
        entry.failures = entry.failures.saturating_add(1);
        if entry.failures >= BAN_AFTER_FAILURES {
            entry.until_unix = now_unix.saturating_add(BAN_DURATION.as_secs());
            entry.failures = 0;
            return true;
        }
        false
    }

    /// Whether `peer` is banned at `now`.
    #[must_use]
    pub fn is_banned(&self, peer: &str, now: SystemTime) -> bool {
        let Some(host) = host_key(peer) else {
            return false;
        };
        if is_loopback_host(&host) {
            return false;
        }
        self.entries
            .get(&host)
            .is_some_and(|entry| entry.until_unix > unix_secs(now))
    }

    /// Write `host until_unix` lines.
    pub fn save(&self, path: &Path) -> Result<(), String> {
        let mut body = String::new();
        for (host, entry) in &self.entries {
            if entry.until_unix == 0 {
                continue;
            }
            body.push_str(host);
            body.push(' ');
            body.push_str(&entry.until_unix.to_string());
            body.push('\n');
        }
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        }
        std::fs::write(path, body).map_err(|e| e.to_string())
    }

    /// Load a file written by [`BanTable::save`]. Missing file is an empty table.
    pub fn load(path: &Path) -> Result<Self, String> {
        if !path.exists() {
            return Ok(Self::new());
        }
        let text = std::fs::read_to_string(path).map_err(|e| e.to_string())?;
        let mut table = Self::new();
        for line in text.lines() {
            let mut parts = line.split_whitespace();
            let Some(host) = parts.next() else { continue };
            let Some(until) = parts.next() else { continue };
            let until_unix = until.parse::<u64>().map_err(|e| e.to_string())?;
            table.entries.insert(
                host.to_string(),
                BanEntry {
                    failures: 0,
                    until_unix,
                },
            );
        }
        Ok(table)
    }
}

static GLOBAL: Mutex<BanTable> = Mutex::new(BanTable {
    entries: BTreeMap::new(),
});

/// Replace the process ban table (startup load).
pub fn install(table: BanTable) {
    if let Ok(mut guard) = GLOBAL.lock() {
        *guard = table;
    }
}

/// True when the inbound handshake may proceed.
pub fn inbound_allowed(peer: &str) -> bool {
    let Ok(guard) = GLOBAL.lock() else {
        return false;
    };
    !guard.is_banned(peer, SystemTime::now())
}

/// Count a failure against the process table. Returns true if a ban started.
pub fn record_misbehavior(peer: &str) -> bool {
    let Ok(mut guard) = GLOBAL.lock() else {
        return false;
    };
    guard.note_failure(peer, SystemTime::now())
}

fn host_key(peer: &str) -> Option<String> {
    if let Ok(addr) = peer.parse::<SocketAddr>() {
        return Some(addr.ip().to_string());
    }
    let (host, _) = crate::peer_addr::parse_peer_host_port(peer).ok()?;
    Some(host)
}

fn is_loopback_host(host: &str) -> bool {
    host.parse::<IpAddr>()
        .map(|ip| ip.is_loopback())
        .unwrap_or(false)
}

fn unix_secs(now: SystemTime) -> u64 {
    now.duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::thread;

    #[test]
    fn five_failures_ban_and_survive_reload() {
        let dir = std::env::temp_dir().join(format!("pw-ban-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("bans.txt");
        let mut table = BanTable::new();
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        let peer = "203.0.113.9:8333";
        for _ in 0..4 {
            assert!(!table.note_failure(peer, now));
        }
        assert!(table.note_failure(peer, now));
        assert!(table.is_banned(peer, now + Duration::from_secs(10)));
        table.save(&path).unwrap();
        let loaded = BanTable::load(&path).unwrap();
        assert!(loaded.is_banned(peer, now + Duration::from_secs(10)));
        assert!(!loaded.is_banned(peer, now + BAN_DURATION + Duration::from_secs(5)));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn banned_ip_is_closed_before_any_handshake_bytes() {
        let mut table = BanTable::new();
        let now = SystemTime::now();
        for _ in 0..BAN_AFTER_FAILURES {
            table.note_failure("203.0.113.8:1", now);
        }
        install(table);
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (mut sock, _) = listener.accept().unwrap();
            if !inbound_allowed("203.0.113.8:40000") {
                drop(sock);
                return;
            }
            let _ = sock.write_all(b"HELLO");
        });
        let mut client = std::net::TcpStream::connect(addr).unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let mut buf = [0u8; 5];
        let n = client.read(&mut buf).unwrap_or(0);
        server.join().unwrap();
        assert_eq!(n, 0, "banned peer must not receive handshake bytes");
    }
}
