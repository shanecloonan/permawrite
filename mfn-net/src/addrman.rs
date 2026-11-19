//! New/tried address buckets.
//!
//! Learned peers start in `new`. A successful handshake moves that address
//! into `tried`. Bucket choice is a hash of a secret and the IPv4 /16 (or the
//! whole host for overlay names), so one network cannot fill every slot.

use std::collections::BTreeSet;
use std::net::Ipv4Addr;
use std::path::Path;
use std::sync::{Mutex, OnceLock};

use crate::peer_addr::parse_peer_host_port;

const NEW_BUCKETS: usize = 64;
const TRIED_BUCKETS: usize = 32;
const PER_BUCKET: usize = 8;

#[derive(Clone, Debug, Default)]
struct Bucket {
    addrs: Vec<String>,
}

/// Stochastic address table.
#[derive(Clone, Debug)]
pub struct AddrMan {
    key: [u8; 32],
    new_buckets: Vec<Bucket>,
    tried_buckets: Vec<Bucket>,
    known: BTreeSet<String>,
}

impl AddrMan {
    /// Empty tables keyed by `key`.
    #[must_use]
    pub fn new(key: [u8; 32]) -> Self {
        Self {
            key,
            new_buckets: vec![Bucket::default(); NEW_BUCKETS],
            tried_buckets: vec![Bucket::default(); TRIED_BUCKETS],
            known: BTreeSet::new(),
        }
    }

    /// Insert a never-successful address into `new`.
    pub fn add_new(&mut self, addr: &str) -> bool {
        let Ok(addr) = normalize(addr) else {
            return false;
        };
        if self.known.contains(&addr) {
            return false;
        }
        let idx = self.bucket_index(&addr, false);
        let bucket = &mut self.new_buckets[idx];
        if bucket.addrs.len() >= PER_BUCKET {
            let evicted = bucket.addrs.remove(0);
            self.known.remove(&evicted);
        }
        bucket.addrs.push(addr.clone());
        self.known.insert(addr);
        true
    }

    /// Move `addr` into `tried` after a successful session.
    pub fn mark_good(&mut self, addr: &str) {
        let Ok(addr) = normalize(addr) else {
            return;
        };
        self.forget_from_new(&addr);
        let idx = self.bucket_index(&addr, true);
        let bucket = &mut self.tried_buckets[idx];
        if !bucket.addrs.iter().any(|a| a == &addr) {
            if bucket.addrs.len() >= PER_BUCKET {
                let evicted = bucket.addrs.remove(0);
                self.known.remove(&evicted);
            }
            bucket.addrs.push(addr.clone());
        }
        self.known.insert(addr);
    }

    /// One address, preferring `tried`.
    #[must_use]
    pub fn select(&self, n: u64) -> Option<String> {
        let tried = self.tried_count();
        let fresh = self.new_count();
        if tried == 0 && fresh == 0 {
            return None;
        }
        if tried > 0 && (fresh == 0 || n % 2 == 0) {
            return self.pick(&self.tried_buckets, n);
        }
        self.pick(&self.new_buckets, n)
    }

    /// How many distinct IPv4 /16 groups are stored.
    #[must_use]
    pub fn distinct_ipv4_groups(&self) -> usize {
        let mut groups = BTreeSet::new();
        for addr in &self.known {
            if let Some(group) = ipv4_group(addr) {
                groups.insert(group);
            }
        }
        groups.len()
    }

    fn tried_count(&self) -> usize {
        self.tried_buckets.iter().map(|b| b.addrs.len()).sum()
    }

    fn new_count(&self) -> usize {
        self.new_buckets.iter().map(|b| b.addrs.len()).sum()
    }

    fn pick(&self, buckets: &[Bucket], n: u64) -> Option<String> {
        let flat: Vec<&String> = buckets.iter().flat_map(|b| b.addrs.iter()).collect();
        if flat.is_empty() {
            return None;
        }
        Some(flat[(n as usize) % flat.len()].clone())
    }

    fn forget_from_new(&mut self, addr: &str) {
        for bucket in &mut self.new_buckets {
            bucket.addrs.retain(|a| a != addr);
        }
    }

    fn bucket_index(&self, addr: &str, tried: bool) -> usize {
        let group = group_key(addr);
        let mut data = Vec::with_capacity(33 + group.len());
        data.extend_from_slice(&self.key);
        data.push(u8::from(tried));
        data.extend_from_slice(group.as_bytes());
        let hash = simple_hash(&data);
        let n = if tried { TRIED_BUCKETS } else { NEW_BUCKETS };
        (hash as usize) % n
    }

    /// Persist as lines `N addr` or `T addr`.
    pub fn save(&self, path: &Path) -> Result<(), String> {
        let mut body = String::new();
        for bucket in &self.new_buckets {
            for addr in &bucket.addrs {
                body.push_str("N ");
                body.push_str(addr);
                body.push('\n');
            }
        }
        for bucket in &self.tried_buckets {
            for addr in &bucket.addrs {
                body.push_str("T ");
                body.push_str(addr);
                body.push('\n');
            }
        }
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        }
        std::fs::write(path, body).map_err(|e| e.to_string())
    }

    /// Load [`AddrMan::save`] output. Bucket placement is recomputed.
    pub fn load(path: &Path, key: [u8; 32]) -> Result<Self, String> {
        let mut man = Self::new(key);
        if !path.exists() {
            return Ok(man);
        }
        let text = std::fs::read_to_string(path).map_err(|e| e.to_string())?;
        for line in text.lines() {
            let mut parts = line.split_whitespace();
            let Some(kind) = parts.next() else { continue };
            let Some(addr) = parts.next() else { continue };
            if kind == "T" {
                man.add_new(addr);
                man.mark_good(addr);
            } else {
                man.add_new(addr);
            }
        }
        Ok(man)
    }
}

fn normalize(addr: &str) -> Result<String, ()> {
    let (host, port) = parse_peer_host_port(addr).map_err(|_| ())?;
    if host.starts_with('[') {
        Ok(format!("{host}:{port}"))
    } else if host.contains(':') {
        Ok(format!("[{host}]:{port}"))
    } else {
        Ok(format!("{host}:{port}"))
    }
}

fn group_key(addr: &str) -> String {
    ipv4_group(addr).unwrap_or_else(|| {
        addr.rsplit_once(':')
            .map(|(host, _)| host.to_string())
            .unwrap_or_else(|| addr.to_string())
    })
}

fn ipv4_group(addr: &str) -> Option<String> {
    let (host, _) = parse_peer_host_port(addr).ok()?;
    let ip: Ipv4Addr = host.parse().ok()?;
    let o = ip.octets();
    Some(format!("{}.{}", o[0], o[1]))
}

fn simple_hash(data: &[u8]) -> u64 {
    let mut h = 0xcbf29ce484222325u64;
    for b in data {
        h ^= u64::from(*b);
        h = h.wrapping_mul(0x100000001b3);
    }
    h
}

fn with_global(f: impl FnOnce(&mut AddrMan)) {
    static GLOBAL: OnceLock<Mutex<AddrMan>> = OnceLock::new();
    let table = GLOBAL.get_or_init(|| Mutex::new(AddrMan::new([0xA7; 32])));
    if let Ok(mut guard) = table.lock() {
        f(&mut guard);
    }
}

/// Insert `addr` into the process table's new buckets.
pub fn learn_address(addr: &str) {
    with_global(|table| {
        table.add_new(addr);
    });
}

/// Move `addr` into the process table's tried buckets.
pub fn mark_dial_good(addr: &str) {
    with_global(|table| {
        table.mark_good(addr);
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn one_prefix16_cannot_fill_the_table() {
        let mut man = AddrMan::new([7u8; 32]);
        for i in 0..200 {
            let host = format!("10.1.{}.{}:8333", (i / 250) % 256, i % 250 + 1);
            man.add_new(&host);
        }
        for i in 0..200 {
            let host = format!("198.{}.{}.1:8333", i % 40, (i % 200) + 1);
            man.add_new(&host);
        }
        assert!(man.distinct_ipv4_groups() > 4);
        assert!(man.new_count() < 200);
    }

    #[test]
    fn success_moves_to_tried_and_survives_reload() {
        let dir = std::env::temp_dir().join(format!("pw-addrman-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("addrman.txt");
        let mut man = AddrMan::new([9u8; 32]);
        man.add_new("203.0.113.4:8333");
        man.add_new("198.51.100.8:8333");
        man.mark_good("203.0.113.4:8333");
        assert_eq!(man.tried_count(), 1);
        man.save(&path).unwrap();
        let loaded = AddrMan::load(&path, [9u8; 32]).unwrap();
        assert_eq!(loaded.tried_count(), 1);
        let picked = loaded.select(0).unwrap();
        assert!(picked.contains("203.0.113.4") || picked.contains("198.51.100"));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn learned_address_is_visible_to_a_second_table() {
        let mut alice = AddrMan::new([1u8; 32]);
        alice.add_new("203.0.113.50:8333");
        alice.mark_good("203.0.113.50:8333");
        let shared = alice.select(0).unwrap();
        let mut bob = AddrMan::new([2u8; 32]);
        assert!(bob.add_new(&shared));
        assert_eq!(bob.select(1).as_deref(), Some(shared.as_str()));
    }
}
