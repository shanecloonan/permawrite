//! Per-remote-IP cap on in-flight JSON-RPC connections.
//!
//! The global in-flight cap can be filled by one address. Loopback is not
//! counted so local wallets and tests keep their existing concurrency.

use std::collections::BTreeMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};

/// Simultaneous RPC handlers one non-loopback IP may hold.
pub const DEFAULT_RPC_PER_HOST: usize = 8;

/// Counts in-flight RPC connections by remote IP.
#[derive(Debug)]
pub struct RpcSourceCap {
    max_per_host: usize,
    per_host: BTreeMap<String, usize>,
}

impl RpcSourceCap {
    /// `max_per_host` is raised to at least 1.
    #[must_use]
    pub fn new(max_per_host: usize) -> Self {
        Self {
            max_per_host: max_per_host.max(1),
            per_host: BTreeMap::new(),
        }
    }

    /// Host key when `peer` should be counted. Loopback returns `None`.
    #[must_use]
    pub fn counted_host(peer: SocketAddr) -> Option<String> {
        if peer.ip().is_loopback() {
            return None;
        }
        if matches!(peer.ip(), IpAddr::V4(v4) if v4.is_unspecified()) {
            return None;
        }
        Some(peer.ip().to_string())
    }

    /// Reserve one handler for `host`. False when that host is already at the cap.
    pub fn try_acquire(&mut self, host: &str) -> bool {
        let count = self.per_host.get(host).copied().unwrap_or(0);
        if count >= self.max_per_host {
            return false;
        }
        *self.per_host.entry(host.to_string()).or_default() += 1;
        true
    }

    fn release(&mut self, host: &str) {
        let Some(count) = self.per_host.get_mut(host) else {
            return;
        };
        *count = count.saturating_sub(1);
        if *count == 0 {
            self.per_host.remove(host);
        }
    }
}

impl Default for RpcSourceCap {
    fn default() -> Self {
        Self::new(DEFAULT_RPC_PER_HOST)
    }
}

/// Releases a [`RpcSourceCap`] reservation when the RPC worker ends.
pub struct RpcSourceGuard {
    state: Arc<Mutex<RpcSourceCap>>,
    host: Option<String>,
}

impl RpcSourceGuard {
    /// `host` is `None` for loopback and other uncounted peers.
    #[must_use]
    pub fn new(state: Arc<Mutex<RpcSourceCap>>, host: Option<String>) -> Self {
        Self { state, host }
    }
}

impl Drop for RpcSourceGuard {
    fn drop(&mut self) {
        let Some(host) = self.host.take() else {
            return;
        };
        if let Ok(mut state) = self.state.lock() {
            state.release(&host);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn one_remote_ip_cannot_take_every_slot() {
        let mut cap = RpcSourceCap::new(1);
        assert!(cap.try_acquire("203.0.113.4"));
        assert!(!cap.try_acquire("203.0.113.4"));
        assert!(cap.try_acquire("203.0.113.5"));
    }

    #[test]
    fn drop_releases_the_host() {
        let state = Arc::new(Mutex::new(RpcSourceCap::new(1)));
        assert!(state.lock().unwrap().try_acquire("198.51.100.1"));
        {
            let _guard = RpcSourceGuard::new(Arc::clone(&state), Some("198.51.100.1".into()));
        }
        assert!(state.lock().unwrap().try_acquire("198.51.100.1"));
    }

    #[test]
    fn loopback_is_not_counted() {
        let peer: SocketAddr = "127.0.0.1:9".parse().unwrap();
        assert!(RpcSourceCap::counted_host(peer).is_none());
        let v6: SocketAddr = "[::1]:9".parse().unwrap();
        assert!(RpcSourceCap::counted_host(v6).is_none());
        let public: SocketAddr = "203.0.113.9:9".parse().unwrap();
        assert_eq!(
            RpcSourceCap::counted_host(public).as_deref(),
            Some("203.0.113.9")
        );
    }
}
