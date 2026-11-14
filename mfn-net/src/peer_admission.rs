//! Inbound connection caps against a single host or IPv4 /16 filling every slot.
//!
//! Loopback accepts are not counted. Local meshes keep using `127.0.0.1`.

use std::collections::BTreeMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};

/// Default cap on simultaneous inbound handlers from one remote IP.
pub const DEFAULT_MAX_INBOUND_PER_HOST: usize = 4;
/// Default cap on simultaneous inbound handlers from one IPv4 /16 (or IPv6 /32).
pub const DEFAULT_MAX_INBOUND_PER_PREFIX: usize = 8;

/// Why an inbound socket was refused before the global handler cap.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AdmissionReject {
    /// This IP already holds `cap` handlers.
    Host {
        /// Remote IP.
        host: String,
        /// Configured cap.
        cap: usize,
    },
    /// This prefix already holds `cap` handlers.
    Prefix {
        /// IPv4 /16 or IPv6 /32 label.
        prefix: String,
        /// Configured cap.
        cap: usize,
    },
}

impl std::fmt::Display for AdmissionReject {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Host { host, cap } => write!(f, "host={host} cap={cap}"),
            Self::Prefix { prefix, cap } => write!(f, "prefix={prefix} cap={cap}"),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct AdmissionPermit {
    host: String,
    prefix: String,
}

/// Live counts of inbound handlers by host and prefix.
#[derive(Debug)]
pub struct InboundAdmission {
    max_per_host: usize,
    max_per_prefix: usize,
    per_host: BTreeMap<String, usize>,
    per_prefix: BTreeMap<String, usize>,
}

impl Default for InboundAdmission {
    fn default() -> Self {
        Self::new(DEFAULT_MAX_INBOUND_PER_HOST, DEFAULT_MAX_INBOUND_PER_PREFIX)
    }
}

impl InboundAdmission {
    /// Caps must be at least 1.
    #[must_use]
    pub fn new(max_per_host: usize, max_per_prefix: usize) -> Self {
        Self {
            max_per_host: max_per_host.max(1),
            max_per_prefix: max_per_prefix.max(1),
            per_host: BTreeMap::new(),
            per_prefix: BTreeMap::new(),
        }
    }

    /// Reserve a slot for `peer` (`IP:port` from `accept`).
    ///
    /// `Ok(None)` means the peer is loopback or not a socket address and is not counted.
    pub(crate) fn try_acquire(
        &mut self,
        peer: &str,
    ) -> Result<Option<AdmissionPermit>, AdmissionReject> {
        let Some(ip) = remote_ip(peer) else {
            return Ok(None);
        };
        if ip.is_loopback() {
            return Ok(None);
        }
        let host = ip.to_string();
        let prefix = prefix_key(ip);
        let host_n = self.per_host.get(&host).copied().unwrap_or(0);
        if host_n >= self.max_per_host {
            return Err(AdmissionReject::Host {
                host,
                cap: self.max_per_host,
            });
        }
        let prefix_n = self.per_prefix.get(&prefix).copied().unwrap_or(0);
        if prefix_n >= self.max_per_prefix {
            return Err(AdmissionReject::Prefix {
                prefix,
                cap: self.max_per_prefix,
            });
        }
        *self.per_host.entry(host.clone()).or_default() += 1;
        *self.per_prefix.entry(prefix.clone()).or_default() += 1;
        Ok(Some(AdmissionPermit { host, prefix }))
    }

    fn release(&mut self, permit: &AdmissionPermit) {
        decrement(&mut self.per_host, &permit.host);
        decrement(&mut self.per_prefix, &permit.prefix);
    }
}

/// Releases one inbound reservation when the handler thread ends.
pub(crate) struct InboundAdmissionGuard {
    state: Arc<Mutex<InboundAdmission>>,
    permit: Option<AdmissionPermit>,
}

impl InboundAdmissionGuard {
    /// Wrap a reservation. Dropping the guard releases it.
    #[must_use]
    pub(crate) fn new(
        state: Arc<Mutex<InboundAdmission>>,
        permit: Option<AdmissionPermit>,
    ) -> Self {
        Self { state, permit }
    }
}

impl Drop for InboundAdmissionGuard {
    fn drop(&mut self) {
        let Some(permit) = self.permit.take() else {
            return;
        };
        if let Ok(mut state) = self.state.lock() {
            state.release(&permit);
        }
    }
}

fn remote_ip(peer: &str) -> Option<IpAddr> {
    peer.parse::<SocketAddr>().ok().map(|addr| addr.ip())
}

fn prefix_key(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            format!("{}.{}", o[0], o[1])
        }
        IpAddr::V6(v6) => {
            let s = v6.segments();
            format!("{:x}:{:x}", s[0], s[1])
        }
    }
}

fn decrement(map: &mut BTreeMap<String, usize>, key: &str) {
    let Some(count) = map.get_mut(key) else {
        return;
    };
    *count = count.saturating_sub(1);
    if *count == 0 {
        map.remove(key);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn one_host_cannot_fill_the_table() {
        let mut admission = InboundAdmission::new(1, 8);
        assert!(admission
            .try_acquire("203.0.113.4:40000")
            .unwrap()
            .is_some());
        let err = admission.try_acquire("203.0.113.4:40001").unwrap_err();
        assert!(matches!(err, AdmissionReject::Host { cap: 1, .. }));
    }

    #[test]
    fn release_frees_the_host_slot() {
        let state = Arc::new(Mutex::new(InboundAdmission::new(1, 8)));
        let permit = state.lock().unwrap().try_acquire("203.0.113.4:1").unwrap();
        {
            let _guard = InboundAdmissionGuard::new(Arc::clone(&state), permit);
        }
        assert!(state
            .lock()
            .unwrap()
            .try_acquire("203.0.113.4:2")
            .unwrap()
            .is_some());
    }

    #[test]
    fn one_prefix16_is_capped_across_hosts() {
        let mut admission = InboundAdmission::new(4, 2);
        assert!(admission.try_acquire("198.51.100.1:1").unwrap().is_some());
        assert!(admission.try_acquire("198.51.100.2:1").unwrap().is_some());
        let err = admission.try_acquire("198.51.100.3:1").unwrap_err();
        assert!(matches!(err, AdmissionReject::Prefix { .. }));
        assert!(admission.try_acquire("203.0.113.9:1").unwrap().is_some());
    }

    #[test]
    fn loopback_is_not_counted() {
        let mut admission = InboundAdmission::new(1, 1);
        assert!(admission.try_acquire("127.0.0.1:19001").unwrap().is_none());
        assert!(admission.try_acquire("127.0.0.1:19002").unwrap().is_none());
        assert!(admission.try_acquire("[::1]:19003").unwrap().is_none());
    }
}
