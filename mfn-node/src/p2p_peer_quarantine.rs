//! Peer failure scoring and temporary quarantine (**M2.3.22**).

use std::collections::BTreeMap;
use std::time::{Duration, Instant};

pub(crate) const PEER_FAILURES_BEFORE_QUARANTINE: u32 = 3;
pub(crate) const PEER_QUARANTINE_DURATION: Duration = Duration::from_secs(5 * 60);

pub(crate) fn should_drop_persistent_peer_on_failure(reason: &str) -> bool {
    reason == "genesis_mismatch" || reason.starts_with("genesis_mismatch ")
}

/// Transient local I/O pressure must not accumulate toward peer quarantine (**B-48**).
///
/// Live tip-4031 stalls showed `mfnd_p2p_gossip_abort … os error 11` (EAGAIN) during
/// post-restart bind storms. Counting those as peer failures quarantined the whole
/// committee for [`PEER_QUARANTINE_DURATION`] and blocked proposal vote fan-out.
pub(crate) fn should_ignore_failure_for_quarantine(reason: &str) -> bool {
    let r = reason.to_ascii_lowercase();
    r.contains("resource temporarily unavailable")
        || r.contains("would block")
        || r.contains("wouldblock")
        || r.contains("eagain")
        || reason_mentions_os_error_11(&r)
}

/// True for `os error 11` / `(os error 11)` but not `os error 111` (ECONNREFUSED).
fn reason_mentions_os_error_11(reason_lower: &str) -> bool {
    let needle = "os error 11";
    let mut rest = reason_lower;
    while let Some(idx) = rest.find(needle) {
        let after = &rest[idx + needle.len()..];
        if after
            .chars()
            .next()
            .map(|c| !c.is_ascii_digit())
            .unwrap_or(true)
        {
            return true;
        }
        rest = &rest[idx + needle.len()..];
    }
    false
}

#[derive(Clone, Debug)]
struct PeerPenalty {
    failures: u32,
    quarantined_until: Option<Instant>,
}

#[derive(Debug)]
pub(crate) struct PeerQuarantine {
    failures_before_quarantine: u32,
    quarantine_duration: Duration,
    penalties: BTreeMap<String, PeerPenalty>,
}

impl PeerQuarantine {
    pub(crate) fn new(failures_before_quarantine: u32, quarantine_duration: Duration) -> Self {
        Self {
            failures_before_quarantine: failures_before_quarantine.max(1),
            quarantine_duration,
            penalties: BTreeMap::new(),
        }
    }

    pub(crate) fn note_success(&mut self, peer: &str) {
        self.penalties.remove(peer);
    }

    pub(crate) fn note_failure(&mut self, peer: &str) -> Option<Duration> {
        let now = Instant::now();
        if let Some(remaining) = self.quarantine_remaining_at(peer, now) {
            return Some(remaining);
        }
        let penalty = self
            .penalties
            .entry(peer.to_string())
            .or_insert(PeerPenalty {
                failures: 0,
                quarantined_until: None,
            });
        penalty.failures = penalty.failures.saturating_add(1);
        if penalty.failures >= self.failures_before_quarantine {
            let until = now + self.quarantine_duration;
            penalty.quarantined_until = Some(until);
            return Some(self.quarantine_duration);
        }
        None
    }

    pub(crate) fn is_quarantined(&mut self, peer: &str) -> bool {
        self.quarantine_remaining_at(peer, Instant::now()).is_some()
    }

    fn quarantine_remaining_at(&mut self, peer: &str, now: Instant) -> Option<Duration> {
        let until = self.penalties.get(peer).and_then(|p| p.quarantined_until)?;
        if until > now {
            return Some(until.duration_since(now));
        }
        self.penalties.remove(peer);
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn peer_quarantine_starts_after_threshold() {
        let mut q = PeerQuarantine::new(3, Duration::from_secs(60));
        assert_eq!(q.note_failure("127.0.0.1:9000"), None);
        assert_eq!(q.note_failure("127.0.0.1:9000"), None);

        let remaining = q
            .note_failure("127.0.0.1:9000")
            .expect("third failure quarantines");

        assert!(remaining <= Duration::from_secs(60));
        assert!(q.is_quarantined("127.0.0.1:9000"));
    }

    #[test]
    fn peer_quarantine_success_clears_penalty() {
        let mut q = PeerQuarantine::new(2, Duration::from_secs(60));
        let _ = q.note_failure("127.0.0.1:9000");
        assert!(q.note_failure("127.0.0.1:9000").is_some());
        assert!(q.is_quarantined("127.0.0.1:9000"));

        q.note_success("127.0.0.1:9000");

        assert!(!q.is_quarantined("127.0.0.1:9000"));
        assert_eq!(q.note_failure("127.0.0.1:9000"), None);
    }

    #[test]
    fn peer_quarantine_expiry_prunes_penalty() {
        let peer = "127.0.0.1:9000";
        let mut q = PeerQuarantine::new(2, Duration::from_secs(60));
        assert_eq!(q.note_failure(peer), None);
        assert!(q.note_failure(peer).is_some());
        let until = q
            .penalties
            .get(peer)
            .and_then(|penalty| penalty.quarantined_until)
            .expect("peer is quarantined");

        assert_eq!(
            q.quarantine_remaining_at(peer, until + Duration::from_nanos(1)),
            None
        );
        assert!(!q.penalties.contains_key(peer));
        assert_eq!(q.note_failure(peer), None);
    }

    #[test]
    fn genesis_mismatch_is_durable_peer_drop_reason() {
        assert!(should_drop_persistent_peer_on_failure(
            "genesis_mismatch expected=00 got=11"
        ));
        assert!(should_drop_persistent_peer_on_failure("genesis_mismatch"));
        assert!(!should_drop_persistent_peer_on_failure(
            "connection refused"
        ));
        assert!(!should_drop_persistent_peer_on_failure(
            "decode_error genesis_mismatch"
        ));
    }

    #[test]
    fn transient_eagain_is_ignored_for_quarantine() {
        assert!(should_ignore_failure_for_quarantine(
            "frame: io: Resource temporarily unavailable (os error 11)"
        ));
        assert!(should_ignore_failure_for_quarantine("io: WouldBlock"));
        assert!(should_ignore_failure_for_quarantine("EAGAIN"));
        assert!(!should_ignore_failure_for_quarantine("connection refused"));
        assert!(!should_ignore_failure_for_quarantine(
            "handshake: Connection refused (os error 111)"
        ));
    }
}
