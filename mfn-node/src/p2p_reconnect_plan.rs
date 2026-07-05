//! Boot reconnect and committee catch-up dial planning (**M2.3.22**, **M2.3.25**).

use std::net::SocketAddr;

pub(crate) fn is_self_peer_addr(peer_addr: &str, local_p2p_listen: Option<SocketAddr>) -> bool {
    let Some(local) = local_p2p_listen else {
        return false;
    };
    let trimmed = peer_addr.trim();
    if trimmed == local.to_string() {
        return true;
    }
    trimmed
        .parse::<SocketAddr>()
        .map(|peer| peer == local)
        .unwrap_or(false)
}

pub(crate) fn is_boot_dial_peer(peer_addr: &str, boot_dials: &[String]) -> bool {
    boot_dials.iter().any(|addr| addr == peer_addr)
}

pub(crate) fn reconnect_cap_reached(spawned: u32, cap: u32) -> bool {
    spawned >= cap
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CatchUpPeerAction {
    SkipSelf,
    CapReached,
    Dial,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum CatchUpPeerEvent {
    SkipSelf { peer: String },
    CapReached { count: u32, cap: u32 },
    Dial { peer: String },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum ReconnectPeerEvent {
    SkipSelf { peer: String },
    SkipBootDial { peer: String },
    CapReached { count: u32, cap: u32 },
    Dial { peer: String },
}

pub(crate) fn catch_up_peer_action(
    peer_addr: &str,
    local_p2p_listen: Option<SocketAddr>,
    attempted: u32,
    cap: u32,
) -> CatchUpPeerAction {
    if is_self_peer_addr(peer_addr, local_p2p_listen) {
        return CatchUpPeerAction::SkipSelf;
    }
    if reconnect_cap_reached(attempted, cap) {
        return CatchUpPeerAction::CapReached;
    }
    CatchUpPeerAction::Dial
}

pub(crate) fn catch_up_peer_events(
    peers: Vec<String>,
    local_p2p_listen: Option<SocketAddr>,
    cap: u32,
) -> Vec<CatchUpPeerEvent> {
    let mut events = Vec::new();
    let mut attempted = 0u32;
    for addr in peers {
        match catch_up_peer_action(&addr, local_p2p_listen, attempted, cap) {
            CatchUpPeerAction::SkipSelf => {
                events.push(CatchUpPeerEvent::SkipSelf { peer: addr });
            }
            CatchUpPeerAction::CapReached => {
                events.push(CatchUpPeerEvent::CapReached {
                    count: attempted,
                    cap,
                });
                break;
            }
            CatchUpPeerAction::Dial => {
                events.push(CatchUpPeerEvent::Dial { peer: addr });
                attempted = attempted.saturating_add(1);
            }
        }
    }
    events
}

pub(crate) fn reconnect_peer_events(
    peers: Vec<String>,
    local_p2p_listen: Option<SocketAddr>,
    skip_addrs: &[String],
    cap: u32,
) -> Vec<ReconnectPeerEvent> {
    let mut events = Vec::new();
    let mut spawned = 0u32;
    for addr in peers {
        if is_self_peer_addr(&addr, local_p2p_listen) {
            events.push(ReconnectPeerEvent::SkipSelf { peer: addr });
            continue;
        }
        if is_boot_dial_peer(&addr, skip_addrs) {
            events.push(ReconnectPeerEvent::SkipBootDial { peer: addr });
            continue;
        }
        if reconnect_cap_reached(spawned, cap) {
            events.push(ReconnectPeerEvent::CapReached {
                count: spawned,
                cap,
            });
            break;
        }
        events.push(ReconnectPeerEvent::Dial { peer: addr });
        spawned = spawned.saturating_add(1);
    }
    events
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn self_peer_addr_matches_local_socket_addr() {
        let local: SocketAddr = "127.0.0.1:19001".parse().unwrap();
        assert!(is_self_peer_addr("127.0.0.1:19001", Some(local)));
        assert!(is_self_peer_addr(" 127.0.0.1:19001 ", Some(local)));
        assert!(!is_self_peer_addr("127.0.0.1:19002", Some(local)));
        assert!(!is_self_peer_addr("seed.example.org:19001", Some(local)));
        assert!(!is_self_peer_addr("127.0.0.1:19001", None));
    }

    #[test]
    fn self_peer_addr_matches_bracketed_ipv6() {
        let local: SocketAddr = "[::1]:19001".parse().unwrap();
        assert!(is_self_peer_addr("[::1]:19001", Some(local)));
        assert!(!is_self_peer_addr("[::1]:19002", Some(local)));
    }

    #[test]
    fn boot_dial_peer_matches_saved_addr_exactly() {
        let boot_dials = vec!["127.0.0.1:19001".to_string(), "127.0.0.1:19002".to_string()];
        assert!(is_boot_dial_peer("127.0.0.1:19001", &boot_dials));
        assert!(!is_boot_dial_peer("127.0.0.1:19003", &boot_dials));
        assert!(!is_boot_dial_peer(" 127.0.0.1:19001 ", &boot_dials));
    }

    #[test]
    fn reconnect_cap_reached_at_or_above_cap() {
        assert!(!reconnect_cap_reached(0, 1));
        assert!(!reconnect_cap_reached(7, 8));
        assert!(reconnect_cap_reached(8, 8));
        assert!(reconnect_cap_reached(9, 8));
    }

    #[test]
    fn reconnect_peer_events_preserve_skip_and_cap_order() {
        let local: SocketAddr = "127.0.0.1:19001".parse().unwrap();
        let peers = vec![
            "127.0.0.1:19001".to_string(),
            "127.0.0.1:19002".to_string(),
            "127.0.0.1:19003".to_string(),
            "127.0.0.1:19004".to_string(),
        ];
        let skip_addrs = vec!["127.0.0.1:19002".to_string()];

        assert_eq!(
            reconnect_peer_events(peers, Some(local), &skip_addrs, 1),
            vec![
                ReconnectPeerEvent::SkipSelf {
                    peer: "127.0.0.1:19001".to_string(),
                },
                ReconnectPeerEvent::SkipBootDial {
                    peer: "127.0.0.1:19002".to_string(),
                },
                ReconnectPeerEvent::Dial {
                    peer: "127.0.0.1:19003".to_string(),
                },
                ReconnectPeerEvent::CapReached { count: 1, cap: 1 },
            ]
        );
    }

    #[test]
    fn catch_up_peer_action_skips_self_before_cap() {
        let local: SocketAddr = "127.0.0.1:19001".parse().unwrap();

        assert_eq!(
            catch_up_peer_action("127.0.0.1:19001", Some(local), 8, 8),
            CatchUpPeerAction::SkipSelf
        );
    }

    #[test]
    fn catch_up_peer_action_respects_cap_for_non_self_peers() {
        let local: SocketAddr = "127.0.0.1:19001".parse().unwrap();

        assert_eq!(
            catch_up_peer_action("127.0.0.1:19002", Some(local), 7, 8),
            CatchUpPeerAction::Dial
        );
        assert_eq!(
            catch_up_peer_action("127.0.0.1:19002", Some(local), 8, 8),
            CatchUpPeerAction::CapReached
        );
    }

    #[test]
    fn catch_up_peer_events_preserve_self_skip_and_cap_order() {
        let local: SocketAddr = "127.0.0.1:19001".parse().unwrap();
        let peers = vec![
            "127.0.0.1:19001".to_string(),
            "127.0.0.1:19002".to_string(),
            "127.0.0.1:19003".to_string(),
        ];

        assert_eq!(
            catch_up_peer_events(peers, Some(local), 1),
            vec![
                CatchUpPeerEvent::SkipSelf {
                    peer: "127.0.0.1:19001".to_string(),
                },
                CatchUpPeerEvent::Dial {
                    peer: "127.0.0.1:19002".to_string(),
                },
                CatchUpPeerEvent::CapReached { count: 1, cap: 1 },
            ]
        );
    }
}
