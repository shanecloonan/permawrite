//! Friend-to-friend discovery.
//!
//! A signed card lists onion gateways and BitTorrent magnets. A card whose
//! only location is a website can be signed and still be refused: the
//! software has to be reachable after that website is gone.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod card;

pub use card::{sign_card, verify_card, CardError, DiscoveryCard};
