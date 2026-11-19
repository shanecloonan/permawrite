//! Offline installer.
//!
//! Files land in the destination only after a signature over their hashes
//! verifies. A bad hash or a bad signature leaves the destination as it was.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod install;

pub use install::{install, sign_plan, InstallError, InstallFile, Plan};
