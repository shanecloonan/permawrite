//! Air-gapped signing for a Permawrite wallet.
//!
//! The online machine writes a payment request. The offline machine, which
//! holds the wallet seed, signs that request with the spend key. The online
//! machine checks the signature against the spend key it was shown once,
//! in person. The signed file does not contain the seed.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod ceremony;

pub use ceremony::{
    load_seed_file, sign_request, verify_signed, watch_only, AirgapError, PaymentRequest,
    SignedRequest,
};
