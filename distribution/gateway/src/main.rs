//! Serve stored files by content id on loopback.
//!
//! The access line is status, byte count, and content id. The client
//! address is dropped as soon as the connection is accepted.

use std::env;
use std::io::{self, Write};
use std::process::ExitCode;

use mfn_gateway::{bind_loopback, serve_one, Store};

fn main() -> ExitCode {
    let mut args = env::args().skip(1);
    let dir = args
        .next()
        .unwrap_or_else(|| "/var/lib/permawrite/gateway".into());
    let port: u16 = args
        .next()
        .unwrap_or_else(|| "8080".into())
        .parse()
        .unwrap_or(8080);
    let store = match Store::production(&dir) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::from(1);
        }
    };
    let listener = match bind_loopback(port) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::from(1);
        }
    };
    eprintln!("gateway listen=127.0.0.1:{port} store={dir}");
    loop {
        match serve_one(&listener, &store) {
            Ok(line) => {
                let _ = writeln!(io::stderr(), "{}", line.render());
            }
            Err(e) => eprintln!("gateway io {e}"),
        }
    }
}
