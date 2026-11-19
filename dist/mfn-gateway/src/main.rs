//! `mfn-gateway` — ingest a file, or serve verified bytes on loopback.

use std::env;
use std::fs;
use std::io::{self, Write};
use std::process::ExitCode;

use mfn_gateway::{bind_loopback, format_access, ingest, onion_snippet, serve_one, Store};

fn main() -> ExitCode {
    let args: Vec<String> = env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("ingest") => ingest_cmd(&args[1..]),
        Some("serve") => serve_cmd(&args[1..]),
        Some("onion") => onion_cmd(&args[1..]),
        _ => {
            println!("{HELP}");
            ExitCode::SUCCESS
        }
    }
}

const HELP: &str = "\
mfn-gateway ingest --store DIR --file PATH
mfn-gateway serve --store DIR [--listen 127.0.0.1:8788]
mfn-gateway onion --listen 127.0.0.1:8788
";

fn ingest_cmd(args: &[String]) -> ExitCode {
    let store = flag(args, "--store");
    let file = flag(args, "--file");
    let (Some(store), Some(file)) = (store, file) else {
        eprintln!("ingest needs --store and --file");
        return ExitCode::from(2);
    };
    let bytes = match fs::read(file) {
        Ok(b) => b,
        Err(err) => {
            eprintln!("{err}");
            return ExitCode::from(1);
        }
    };
    let opened = match Store::open(store) {
        Ok(s) => s,
        Err(err) => {
            eprintln!("{err}");
            return ExitCode::from(1);
        }
    };
    match ingest(&opened, &bytes) {
        Ok(id) => {
            println!("{id}");
            ExitCode::SUCCESS
        }
        Err(err) => {
            eprintln!("{err}");
            ExitCode::from(1)
        }
    }
}

fn serve_cmd(args: &[String]) -> ExitCode {
    let Some(dir) = flag(args, "--store") else {
        eprintln!("serve needs --store");
        return ExitCode::from(2);
    };
    let listen = flag(args, "--listen").unwrap_or("127.0.0.1:8788");
    let Some((host, port)) = listen.rsplit_once(':') else {
        eprintln!("--listen needs host:port");
        return ExitCode::from(2);
    };
    let port: u16 = match port.parse() {
        Ok(p) => p,
        Err(_) => {
            eprintln!("bad port");
            return ExitCode::from(2);
        }
    };
    let listener = match bind_loopback(host, port) {
        Ok(l) => l,
        Err(err) => {
            eprintln!("{err}");
            return ExitCode::from(1);
        }
    };
    let store = match Store::open(dir) {
        Ok(s) => s,
        Err(err) => {
            eprintln!("{err}");
            return ExitCode::from(1);
        }
    };
    let addr = match listener.local_addr() {
        Ok(a) => a,
        Err(err) => {
            eprintln!("{err}");
            return ExitCode::from(1);
        }
    };
    println!("listen={addr}");
    loop {
        match serve_one(&listener, &store) {
            Ok(record) => {
                let _ = writeln!(io::stdout(), "{}", format_access(&record));
            }
            Err(err) => {
                eprintln!("accept: {err}");
            }
        }
    }
}

fn onion_cmd(args: &[String]) -> ExitCode {
    let listen = flag(args, "--listen").unwrap_or("127.0.0.1:8788");
    let Some((host, port)) = listen.rsplit_once(':') else {
        eprintln!("--listen needs host:port");
        return ExitCode::from(2);
    };
    let port: u16 = match port.parse() {
        Ok(p) => p,
        Err(_) => return ExitCode::from(2),
    };
    match onion_snippet(host, port) {
        Ok(text) => {
            print!("{text}");
            ExitCode::SUCCESS
        }
        Err(err) => {
            eprintln!("{err}");
            ExitCode::from(1)
        }
    }
}

fn flag<'a>(args: &'a [String], name: &str) -> Option<&'a str> {
    args.windows(2)
        .find(|w| w[0] == name)
        .map(|w| w[1].as_str())
}
