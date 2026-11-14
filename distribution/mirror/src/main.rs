//! Print a content-addressed mirror for a directory of regular files.

use std::env;
use std::process::ExitCode;

use mfn_mirror::{from_files, read_tree, render};

fn main() -> ExitCode {
    let dir = env::args().nth(1).unwrap_or_else(|| ".".into());
    let files = match read_tree(std::path::Path::new(&dir)) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::from(1);
        }
    };
    let mirror = match from_files("permawrite", &files, &[]) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::from(1);
        }
    };
    print!("{}", render(&mirror));
    eprintln!(
        "upload the bundle named by bundle_sha256; ipfs={} torrent={}",
        mirror.ipfs_cid, mirror.bittorrent_v2
    );
    ExitCode::SUCCESS
}
