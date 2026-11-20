//! `mfn-release` — create maintainer keys, sign a release, verify a threshold.

use std::env;
use std::fs;
use std::process::ExitCode;

use mfn_release::{
    generate_key, hash_bytes, sign_manifest, verify_manifest, Artifact, Keyring, MaintainerKey,
    ReleaseManifest, Revocation,
};

fn main() -> ExitCode {
    let mut args = env::args().skip(1);
    match args.next().as_deref() {
        Some("keygen") => keygen(args.collect()),
        Some("sign") => sign(args.collect()),
        Some("verify") => verify(args.collect()),
        Some("help") | None => {
            println!("{HELP}");
            ExitCode::SUCCESS
        }
        Some(other) => {
            eprintln!("unknown command {other}\n{HELP}");
            ExitCode::from(2)
        }
    }
}

const HELP: &str = "\
mfn-release keygen --id ID --out FILE
mfn-release sign --key FILE --git HEX --rustc VER --target TRIPLE --threshold N --artifact NAME=PATH --out FILE
mfn-release verify --keyring FILE --manifest FILE [--revoked FILE]
";

fn keygen(args: Vec<String>) -> ExitCode {
    let id = flag(&args, "--id");
    let out = flag(&args, "--out");
    let (Some(id), Some(out)) = (id, out) else {
        eprintln!("keygen needs --id and --out");
        return ExitCode::from(2);
    };
    match generate_key(id) {
        Ok(key) => {
            if let Err(err) = fs::write(out, key.render_secret()) {
                eprintln!("{err}");
                return ExitCode::from(1);
            }
            println!("{}", key.render_public());
            ExitCode::SUCCESS
        }
        Err(err) => {
            eprintln!("{err}");
            ExitCode::from(1)
        }
    }
}

fn sign(args: Vec<String>) -> ExitCode {
    let key_path = flag(&args, "--key");
    let git = flag(&args, "--git");
    let rustc = flag(&args, "--rustc");
    let target = flag(&args, "--target");
    let threshold = flag(&args, "--threshold");
    let out = flag(&args, "--out");
    if key_path.is_none() || git.is_none() || rustc.is_none() || target.is_none() || out.is_none() {
        eprintln!("sign needs --key --git --rustc --target --threshold --artifact --out");
        return ExitCode::from(2);
    }
    let threshold: u32 = match threshold.unwrap_or("0").parse() {
        Ok(v) => v,
        Err(_) => {
            eprintln!("threshold must be a number");
            return ExitCode::from(2);
        }
    };
    let key = match read_key(key_path.unwrap()) {
        Ok(k) => k,
        Err(err) => {
            eprintln!("{err}");
            return ExitCode::from(1);
        }
    };
    let mut artifacts = Vec::new();
    let mut i = 0;
    while i < args.len() {
        if args[i] == "--artifact" {
            let Some(spec) = args.get(i + 1) else {
                eprintln!("--artifact needs NAME=PATH");
                return ExitCode::from(2);
            };
            let Some((name, path)) = spec.split_once('=') else {
                eprintln!("--artifact needs NAME=PATH");
                return ExitCode::from(2);
            };
            let bytes = match fs::read(path) {
                Ok(b) => b,
                Err(err) => {
                    eprintln!("{path}: {err}");
                    return ExitCode::from(1);
                }
            };
            let (sha, size) = hash_bytes(&bytes);
            artifacts.push(Artifact {
                name: name.to_string(),
                sha256_hex: sha,
                size,
            });
            i += 2;
            continue;
        }
        i += 1;
    }
    let mut manifest = match ReleaseManifest::new(
        git.unwrap(),
        rustc.unwrap(),
        target.unwrap(),
        threshold,
        artifacts,
    ) {
        Ok(m) => m,
        Err(err) => {
            eprintln!("{err}");
            return ExitCode::from(1);
        }
    };
    if let Err(err) = sign_manifest(&mut manifest, &key) {
        eprintln!("{err}");
        return ExitCode::from(1);
    }
    if let Err(err) = fs::write(out.unwrap(), manifest.render()) {
        eprintln!("{err}");
        return ExitCode::from(1);
    }
    println!("signed {}", key.id);
    ExitCode::SUCCESS
}

fn verify(args: Vec<String>) -> ExitCode {
    let keyring_path = flag(&args, "--keyring");
    let manifest_path = flag(&args, "--manifest");
    let (Some(keyring_path), Some(manifest_path)) = (keyring_path, manifest_path) else {
        eprintln!("verify needs --keyring and --manifest");
        return ExitCode::from(2);
    };
    let keyring = match fs::read_to_string(keyring_path).and_then(|t| {
        Keyring::parse(&t).map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
    }) {
        Ok(k) => k,
        Err(err) => {
            eprintln!("{err}");
            return ExitCode::from(1);
        }
    };
    let revoked = if let Some(path) = flag(&args, "--revoked") {
        match fs::read_to_string(path).and_then(|t| {
            Revocation::parse(&t)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
        }) {
            Ok(r) => r,
            Err(err) => {
                eprintln!("{err}");
                return ExitCode::from(1);
            }
        }
    } else {
        Revocation::parse("").expect("empty revocation")
    };
    let text = match fs::read_to_string(manifest_path) {
        Ok(t) => t,
        Err(err) => {
            eprintln!("{err}");
            return ExitCode::from(1);
        }
    };
    let manifest = match ReleaseManifest::parse(&text) {
        Ok(m) => m,
        Err(err) => {
            eprintln!("{err}");
            return ExitCode::from(1);
        }
    };
    match verify_manifest(&manifest, &keyring, &revoked) {
        Ok(ok) => {
            println!("ok signers={}", ok.signers.join(","));
            ExitCode::SUCCESS
        }
        Err(err) => {
            eprintln!("{err}");
            ExitCode::from(1)
        }
    }
}

fn read_key(path: &str) -> Result<MaintainerKey, String> {
    let text = fs::read_to_string(path).map_err(|e| e.to_string())?;
    MaintainerKey::parse_secret(&text).map_err(|e| e.to_string())
}

fn flag<'a>(args: &'a [String], name: &str) -> Option<&'a str> {
    args.windows(2)
        .find(|w| w[0] == name)
        .map(|w| w[1].as_str())
}
