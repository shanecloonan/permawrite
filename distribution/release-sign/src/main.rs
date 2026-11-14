//! `mfn-release` — generate a maintainer key, sign a release manifest,
//! or refuse the manifest when too few maintainers signed it.

use std::env;
use std::fs;
use std::process::ExitCode;

use mfn_release::{
    from_json, to_json, verify, verify_files, Keyring, MaintainerSecret, ReleaseManifest,
    SignatureSet,
};

fn main() -> ExitCode {
    let mut args = env::args().skip(1);
    let cmd = args.next().unwrap_or_default();
    let result = match cmd.as_str() {
        "keygen" => cmd_keygen(&mut args),
        "sign" => cmd_sign(&mut args),
        "verify" => cmd_verify(&mut args),
        "help" | "-h" | "--help" | "" => {
            eprintln!(
                "usage: mfn-release keygen --name NAME --out FILE\n       mfn-release sign --key FILE --manifest FILE --out FILE\n       mfn-release verify --keyring FILE --manifest FILE --sigs FILE [--dir DIR]"
            );
            Ok(())
        }
        other => Err(mfn_release::ReleaseError::Format(format!(
            "unknown command {other}"
        ))),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("{e}");
            ExitCode::from(1)
        }
    }
}

fn flag(
    args: &mut impl Iterator<Item = String>,
    name: &str,
) -> Result<String, mfn_release::ReleaseError> {
    let got = args
        .next()
        .ok_or_else(|| mfn_release::ReleaseError::Format(format!("missing {name}")))?;
    if got != name {
        return Err(mfn_release::ReleaseError::Format(format!(
            "expected {name}, got {got}"
        )));
    }
    args.next()
        .ok_or_else(|| mfn_release::ReleaseError::Format(format!("missing value for {name}")))
}

fn cmd_keygen(args: &mut impl Iterator<Item = String>) -> Result<(), mfn_release::ReleaseError> {
    let name = flag(args, "--name")?;
    let out = flag(args, "--out")?;
    let secret = MaintainerSecret::generate(&name)?;
    let public = secret.public_key()?;
    fs::write(&out, to_json(&secret)?)
        .map_err(|e| mfn_release::ReleaseError::Format(e.to_string()))?;
    println!("{}", to_json(&public)?);
    Ok(())
}

fn cmd_sign(args: &mut impl Iterator<Item = String>) -> Result<(), mfn_release::ReleaseError> {
    let key = flag(args, "--key")?;
    let manifest_path = flag(args, "--manifest")?;
    let out = flag(args, "--out")?;
    let secret: MaintainerSecret = from_json(
        &fs::read_to_string(&key).map_err(|e| mfn_release::ReleaseError::Format(e.to_string()))?,
    )?;
    let manifest = load_manifest(&manifest_path)?;
    let sig = secret.sign(&manifest)?;
    fs::write(&out, to_json(&sig)?)
        .map_err(|e| mfn_release::ReleaseError::Format(e.to_string()))?;
    Ok(())
}

fn cmd_verify(args: &mut impl Iterator<Item = String>) -> Result<(), mfn_release::ReleaseError> {
    let keyring_path = flag(args, "--keyring")?;
    let manifest_path = flag(args, "--manifest")?;
    let sigs_path = flag(args, "--sigs")?;
    let dir = match args.next() {
        Some(flag) if flag == "--dir" => Some(
            args.next()
                .ok_or_else(|| mfn_release::ReleaseError::Format("missing --dir value".into()))?,
        ),
        Some(other) => {
            return Err(mfn_release::ReleaseError::Format(format!(
                "unexpected {other}"
            )))
        }
        None => None,
    };
    let keyring: Keyring = from_json(
        &fs::read_to_string(&keyring_path)
            .map_err(|e| mfn_release::ReleaseError::Format(e.to_string()))?,
    )?;
    let manifest = load_manifest(&manifest_path)?;
    let sigs: SignatureSet = from_json(
        &fs::read_to_string(&sigs_path)
            .map_err(|e| mfn_release::ReleaseError::Format(e.to_string()))?,
    )?;
    verify(&manifest, &keyring, &sigs)?;
    if let Some(dir) = dir {
        verify_files(std::path::Path::new(&dir), &manifest)?;
    }
    println!(
        "release verify ok version={} target={} files={} threshold={}",
        manifest.version,
        manifest.target,
        manifest.files.len(),
        keyring.threshold
    );
    Ok(())
}

fn load_manifest(path: &str) -> Result<ReleaseManifest, mfn_release::ReleaseError> {
    let text =
        fs::read_to_string(path).map_err(|e| mfn_release::ReleaseError::Format(e.to_string()))?;
    let manifest: ReleaseManifest = from_json(&text)?;
    manifest.normalize()
}
