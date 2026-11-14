//! Self-host doctor.
//!
//! Point it at the directory a node setup wrote. It reads the text files
//! and says whether the layout keeps the node on localhost, whether Tor
//! hides addresses in its log, and whether a clearnet URL or a published
//! port slipped in. It does not start a process and it does not open a
//! socket.

use std::fs;
use std::path::Path;

/// One sentence about one file.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Note {
    /// Relative path.
    pub path: String,
    /// True when this file passed.
    pub pass: bool,
    /// Plain language.
    pub sentence: String,
}

/// The whole layout.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Report {
    /// One note per file, plus a summary.
    pub notes: Vec<Note>,
}

impl Report {
    /// True when every note passed.
    pub fn ok(&self) -> bool {
        !self.notes.is_empty() && self.notes.iter().all(|n| n.pass)
    }

    /// Text a person can read.
    pub fn render(&self) -> String {
        let mut out = String::new();
        for note in &self.notes {
            let word = if note.pass { "pass" } else { "fail" };
            out.push_str(word);
            out.push_str(": ");
            out.push_str(&note.path);
            out.push_str(" — ");
            out.push_str(&note.sentence);
            out.push('\n');
        }
        if self.ok() {
            out.push_str("The layout keeps the node off the clearnet.\n");
        } else {
            out.push_str("The layout is not safe to start.\n");
        }
        out
    }
}

/// Why the directory could not be read.
#[derive(Debug, PartialEq, Eq)]
pub enum DoctorError {
    /// No text files, or a path escaped.
    Empty,
    /// Filesystem error.
    Io(String),
}

impl std::fmt::Display for DoctorError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Empty => write!(f, "no layout files to read"),
            Self::Io(msg) => write!(f, "{msg}"),
        }
    }
}

impl std::error::Error for DoctorError {}

/// Read every regular file under `root` (one level) and audit the text.
pub fn audit_dir(root: &Path) -> Result<Report, DoctorError> {
    let entries = fs::read_dir(root).map_err(|e| DoctorError::Io(e.to_string()))?;
    let mut names: Vec<_> = entries
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| DoctorError::Io(e.to_string()))?;
    names.sort_by_key(|e| e.file_name());
    let mut notes = Vec::new();
    for entry in names {
        let path = entry.path();
        let meta = fs::symlink_metadata(&path).map_err(|e| DoctorError::Io(e.to_string()))?;
        if meta.file_type().is_symlink() || !meta.is_file() {
            continue;
        }
        let name = entry.file_name().to_string_lossy().to_string();
        if name.contains("..") || name.contains('/') {
            return Err(DoctorError::Empty);
        }
        let text = fs::read_to_string(&path).map_err(|e| DoctorError::Io(e.to_string()))?;
        notes.push(audit_file(&name, &text));
    }
    if notes.is_empty() {
        return Err(DoctorError::Empty);
    }
    Ok(Report { notes })
}

/// Audit one file's text.
pub fn audit_file(name: &str, text: &str) -> Note {
    if text.contains("0.0.0.0") {
        return fail(name, "It binds the wildcard address 0.0.0.0.");
    }
    if text.contains("5.161.201.73") {
        return fail(name, "It names the public testnet host.");
    }
    if text.contains("https://github.com") || text.contains("http://github.com") {
        return fail(name, "It points at GitHub, which is a clearnet host.");
    }
    if text.contains("EXPOSE") || text.contains("--publish") || text.contains("\n-p ") {
        return fail(name, "It publishes a host port.");
    }
    let is_unit = text.contains("[Service]");
    let is_tor = text.contains("HiddenService") || text.contains("SocksPort");
    if is_unit {
        if !text.contains("IPAddressDeny=any") || !text.contains("IPAddressAllow=localhost") {
            return fail(
                name,
                "The service can open a socket that is not on localhost.",
            );
        }
        if !text.contains("127.0.0.1") {
            return fail(name, "RPC or P2P is not bound to localhost.");
        }
        if !text.contains("MFND_P2P_TRANSPORT=tor") {
            return fail(name, "The node is not set to use Tor.");
        }
        return pass(name, "The node may talk only to localhost, through Tor.");
    }
    if is_tor {
        if !text.contains("SafeLogging 1") {
            return fail(name, "Tor may write client addresses into its log.");
        }
        return pass(
            name,
            "Tor hides addresses in its log and stays on loopback.",
        );
    }
    pass(name, "Nothing in this file opens a clearnet path.")
}

fn pass(path: &str, sentence: &str) -> Note {
    Note {
        path: path.to_string(),
        pass: true,
        sentence: sentence.to_string(),
    }
}

fn fail(path: &str, sentence: &str) -> Note {
    Note {
        path: path.to_string(),
        pass: false,
        sentence: sentence.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_tor_only_unit_passes_and_a_wildcard_fails() {
        let dir = std::env::temp_dir().join(format!(
            "mfn-doctor-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&dir).unwrap();
        fs::write(
            dir.join("permawrite-node.service"),
            "\
[Service]
IPAddressDeny=any
IPAddressAllow=localhost
Environment=MFND_P2P_TRANSPORT=tor
ExecStart=/usr/local/bin/mfnd --rpc-listen 127.0.0.1:18734 --p2p-listen 127.0.0.1:8333 serve
",
        )
        .unwrap();
        fs::write(
            dir.join("permawrite-torrc"),
            "SocksPort 127.0.0.1:9050\nSafeLogging 1\nHiddenServicePort 8333 127.0.0.1:8333\n",
        )
        .unwrap();
        let report = audit_dir(&dir).unwrap();
        assert!(report.ok(), "{}", report.render());
        assert!(
            report.render().contains("keeps the node off the clearnet")
                || report.render().contains("off the clearnet")
        );
        fs::write(
            dir.join("permawrite-node.service"),
            "[Service]\nExecStart=mfnd --rpc-listen 0.0.0.0:18734 serve\n",
        )
        .unwrap();
        let bad = audit_dir(&dir).unwrap();
        assert!(!bad.ok());
        assert!(bad.render().contains("0.0.0.0"));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn github_and_a_published_port_fail_in_plain_language() {
        let gh = audit_file("README", "see https://github.com/shanecloonan/permawrite");
        assert!(!gh.pass);
        assert!(gh.sentence.contains("GitHub"));
        let port = audit_file("run.sh", "podman run --publish 8080:8080 node");
        assert!(!port.pass);
        assert!(port.sentence.contains("port"));
        let seed = audit_file("seeds.txt", "5.161.201.73:19001");
        assert!(!seed.pass);
        let tor = audit_file("torrc", "SocksPort 9050\nHiddenServiceDir /var/lib/tor\n");
        assert!(!tor.pass);
        assert!(tor.sentence.contains("log"));
    }
}
