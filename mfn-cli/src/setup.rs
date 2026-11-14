//! First-run setup: make a wallet and say what to do next.
//!
//! This does not start a node, touch a faucet, or restart anything.
//! Tor is only a local port probe.

use std::net::{SocketAddr, TcpStream};
use std::path::Path;
use std::time::Duration;

use crate::wallet_cmd::{wallet_new, WalletCmdError};

/// What setup learned without talking to the network beyond a local Tor port.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SetupReport {
    /// A wallet file was created in this run.
    pub created: bool,
    /// `127.0.0.1:9050` accepted a TCP connection.
    pub tor_socks_open: bool,
    /// The command a person should run next.
    pub next_command: String,
}

/// Words setup prints. `created` is false when the wallet file was already there.
pub fn setup_report(created: bool, tor_socks_open: bool, wallet_path: &str) -> SetupReport {
    let tor_flag = if tor_socks_open { " --tor" } else { "" };
    let next_command = format!("mfn-cli{tor_flag} --wallet {wallet_path} wallet ready");
    SetupReport {
        created,
        tor_socks_open,
        next_command,
    }
}

/// True when something is listening on `addr` within `timeout`.
pub fn tcp_port_open(addr: &str, timeout: Duration) -> bool {
    let Ok(socket) = addr.parse::<SocketAddr>() else {
        return false;
    };
    TcpStream::connect_timeout(&socket, timeout).is_ok()
}

/// Create `path` when it is missing, probe local Tor, and print the next step.
pub fn wallet_setup(path: &Path) -> Result<SetupReport, WalletCmdError> {
    let created = !path.exists();
    if created {
        wallet_new(path, false)?;
    }
    let tor_socks_open = tcp_port_open("127.0.0.1:9050", Duration::from_millis(200));
    let report = setup_report(created, tor_socks_open, &path.display().to_string());
    println!("setup_created={}", report.created);
    println!("tor_socks_open={}", report.tor_socks_open);
    println!("next={}", report.next_command);
    if report.tor_socks_open {
        eprintln!("Tor is listening on 127.0.0.1:9050. The next command uses it.");
    } else {
        eprintln!(
            "Tor is not listening on 127.0.0.1:9050. The next command talks to the node directly. Start Tor if you want the connection hidden."
        );
    }
    eprintln!(
        "Write the wallet file down somewhere private. The seed restores money, not files you upload."
    );
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn report_uses_tor_only_when_the_port_is_open() {
        let plain = setup_report(true, false, "alice.json");
        assert!(plain.next_command.contains("wallet ready"));
        assert!(!plain.next_command.contains("--tor"));
        let hidden = setup_report(false, true, "alice.json");
        assert!(hidden.next_command.contains("--tor"));
        assert!(!hidden.created);
    }

    #[test]
    fn a_closed_port_is_not_tor() {
        assert!(!tcp_port_open("127.0.0.1:1", Duration::from_millis(50)));
        assert!(!tcp_port_open("not-an-address", Duration::from_millis(50)));
    }

    #[test]
    fn setup_creates_a_wallet_file() {
        let path = std::env::temp_dir().join(format!(
            "mfn-setup-{}-{}.json",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));
        let report = wallet_setup(&path).expect("setup");
        assert!(report.created);
        assert!(path.is_file());
        let again = wallet_setup(&path).expect("second");
        assert!(!again.created);
        let _ = std::fs::remove_file(path);
    }
}
