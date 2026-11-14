//! Short help for the commands a person actually runs.
//!
//! `mfn-cli` with no arguments, and `mfn-cli <command> --help`, print one of
//! these pages. The long option dump stays available for unknown flags.

/// Help page for a command path with help tokens already removed.
pub fn help_for(path: &[&str]) -> String {
    match path {
        [] => root().to_string(),
        ["wallet"] => wallet_index().to_string(),
        ["wallet", "new"] => wallet_new().to_string(),
        ["wallet", "restore"] => wallet_restore().to_string(),
        ["wallet", "address"] => wallet_address().to_string(),
        ["wallet", "send"] => wallet_send().to_string(),
        ["wallet", "upload"] => wallet_upload().to_string(),
        ["wallet", "balance"] | ["wallet", "scan"] => wallet_balance().to_string(),
        ["wallet", "light-scan"] => wallet_light().to_string(),
        ["wallet", "status"] => wallet_status().to_string(),
        ["wallet", "backup-info"] => wallet_backup().to_string(),
        ["wallet", other] => format!("No page for `wallet {other}`.\n\n{}", wallet_index()),
        [other, ..] => format!("No page for `{other}`.\n\n{root}", root = root()),
    }
}

fn root() -> &'static str {
    "\
Permawrite wallet and node client.

Start here:
  mfn-cli wallet new
  mfn-cli --wallet alice.json wallet address
  mfn-cli --wallet alice.json wallet balance
  mfn-cli --wallet alice.json wallet send mfADDRESS 100000000
  mfn-cli --wallet alice.json wallet upload ./notes.txt

100000000 atomic units is 1 MFN. A bare whole number is atomic units.

Privacy stays on. The ring size defaults to 16 and a smaller ring is refused.
Payments cannot carry a public note. Uploaded files are not inside the wallet
seed: keep the upload-artifacts folder as well.

Reach a node over Tor:
  mfn-cli --tor --rpc YOURNODE.onion:18731 wallet balance

More on one command:
  mfn-cli wallet send --help
"
}

fn wallet_index() -> &'static str {
    "\
Wallet commands:
  new           create a wallet file
  restore       rebuild a wallet from its seed
  address       show the address other people pay
  balance       scan the chain and show what you can spend
  light-scan    same balance, checking headers yourself
  send          pay someone privately
  upload        store a file permanently
  status        show the saved balance without downloading blocks
  backup-info   list what you must back up, without printing the seed

  mfn-cli wallet send --help
"
}

fn wallet_new() -> &'static str {
    "\
Create a wallet.

  mfn-cli --wallet alice.json wallet new

This writes alice.json. That file can spend your money. Keep it private.
Back it up somewhere that is not a chat and not a photo roll.
Pass --force only when you mean to replace an existing file.
"
}

fn wallet_restore() -> &'static str {
    "\
Restore a wallet from its 32-byte seed.

  mfn-cli --wallet restored.json wallet restore SEED_HEX

Use this for your own wallet. Operator payout wallets add
--key-derivation payout_stealth_v1 and are not for everyday use.
The seed restores money, not files you uploaded.
"
}

fn wallet_address() -> &'static str {
    "\
Show the address that can receive a payment.

  mfn-cli --wallet alice.json wallet address

Give people the mf... address. The view and spend keys inside it are public
receive keys. They cannot spend.
"
}

fn wallet_send() -> &'static str {
    "\
Send money privately.

  mfn-cli --rpc 127.0.0.1:18731 --wallet alice.json \\
    wallet send mfADDRESS 100000000

100000000 atomic units is 1 MFN. A bare whole number is atomic units.
The wallet needs two coins before it will spend (a faucet sends two).
The ring size defaults to 16. A smaller ring is refused, not quietly used.
Do not add --extra. A note on a payment makes it stand out.

  mfn-cli wallet send --fee 10000 --ring-size 16
"
}

fn wallet_upload() -> &'static str {
    "\
Store a file on the network.

  mfn-cli --rpc 127.0.0.1:18731 --wallet alice.json \\
    wallet upload ./notes.txt

The command prints the fee that pays for storage. If the fee is too small,
nothing is signed. After it succeeds, copy the upload-artifacts folder
next to the wallet. The wallet seed does not contain the file bytes.

  mfn-cli --wallet alice.json uploads retrieve COMMITMENT_HASH ./notes.txt
"
}

fn wallet_balance() -> &'static str {
    "\
See what the wallet can spend.

  mfn-cli --rpc 127.0.0.1:18731 --wallet alice.json wallet balance

balance is atomic units. Scan reads blocks from the node and checks which
outputs open with your keys. Add --json for a support record.
wallet scan is the same scan without focusing on the balance line.
"
}

fn wallet_light() -> &'static str {
    "\
See a balance without trusting the node to describe the chain.

  mfn-cli --rpc 127.0.0.1:18731 --wallet alice.json wallet light-scan

The client checks block headers and validator evolution, then scans
transactions. The node does not get to invent your balance.
Add more nodes with --quorum-rpc HOST:PORT,HOST:PORT when you have them.
"
}

fn wallet_status() -> &'static str {
    "\
Show the last saved balance without downloading blocks.

  mfn-cli --wallet alice.json wallet status

If sync_needed is true, run wallet balance or wallet light-scan.
"
}

fn wallet_backup() -> &'static str {
    "\
List what a backup must include. The seed is not printed.

  mfn-cli --wallet alice.json wallet backup-info

Back up the wallet file (money) and, when the list is not empty, the
upload-artifacts folder (files). Restoring only the seed does not restore
file bytes.
"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn send_help_names_the_privacy_floor_and_an_example() {
        let text = help_for(&["wallet", "send"]);
        assert!(text.contains("mfn-cli"));
        assert!(text.contains("100000000"));
        assert!(text.contains("refused"));
        assert!(text.contains("16"));
    }

    #[test]
    fn upload_help_says_the_seed_is_not_the_file() {
        let text = help_for(&["wallet", "upload"]);
        assert!(text.contains("upload-artifacts"));
        assert!(text.contains("does not contain the file"));
    }

    #[test]
    fn root_help_mentions_tor_and_wallet_new() {
        let text = help_for(&[]);
        assert!(text.contains("wallet new"));
        assert!(text.contains("--tor"));
    }
}
