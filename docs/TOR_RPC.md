# Tor for the wallet

`mfn-cli` checks `127.0.0.1:9050` before it dials a node.

- If that port is open, RPC goes through the SOCKS proxy.
- If it is closed, a normal address is dialed directly and the program says Tor is not in use.
- An `.onion` address is refused unless Tor is in use. `--no-tor` does not override that.
- `--tor` forces the proxy even when the probe is skipped by the caller. `--no-tor` forces a direct dial for a clearnet address.

This does not install Tor. It only uses a Tor daemon the computer is already running.
