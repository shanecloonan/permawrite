# Self-host doctor

`mfn-doctor` reads the text files in a layout directory and says whether that layout is safe to start. It does not start a node and it does not open a socket.

It fails a file that:

- binds `0.0.0.0`
- names the public testnet host
- points at GitHub
- publishes a host port (`EXPOSE`, `--publish`)
- is a systemd service without `IPAddressDeny=any`, `IPAddressAllow=localhost`, and `MFND_P2P_TRANSPORT=tor`
- is a Tor config without `SafeLogging 1`

```bash
cargo run --manifest-path distribution/doctor/Cargo.toml -- ./node-layout
```

A passing report ends with "The layout keeps the node off the clearnet." A failing report ends with "The layout is not safe to start." and a sentence for each file.

This does not change consensus, Path A, or F-A.
