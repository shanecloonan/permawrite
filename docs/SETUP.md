# Set up a wallet

One command, from a checkout of this repository:

```bash
bash scripts/setup-wallet.sh
```

The first run builds `mfn-cli` and writes `wallet.json` in the repository root. It then prints the next command.

If something is listening on `127.0.0.1:9050`, that next command includes `--tor`. Otherwise it says Tor is not available and does not pretend the connection is hidden.

The script does not start a node and does not ask the faucet for money. After it finishes, run the printed `wallet ready` command, then `wallet light-scan` against a node you choose.

`bash scripts/setup-wallet.sh --self-test` prints the offline plan and does not build or write a wallet. CI runs that plan.
