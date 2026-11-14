# I2P transport

`MFND_P2P_TRANSPORT=i2p` dials `.i2p` and `.b32.i2p` destinations through a local
SOCKS proxy. The default proxy is `127.0.0.1:4447` (`MFND_I2P_SOCKS5`).

Clearnet hosts are refused on this transport, including literal IP addresses.
The SOCKS request uses a domain name, so the process does not resolve the
destination in DNS. A cleartext node also refuses `.i2p` dials.

```bash
export MFND_P2P_TRANSPORT=i2p
export MFND_I2P_SOCKS5=127.0.0.1:4447
mfnd … serve --p2p-dial example.b32.i2p:8333
```

This does not change consensus or the cleartext default. See
[`NETWORK_ANONYMITY.md`](../NETWORK_ANONYMITY.md).
