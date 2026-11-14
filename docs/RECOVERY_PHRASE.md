# Recovery phrase

A new wallet can be written down as 24 English words (BIP-39). Those words are the seed. Restoring them rebuilds the same view key, spend key, and address.

The browser package exports two functions:

- `phraseFromSeedHex` turns a 64-character seed into the 24 words.
- `seedHexFromPhrase` turns the 24 words back into that seed. A short list, a word that is not in the list, or a bad checksum is an error. Nothing is guessed.

`walletAddressFromSeedHex` then shows the address for that seed. The page does not send the words anywhere. They stay in the browser until the person writes them down.
