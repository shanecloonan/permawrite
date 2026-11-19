# File vault

The testnet page can seal a file before it is shared.

Pick a file and a passphrase. The page encrypts the bytes with PBKDF2-HMAC-SHA256 and AES-GCM. The content id is the SHA-256 of the ciphertext, not of the original file. That id is what you copy. The sealed copy is stored in this browser under the id. Decrypting asks for the same passphrase and downloads the original bytes. A wrong passphrase does not open the file.

When the page WASM can build a storage preview, the commitment hash and data root of the ciphertext are shown next to the content id. The plaintext is not the thing being committed, and it is not written into storage.

Opening the id on a browser that does not have the sealed copy cannot invent the bytes. The id names the ciphertext. It is not a claim that a storage operator already holds it.
