# hushbox-core

End-to-end encryption core library for Hushbox — NaCl (libsodium) keypair management,
persistent chat history, and relay transport over HTTP.

## Installation

```bash
pip install -e .
```

## Usage

```python
from hushbox_core import EncryptionManager, ChatStore, RelayTransport, AppSettings

# Generate or load your NaCl keypair
mgr = EncryptionManager(data_dir="/path/to/data")
print(mgr.export_public_key())

# Add a contact and encrypt a message
mgr.add_contact("Alice", alice_public_key_b64)
ciphertext = mgr.encrypt("Alice", "Hello, Alice!")

# Persist chat history
store = ChatStore(data_dir="/path/to/data")

# Send via relay
transport = RelayTransport(relay_url="https://relay.example.com", my_pubkey_b64=mgr.export_public_key())
transport.send(alice_public_key_b64, ciphertext)
```

## Protecting the private key at rest

`my_private_key.bin` can be wrapped in a versioned container (`hushbox_core.keyfile`)
that derives a key with Argon2id and seals the private key with a `SecretBox`. A
password is optional: files written by earlier versions (raw 32 bytes) still load
unchanged, so existing installations keep working.

```python
from pathlib import Path
from hushbox_core import EncryptionManager, keyfile

key_path = Path("/path/to/data/my_private_key.bin")

# Ask for a password only when the file actually needs one
if keyfile.path_is_encrypted(key_path):
    mgr = EncryptionManager(data_dir="/path/to/data", passphrase=prompt_user())
else:
    mgr = EncryptionManager(data_dir="/path/to/data")
    mgr.set_passphrase("correct horse battery staple")  # migrates a legacy file
```

A wrong password raises `InvalidPassphrase`; a missing one on an encrypted file
raises `PassphraseRequired`. There is no recovery path — losing the password
means losing the identity stored on that device.

## Verifying a contact's identity (TOFU)

Encryption alone does not tell you *who* you are talking to. Every public key has
a `fingerprint` — SHA-256 over the raw 32 key bytes, rendered as grouped
uppercase hex — meant to be compared with the contact over a separate channel
(call, video, in person).

```python
print(mgr.my_fingerprint())          # read this out to your contact
print(mgr.fingerprint("Alice"))      # what you have stored for them
mgr.verify_contact("Alice", "…")     # raises FingerprintMismatch if it differs
mgr.is_verified("Alice")             # True once confirmed out-of-band
```

Re-adding an existing contact with a **different** public key raises
`KeyConflictError` instead of quietly replacing it — silent replacement was a
man-in-the-middle vector. Pass `allow_key_change=True` only after the user has
knowingly approved the new fingerprint (e.g. the contact reinstalled the app);
any key change resets `verified` to `False`.

> **Two different hashes of a public key — do not mix them up.**
> `pubkey_hash` is SHA-256 over the **base64 string** and identifies the relay
> inbox; it is part of the wire protocol, so every client must hash the base64
> form. `fingerprint` is SHA-256 over the **raw key bytes** and is the value
> shown to humans, stable regardless of base64 variant.

## Errors

All exceptions derive from `HushboxError`:

| Exception | Raised when |
|---|---|
| `PassphraseRequired` | the key file is encrypted but no password was supplied |
| `InvalidPassphrase` | the supplied password does not unseal the key file |
| `UnsupportedKeyFormat` | the key file header is not a format this version understands |
| `KeyConflictError` | a contact already exists with a different public key |
| `FingerprintMismatch` | `verify_contact` received a fingerprint that does not match |
| `InvalidCiphertextFormat` | the ciphertext is not valid base64 |
| `DecryptionError` | decryption or authentication failed (parent of the above) |

`decrypt()` raises `DecryptionError` rather than leaking `nacl.exceptions.CryptoError`,
so callers can distinguish "this payload is not for me / was tampered with" from
a genuine bug. Whitespace inside the ciphertext (line wrapping from email or
chat clients) is tolerated, then base64 is validated strictly.
