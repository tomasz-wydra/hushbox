# hushbox-core

End-to-end encryption core library for Hushbox — NaCl (libsodium) keypair management,
versioned private key file format, versioned message envelope with replay protection,
versioned QR code payload, contact verification (TOFU) and a relay transport client over HTTP.

Storage of chat history and settings is left to the application. `ChatStore` and `AppSettings`,
which wrote plaintext JSON, were removed in 0.4.0.

## Installation

```bash
pip install -e .
```

## Usage

```python
from hushbox_core import EncryptionManager, RelayTransport

# Generate or load your NaCl keypair
mgr = EncryptionManager(data_dir="/path/to/data")
print(mgr.export_public_key())

# Add a contact and encrypt a message
mgr.add_contact("Alice", alice_public_key_b64)
ciphertext = mgr.encrypt("Alice", "Hello, Alice!")

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

## Message format and replay protection

Every message is a versioned envelope (`hushbox_core.envelope`), format v2 since 0.6.0:

```
base64( "HBM1" | version=2 | Box(nonce || ciphertext) )
Box plaintext: header copy (5 B) | content type (1 B) | message ID (16 random bytes) | timestamp ms (uint64 BE) | UTF-8 body
```

The content type, message ID and timestamp are inside the ciphertext, so the
relay sees none of them. The header is repeated inside the ciphertext because
NaCl `Box` has no associated data; comparing the two copies binds the version
to the authenticated content. The envelope adds 75 bytes (`envelope.OVERHEAD`).

**Breaking changes:** bare `Box` ciphertexts written by 0.4.0 and earlier are
rejected with `InvalidCiphertextFormat`, and v1 envelopes from 0.5.0 with
`UnsupportedMessageFormat`. All parties must upgrade together.

### Content types

| Value | `MessageType` | Meaning |
|---|---|---|
| 1 | `TEXT` | text shown to the user (default) |
| 2 | `FILE_DESCRIPTOR` | message announcing a stored file package (body defined by the application) |
| 3 | `FILE_PACKAGE` | encrypted file package: a stored object, **not** a message |
| 4–127 | – | reserved for future core types (read receipts, group headers, key rotation) |
| 128–255 | – | application-specific, opaque to the core |
| 0 | – | invalid |

An unknown core type raises `UnsupportedMessageType`, so an older client can
ask the user to update instead of showing a control message as text.

```python
mgr.encrypt("Alice", '{"object_ref": "..."}', type=MessageType.FILE_DESCRIPTOR)
msg = mgr.decrypt_message("Alice", ciphertext)   # msg.type tells what it is
mgr.decrypt("Alice", ciphertext)                 # TEXT only, else UnexpectedMessageType

pkg = mgr.encrypt("Alice", package_json, type=MessageType.FILE_PACKAGE)
mgr.open_package("Alice", pkg)                   # any number of times, any age
```

File packages are opened with `open_package()`: authenticity and type are
checked, the replay register and the receive window are not, so a package can
be downloaded again or opened months later. The message path refuses packages
and `open_package()` refuses messages; the content type makes this binding
cryptographic, so a package cannot be replayed as a message or the other way
round.

### Replay protection

`decrypt()` accepts a message once per sender and message ID, and only inside the
receive window: not older than 30 days and not more than 10 minutes in the future
(both configurable). Accepted IDs are kept in `seen_messages.json` next to the key
and pruned once they fall out of the window.

```python
sent = mgr.encrypt_message("Alice", "Hello")      # .ciphertext, .message_id, .timestamp_ms, .type
msg = mgr.decrypt_message("Alice", ciphertext)    # .text, .type, .message_id, .timestamp_ms, .sent_at
mgr.decrypt("Alice", ciphertext)                  # second time: ReplayedMessage
```

Applications with their own database can pass any `ReplayStore` implementation:

```python
mgr = EncryptionManager(data_dir, replay_store=MyDbReplayStore(), max_message_age=7 * 86400)

# check now, record only after the message is stored, so a crash in between
# does not lose it (the relay delivers it again)
msg = mgr.decrypt_message("Alice", ciphertext, record=False)
store_message(msg)
mgr.mark_seen("Alice", msg)
```

Replay protection is local to one device: a second device of the same person
keeps its own register, and wiping the data directory resets it (messages older
than the window are still rejected).

## QR codes

`hushbox_core.qr_payload` defines what a Hushbox QR code contains: compact JSON
with a format version and a content type, so a scanner can tell a contact from a
future invitation or message and refuse what it does not understand.

```python
from hushbox_core import qr_payload

text = qr_payload.contact_payload(mgr.export_public_key(), "https://relay.example.com")
# {"v":1,"type":"contact","public_key":"…","relay_url":"https://relay.example.com"}

card = qr_payload.parse(scanned_text)   # ContactCard(public_key, relay_url)
card.fingerprint                        # still compare out of band before trusting it
```

| Field | Required | Meaning |
|---|---|---|
| `v` | yes | format version, only `1` |
| `type` | yes | `"contact"`; `"invite"` and `"message"` are reserved and rejected for now |
| `public_key` | for `contact` | canonical base64 of the 32-byte public key |
| `relay_url` | no | `http(s)` relay of the contact, without credentials |

Unknown fields are ignored, so optional fields can be added within v1. The
payload is neither encrypted nor signed: a scanned key is as unverified as a
typed one. The pre-0.7.0 payload `{"public_key": …}` is not accepted.

## Errors

All exceptions derive from `HushboxError`:

| Exception | Raised when |
|---|---|
| `PassphraseRequired` | the key file is encrypted but no password was supplied |
| `InvalidPassphrase` | the supplied password does not unseal the key file |
| `UnsupportedKeyFormat` | the key file header is not a format this version understands |
| `KeyConflictError` | a contact already exists with a different public key |
| `FingerprintMismatch` | `verify_contact` received a fingerprint that does not match |
| `InvalidCiphertextFormat` | the ciphertext is not valid base64, has no envelope header (pre-0.5.0 message) or is truncated |
| `UnsupportedMessageFormat` | the envelope uses another format version (newer, or v1 from 0.5.0) |
| `UnsupportedMessageType` | the content type is not defined in this version (subclass of the above) |
| `UnexpectedMessageType` | a known type in the wrong place (package to the message path, non-text to `decrypt()`) |
| `MessageExpired` | the message timestamp is outside the receive window |
| `ReplayedMessage` | the same message (sender + message ID) was already accepted |
| `DecryptionError` | decryption or authentication failed (parent of the seven above) |
| `ReplayStoreError` | the register of received messages cannot be read (corrupted file) |
| `InvalidQrPayload` | scanned text is not a Hushbox QR code, or a field is malformed |
| `UnsupportedQrPayload` | a Hushbox QR code of a newer version or an unsupported type |

`decrypt()` raises `DecryptionError` rather than leaking `nacl.exceptions.CryptoError`,
so callers can distinguish "this payload is not for me / was tampered with" from
a genuine bug. Whitespace inside the ciphertext (line wrapping from email or
chat clients) is tolerated, then base64 is validated strictly.
