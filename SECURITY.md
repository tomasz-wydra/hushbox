# Security Policy

Hushbox is end-to-end encryption software, so security reports get priority over any other work. Thank you for taking the time to report responsibly.

## Supported versions

| Component | Supported |
|-----------|-----------|
| `hushbox-core` – latest released minor version | ✅ security fixes |
| `hushbox-core` – older versions | ❌ please upgrade |
| Code under the `legacy-0.3` tag (demo relay and desktop client) | ❌ unmaintained, do not deploy |

## Reporting a vulnerability

**Do not open a public issue, discussion or pull request for a vulnerability.**

Report it privately through GitHub: open the repository's **Security** tab and choose **Report a vulnerability**. This creates a private advisory visible only to you and the maintainer.

Please include:

- the affected component and version (or commit),
- a description of the issue and its impact,
- steps to reproduce or a proof of concept,
- whether you plan to publish your findings, and when.

Reports in English or Polish are welcome.

## What to expect

| Step | Target time |
|------|-------------|
| Acknowledgement of your report | within 21 days |
| Initial assessment (confirmed / not a vulnerability / need more information) | within 45 days |
| Fix or mitigation for confirmed issues | within 90 days, sooner for critical issues |

We follow coordinated disclosure: please give us the time above before publishing. Once a fix is released, we publish a GitHub security advisory and, if you agree, credit you by name.

Hushbox is maintained by a single person, so these are targets that leave room for travel and holidays, not a contractual SLA. Critical issues are handled as soon as possible.

## Scope

In scope:

- cryptography and key handling in `packages/hushbox-core` (encryption, key file format, fingerprints, contact key changes),
- the relay client and its mailbox authentication (`relay_auth`, specified in `docs/relay-auth.md`), the QR payload format and the Ed25519 signing key and signatures in `packages/hushbox-core`.

Vulnerabilities in NULLGIS itself (desktop application or relay server) can be reported the same way.

Out of scope:

- attacks that require full control of the user's unlocked device or operating system,
- denial of service by sending large volumes of traffic to a self-hosted relay,
- social engineering of users or the maintainer,
- vulnerabilities in third-party dependencies without a demonstrated impact on Hushbox (please report those upstream),
- code under the `legacy-0.3` tag,
- the known limitations listed below.

## Known limitations

These are documented design properties, not vulnerabilities. Reports that only restate them will be closed, but proposals to improve them are very welcome as regular issues.

- **No forward secrecy.** Messages are encrypted with static X25519 keys (NaCl `Box`). If a private key is compromised, previously captured ciphertexts from or to that key can be decrypted.
- **Relay metadata.** The relay sees SHA-256 hashes of the sender's and recipient's public keys, message sizes and timing. It never sees plaintext.
- **Relay sessions are bearer tokens.** Mailbox access uses a short-lived token obtained by challenge-response (`docs/relay-auth.md`). Whoever obtains the token, for example a TLS terminator in front of the relay, can read and delete that mailbox's ciphertexts until the session expires or is revoked. The `from` field of a sent message is not authenticated by the relay.
- **Replay protection is local and time-bounded.** Since 0.5.0 each message carries a random ID and a sender timestamp inside the ciphertext (since 0.6.0 also a content type). A receiver accepts a message once per sender and ID, and only if its timestamp is within the receive window (default: 30 days back, 10 minutes ahead). The register of seen IDs lives on each device: a second device, or a device whose data directory was wiped, can accept a replay of a message that is still inside the window. The timestamp is the sender's clock and is not verified by any third party. File packages (content type `FILE_PACKAGE`) are deliberately exempt: they can be opened any number of times and at any age. The content type keeps them apart from messages, so a package cannot be replayed as a message.
- **No message ordering or loss detection.** The envelope has no sequence number, so a relay can drop or reorder messages without the receiver noticing.
- **Trust on first use.** A contact's identity is only as strong as the out-of-band fingerprint check. `hushbox-core` tracks a `verified` flag per contact and refuses silent key changes, but it is up to the client to show unverified contacts clearly.
- **QR codes are not authenticated.** A Hushbox QR code (`qr_payload`) is plain, unsigned JSON. Anyone who sees it learns the public key and relay address. Anyone who can replace a printed or displayed code can substitute their own key. The fingerprint comparison is what establishes identity.
- **The signing key is derived from the encryption key.** The Ed25519 key is computed from the X25519 private key (one-way, domain-separated BLAKE2b). Whoever obtains the X25519 private key can also sign as that identity; the two keys cannot be rotated or revoked separately. Signing keys of other people are not yet distributed or verified by `hushbox-core`.
- **Optional key passphrase.** The private key file is protected with Argon2id only if the user sets a passphrase; legacy unencrypted key files are still accepted.
