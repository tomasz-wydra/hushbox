# Security Policy

Hushbox is end-to-end encryption software, so security reports get priority over any other work. Thank you for taking the time to report responsibly.

## Supported versions

| Component | Supported |
|-----------|-----------|
| `hushbox-core` – latest released minor version | ✅ security fixes |
| `hushbox-core` – older versions | ❌ please upgrade |
| `hushbox-relay-api` – `main` branch | ✅ security fixes |
| `hushbox-web` – `main` branch | ✅ best effort |
| `hushbox-mobile` | not released, design only |

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
- the relay server in `services/hushbox-relay-api`,
- the desktop client in `clients/hushbox-web`.

Out of scope:

- attacks that require full control of the user's unlocked device or operating system,
- denial of service by sending large volumes of traffic to a self-hosted relay,
- social engineering of users or the maintainer,
- vulnerabilities in third-party dependencies without a demonstrated impact on Hushbox (please report those upstream),
- the known limitations listed below.

## Known limitations

These are documented design properties, not vulnerabilities. Reports that only restate them will be closed, but proposals to improve them are very welcome as regular issues.

- **No forward secrecy.** Messages are encrypted with static X25519 keys (NaCl `Box`). If a private key is compromised, previously captured ciphertexts from or to that key can be decrypted.
- **Relay metadata.** The relay sees SHA-256 hashes of the sender's and recipient's public keys, message sizes and timing. It never sees plaintext.
- **No mailbox authentication in the public relay.** In `services/hushbox-relay-api` anyone who knows a recipient's public key hash can fetch that mailbox's ciphertexts and delete them. Content stays confidential, but messages can be read as ciphertext, dropped or delayed. Run the relay only where this is acceptable.
- **No replay protection in the message format.** A ciphertext delivered again (by the relay or through a copy-paste channel) is accepted again by the client.
- **Trust on first use.** A contact's identity is only as strong as the out-of-band fingerprint check. `hushbox-core` tracks a `verified` flag per contact and refuses silent key changes, but it is up to the client to show unverified contacts clearly.
- **Optional key passphrase.** The private key file is protected with Argon2id only if the user sets a passphrase; legacy unencrypted key files are still accepted.
