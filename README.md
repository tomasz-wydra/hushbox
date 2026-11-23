# Hushbox 🔐

Open-source end-to-end encryption core used by [NULLGIS](https://nullgis.com). NaCl/Curve25519 keys, no accounts. The relay that carries messages is blind to their content.

This repository contains **`hushbox-core`**, the public, auditable part of the system: key management, the private key file format, contact verification and the relay transport client. Applications, the relay server and storage of chat history are not part of this repository.

## Structure

```
hushbox/
└── packages/
    └── hushbox-core/                   # E2E crypto core — Apache-2.0
        ├── hushbox_core/
        │   ├── encryption_manager.py   # NaCl keypairs, contacts, encrypt/decrypt, TOFU
        │   ├── keyfile.py              # Versioned private key file (Argon2id + SecretBox)
        │   ├── relay_transport.py      # HTTP relay client (long polling)
        │   └── errors.py               # Domain exceptions
        └── tests/
```

## Security Model

- **NaCl Box** (X25519 + XSalsa20-Poly1305) — authenticated E2E encryption
- Private key never leaves the device; optional Argon2id passphrase protection at rest
- Relay server sees only: SHA-256 key hashes + encrypted blobs
- No accounts, no phone numbers, no telemetry

Known limitations and how to report a vulnerability: see [SECURITY.md](SECURITY.md).

## Development

```bash
pip install -e "packages/hushbox-core[dev]"
pytest packages/hushbox-core/tests/ -v
```

Usage examples are in [packages/hushbox-core/README.md](packages/hushbox-core/README.md).

## Historical demo

Earlier versions of this repository also shipped a demo relay server (`hushbox-relay-api`) and a demo desktop client (`hushbox-web`). They are preserved under the tag [`legacy-0.3`](https://github.com/tomasz-wydra/hushbox/tree/legacy-0.3) for reference only. They are **unmaintained, not covered by the security policy and must not be deployed**; the legacy relay has no mailbox authentication.

## Contributing

Contributions are welcome. Every commit must be signed off under the Developer Certificate of Origin (`git commit -s`). See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

`hushbox-core` is licensed under the **Apache License 2.0** (releases up to and including 0.3.0 were MIT). See [packages/hushbox-core/LICENSE](packages/hushbox-core/LICENSE).
