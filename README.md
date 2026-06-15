# Hushbox 🔐

Hushbox is a desktop app for end-to-end encrypted messaging built with NaCl/libsodium public-key cryptography.

Messages are encrypted locally on the sender’s device and can only be decrypted by the intended recipient. Hushbox supports both manual ciphertext exchange and an optional relay layer based on Flask and MongoDB for temporary encrypted message delivery.

![Python](https://img.shields.io/badge/Python-3.10%2B-blue)
![License](https://img.shields.io/badge/License-MIT-green)
![Tests](https://img.shields.io/badge/Tests-55%20passed-brightgreen)

## Features

- End-to-end encrypted messaging using NaCl/libsodium.
- Local key generation and local decryption.
- Manual/offline ciphertext exchange through any transport channel.
- Optional relay server for temporary encrypted message delivery.
- No accounts, phone numbers, or password-based onboarding.
- Configurable message retention, with 24 hours by default.

## Quick Start

```bash
git clone <your-repo-url>
pip install -r requirements.txt
cd relay_server
docker compose up -d
cd ..
python main.py
```

For a full setup guide, see [docs/quickstart.md](./docs/quickstart.md).

## Documentation

- [Docs index](./docs/README.md)
- [Architecture](./docs/architecture.md)
- [Quick start](./docs/quickstart.md)
- [Relay API](./docs/relay-api.md)
- [Relay deployment](./docs/relay-deployment.md)
- [Configuration](./docs/configuration.md)
- [Security model](./docs/security-model.md)
- [Migration from Telegram](./docs/migration-from-telegram.md)

## Project Structure

```text
hushbox/
├── /         # Desktop client
├── relay_server/    # Flask-based relay layer
└── docs/            # Project documentation
```

## Security

Hushbox protects message content with end-to-end encryption, but secure deployment still depends on your relay setup, TLS configuration, key verification process, and endpoint security.

See [SECURITY.md](./SECURITY.md) and [docs/security-model.md](./docs/security-model.md).

## Contributing

Contributions, bug reports, and documentation improvements are welcome.

See [CONTRIBUTING.md](./CONTRIBUTING.md).

## License

This project is licensed under the MIT License. See [LICENSE](./LICENSE).