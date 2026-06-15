# Quick Start

## Requirements

- Python 3.10+
- Docker and Docker Compose
- Internet access if using a remote relay
- A running MongoDB instance if not using the bundled Docker setup

## 1. Start the Relay Server

```bash
cd relay_server
docker compose up -d
```

By default, the relay listens on port `5000`.

## 2. Install Client Dependencies

```bash
pip install -r requirements.txt
```

## 3. Run the Desktop Client

```bash
python main.py
```

## 4. Configure the Relay

Open **Settings** and set your relay URL, for example:

```text
https://relay.example.com
```

## 5. Exchange Public Keys

1. Open **My QR** to display your public key.
2. Share the QR code or base64 public key with your contact.
3. Add the contact in the client using their public key.
4. Repeat the process in the other direction.

## 6. Send a Message

Two delivery modes are available:

- **Send via relay** — encrypt and deliver through the configured relay.
- **Send manually** — encrypt and copy ciphertext for delivery through another channel.