# hushbox-web

Desktop GUI client for Hushbox — end-to-end encrypted messaging via a self-hosted relay.

## Requirements

- Python 3.11+
- The `hushbox-core` package (located at `../../packages/hushbox-core`)

## Installation

```bash
pip install -r requirements.txt
```

This installs `customtkinter`, `Pillow`, `segno`, and `hushbox-core` (as an editable local package).

## Running

```bash
python main.py
```

The app opens a dark-mode GUI window. Use **+ Add contact** in the sidebar to add a contact by public key or QR code. Open **⚙ Settings** to configure your relay server URL.

## Relay server

Start your own relay with:

```bash
cd ../../relay_server
docker-compose up -d
```

Then paste the relay URL (e.g. `https://relay.example.com`) into **⚙ Settings**.
