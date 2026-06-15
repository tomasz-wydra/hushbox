# Hushbox 🔐

> End-to-end encrypted desktop chat using NaCl/Curve25519. No server, no accounts — just keys.

Hushbox is a local desktop application for end-to-end encrypted messaging, built on elliptic curve cryptography (NaCl/libsodium, Curve25519 + XSalsa20-Poly1305). It does not send any data over the network — you exchange encrypted text manually through any channel you already use (SMS, email, Messenger, etc.).

![Python](https://img.shields.io/badge/Python-3.10%2B-blue)
![License](https://img.shields.io/badge/License-MIT-green)
![Tests](https://img.shields.io/badge/Tests-59%20passed-brightgreen)

---

## How it works

1. Each user generates a **key pair** (private + public key) on first launch
2. You exchange **public keys** with your contacts via QR code
3. You type a message → Hushbox encrypts it → **copies ciphertext to clipboard**
4. You paste the ciphertext into any messenger and send it
5. The recipient pastes the ciphertext into Hushbox → it decrypts instantly

No server. No accounts. No metadata. The encrypted blob is meaningless to anyone without the correct private key.

---

## Features

- **Multi-contact sidebar** — open multiple conversations as tabs simultaneously
- **QR code key exchange** — share your public key as a scannable QR
- **Auto-copy to clipboard** — encrypted text is ready to paste after every send
- **Telegram integration** — send & receive encrypted messages directly via your own Telegram bot
- **Persistent chat history** — conversations are saved locally per contact
- **Contact management** — add, rename, delete contacts with their public keys
- **Dark mode UI** built with [CustomTkinter](https://github.com/TomSchimansky/CustomTkinter)

---

## Project structure

```
hushbox/
├── main.py                    # GUI application (CustomTkinter)
├── encryption_manager.py      # Key management & NaCl encryption
├── chat_store.py              # Persistent chat history (JSON)
├── requirements.txt           # Python dependencies
├── my_private_key.bin         # Your private key — DO NOT share or commit!
├── contact_keys.json          # Contacts' public keys (auto-generated)
├── chat_history/              # Per-contact message history (auto-generated)
└── tests/
    ├── test_encryption_manager.py
    └── test_chat_store.py
```

---

## Requirements

- Python 3.10+
- Windows (tested), Linux with X11/Wayland, macOS

```bash
pip install -r requirements.txt
```

Or manually:

```bash
pip install pynacl customtkinter segno Pillow pytest pytest-mock
```

> **WSL users:** tkinter requires a graphical environment. Run the app using native Windows Python instead of WSL.

---

## Running the app

```bash
python main.py
```

---

## Running tests

```bash
pytest tests/ -v
```

39 tests covering encryption roundtrips, contact management, chat history persistence, edge cases (unicode, tampered ciphertext, wrong sender keys).

---

## Usage

### Exchanging keys with a new contact

1. Click **📱 My QR** (top-right) — your public key appears as a QR code and base64 string
2. Ask your contact to share their QR code
3. Copy their public key to clipboard
4. Click **📷 Import QR**, enter a name → contact is added and the chat tab opens

### Sending a message

1. Select a contact from the sidebar
2. Type your message and press **Enter** or click **Send 🔒**
3. The encrypted ciphertext is **automatically copied to clipboard** — paste it into any messenger

### Receiving a message

1. Copy the encrypted ciphertext from your contact
2. In the conversation tab, click **▼ expand** (Receive panel)
3. Paste the ciphertext and click **Decrypt**

### Managing contacts

- Click **⋮** next to any contact to edit, update key, or delete
- Chat history is stored locally in `chat_history/` and survives app restarts

---

## Security notes

| Property | Detail |
|---|---|
| Algorithm | Curve25519 + XSalsa20-Poly1305 (NaCl Box) |
| Key storage | Private key stored locally only in `my_private_key.bin` |
| Nonce | Random per message — no two ciphertexts are linkable |
| Network | Zero — no data ever leaves your machine |
| Authentication | Each message is authenticated (MAC) — tampering is detected |

> **Keep `my_private_key.bin` safe.** If you lose it, you cannot decrypt old messages. If someone obtains it, they can decrypt all your messages.

---

## Telegram integration

Hushbox can send and receive encrypted messages automatically via Telegram — no manual copy-paste needed.
Each user creates their own bot. Telegram sees only the encrypted blob, never the content.

### How it works

```
Alice types message
  ↓ Hushbox encrypts (NaCl/Curve25519)
  ↓ sends ciphertext via Bob's bot → Telegram → Bob's Hushbox
  ↓ Bob's Hushbox polls Bob's bot → decrypts automatically
```

Each person sends through the **recipient's bot** and receives on **their own bot**.
This means both sides get fully automatic delivery.

### What each user needs to prepare

Every user creates one bot and shares two things with each contact:

| What | How to get it |
|---|---|
| **Bot Token** | Message [@BotFather](https://t.me/BotFather), send `/newbot`, copy the token |
| **Chat ID** | Message [@getmyid_bot](https://t.me/getmyid_bot) — it replies instantly with your numeric ID. Alternatives: [@JsonDumpBot](https://t.me/JsonDumpBot) or [@RawDataBot](https://t.me/RawDataBot) |

### Setup in Hushbox (one-time, per contact)

When both Alice and Bob want full two-way Telegram delivery:

**Alice** opens Bob's contact (**⋮ → Edit**) and fills in:
- **Contact's Bot Token** — Bob's bot token (Bob gives this to Alice)
- **Contact's Chat ID** — Bob's Chat ID (Bob checks via @userinfobot)

**Bob** opens Alice's contact (**⋮ → Edit**) and fills in:
- **Contact's Bot Token** — Alice's bot token (Alice gives this to Bob)
- **Contact's Chat ID** — Alice's Chat ID (Alice checks via @userinfobot)

Once saved, the **✈ Telegram** button activates and incoming messages appear automatically.

### What to share with each contact

Send your contact these three things (e.g. over any messenger):

```
My Hushbox public key:  <base64 from 📱 My QR button>
My bot token:           123456789:ABCdef...
My Chat ID:             987654321
```

They enter your token and Chat ID in your contact entry in their Hushbox.
You enter their token and Chat ID in their contact entry in your Hushbox.

### One-way vs two-way

| Setup | Result |
|---|---|
| Only you create a bot | Your contacts can write to you automatically, you send manually (clipboard) |
| Both sides create a bot | Fully automatic in both directions |

### Additional dependency

```bash
pip install python-telegram-bot==20.*
```

---

## License

MIT — see [LICENSE](LICENSE)
