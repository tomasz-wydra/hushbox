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
