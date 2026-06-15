# Architecture

Hushbox has two main components:

- a local desktop client,
- an optional relay server.

The desktop client handles key generation, contact management, encryption, decryption, and local message history.

The relay server acts as a store-and-forward transport layer. It accepts encrypted payloads, stores them temporarily, and returns them to recipients on request.

## Data Flow

1. The sender encrypts a message locally using the recipient’s public key.
2. The encrypted payload is either:
   - copied manually and sent through any external transport, or
   - uploaded to the relay server.
3. The recipient retrieves the encrypted payload.
4. The recipient decrypts it locally using their private key.

## Relay Layer

The relay is implemented with Flask and MongoDB.

It is intentionally minimal and does not perform encryption or decryption. Its purpose is temporary persistence and delivery of ciphertext.

By default, stored messages expire after 24 hours.

## Diagram

```text
Alice (Hushbox)                  Relay Server              Bob (Hushbox)
      │                         (Flask + MongoDB)                │
      │  POST /messages                                          │
      │  {to: sha256(bob_pubkey),                                │
      │   payload: <encrypted blob>}                             │
      │ ──────────────────────────────────────────────────────► │
      │                              │  GET /messages/{hash}     │
      │                              │ ◄────────────────────────│
      │                              │  [{payload: <blob>}, ...] │
      │                              │ ────────────────────────► │
      │                              │  decrypt locally          │
```

## Design Notes

- The relay stores ciphertext, not plaintext.
- The client remains responsible for all cryptographic operations.
- Manual transport remains available even when the relay is not used.