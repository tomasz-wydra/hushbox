# Relay protocol and mailbox authentication (`hushbox-relay-auth-v1`)

This document specifies, from the client's point of view, how a Hushbox client talks to a relay: sending messages, authenticating to its own mailbox, long-polling and acknowledging. It is the contract implemented by `hushbox_core.relay_auth`. Anyone writing another client (mobile, web, a different language) should be able to interoperate with a Hushbox relay using only this document.

Server internals (storage, rate-limit values, deployment, proxies) are out of scope. The reference relay is not part of this repository.

Status: protocol version 1, as implemented in `hushbox-core` 0.8.0 and later. This is a project specification, not an audited standard. All primitives come from libsodium (NaCl).

The key words MUST, MUST NOT, SHOULD and MAY are used as in RFC 2119.

---

## 1. What it protects, and what it does not

**Protected**
- Knowing a mailbox id or a public key is not enough to read or delete that mailbox's messages.
- Only a client that proves possession of the X25519 private key matching the public key gets a session. The relay derives the mailbox id from that key itself.
- A session for mailbox A gives no access to mailbox B (403).

**Not protected (by design)**
- Message *content* is protected by end-to-end encryption (see the message envelope in `hushbox_core.envelope`), not by this protocol. The relay still sees metadata: sender and recipient mailbox ids, sizes and timing. A malicious relay operator can still read, delete or withhold the encrypted blobs.
- The session token is a bearer credential. Whoever obtains it has the mailbox's rights until the session expires or is revoked. TLS terminators in front of the relay see tokens and metadata in clear.
- Challenge-response is not multi-factor authentication. It does not protect against a compromised device.
- The `from` field of `POST /messages` is a sender **claim**, not authenticated by the relay. Receivers authenticate the sender cryptographically when decrypting the envelope: since envelope v3 (`hushbox-core` 0.10.0) the authenticated sender public key inside it must equal the expected contact's key. A `Box` alone does not prove the direction (both parties share one key), so clients MUST check that field; an envelope v2 opened by a 0.9.x client could be the receiver's own message reflected back.

---

## 2. Identifiers

| Item | Definition |
|---|---|
| Public key | X25519 public key, 32 bytes, encoded as RFC 4648 base64 with the standard alphabet and padding: **exactly 44 characters**. |
| Mailbox id (`recipient_hash`, `pubkey_hash`) | `hex(SHA-256(ASCII(<44-character base64 public key>)))`, 64 lowercase hex characters. The **base64 text** is hashed, not the raw 32 bytes. |

Because the mailbox id hashes the text, exactly one encoding of a key is valid. Base64URL, missing padding, whitespace or non-zero trailing bits would address a different mailbox and are rejected by the relay (400).

Clients MUST therefore store and hash only the canonical spelling. A key entered by a user (pasted from e-mail or SMS) SHOULD have whitespace removed and anything else outside the base64 alphabet rejected, and is then re-encoded canonically before it is stored or hashed. Otherwise a stray newline silently sends messages to a mailbox nobody reads. The reference client does this in `hushbox_core.keys` since 0.10.0.

Test vectors:

| Private key | Public key (base64) | Mailbox id |
|---|---|---|
| `01` × 32 | `pOCSkrZRwni5dyxWn1+puxPZBrRqtoyd+dwrRAn4ogk=` | `e03889fae1ca33e7f3762bfc9ea6c89983c912e8ae2ebb43c35a6d8f8fc9edd9` |
| `02` × 32 | `zo060cy2M+x7cMF4FKXHbs0CloUFDTRHRboFhw5YfVk=` | `969648030299168793c6eef319b41d1d2a1676c293a17c08d44f7e25302ce332` |

---

## 3. Relay URL and audience

A client is configured with a relay base URL, either globally or per contact. Every endpoint below is relative to it, for example `https://relay.example.com/messages`.

The **audience** is the canonical form of that URL: `scheme://host[:port][/path]`. Scheme and host are lowercase, the default port (80 for `http`, 443 for `https`) is omitted, and trailing `/` of the path are removed. URLs with credentials, a query or a fragment are invalid.

| Configured URL | Audience |
|---|---|
| `https://Relay.Example.COM/` | `https://relay.example.com` |
| `https://relay.example.com:443` | `https://relay.example.com` |
| `https://relay.example.com:8443/base//` | `https://relay.example.com:8443/base` |
| `http://[::1]:5000` | `http://[::1]:5000` |

The client MUST compute the audience from **its own configuration**, never from anything the relay sends. A challenge carrying a different audience was minted for another relay and MUST be rejected. A relay accepts exactly one audience, so users have to configure exactly the URL that relay was set up with.

---

## 4. Transport security

- The session token MUST only be sent over HTTPS. Plain `http://` is acceptable for loopback hosts (`localhost`, `*.localhost`, `127.0.0.0/8`, `::1`) and otherwise only after an explicit opt-in by the user. Without that, the client sends nothing at all, not even the challenge request.
- Clients MUST NOT follow redirects. A `3xx` answer is an error and is never a reason to resend credentials to another origin.
- TLS certificates MUST be verified normally.
- Clients SHOULD reuse one kept-alive connection for the requests of a session (login, polls, acknowledgements, logout) instead of a new TCP and TLS handshake per request. The reference client does since 0.9.1.
- Tokens MUST be kept in memory only: never written to disk, settings or logs, and never put in a URL or query string.

`POST /messages` carries no credential. The same HTTPS rule SHOULD still apply to it, because the mailbox ids it carries are metadata; the reference client applies it.

---

## 5. Authentication

```text
Client                                           Relay
  │ POST /auth/challenge {public_key}              │
  ├───────────────────────────────────────────────>│ validates the key, derives recipient_hash
  │                                                │ secret = 32 random bytes
  │ 200 {challenge_id, encrypted_challenge,        │ encrypted_challenge = SealedBox(public_key, document)
  │      expires_in}                               │
  │<───────────────────────────────────────────────┤
  │ opens the sealed box with the private key      │
  │ validates every field of the document (5.3)    │
  │ POST /auth/verify {challenge_id, response}     │
  ├───────────────────────────────────────────────>│ single use: the challenge is consumed
  │ 200 {access_token, token_type, expires_in}     │
  │<───────────────────────────────────────────────┤
  │ GET /messages/<recipient_hash>                 │
  │ Authorization: Bearer <access_token>           │
  ├───────────────────────────────────────────────>│ session valid and bound to this mailbox?
```

### 5.1 Formats

| Field | Format |
|---|---|
| `public_key` | the 44-character base64 public key (section 2) |
| `challenge_id`, `access_token` | 32 random bytes, base64URL without padding: exactly 43 characters of `A–Z a–z 0–9 - _` |
| `encrypted_challenge` | standard base64 with padding of a NaCl sealed box (`crypto_box_seal`) to `public_key`. Clients SHOULD refuse more than 4096 characters. |
| `response` | the `secret` from the document, unchanged: standard base64 with padding, 44 characters, 32 bytes |
| `expires_in` (challenge) | integer seconds until the challenge expires (informational) |
| `expires_in` (session) | integer seconds, `0 < expires_in ≤ 86400` |
| `token_type` | the string `"Bearer"` |

### 5.2 Challenge document

The plaintext inside the sealed box is a UTF-8 JSON object:

```json
{
  "protocol": "hushbox-relay-auth-v1",
  "purpose": "mailbox-session",
  "relay_audience": "https://relay.example.com",
  "challenge_id": "<same value as in the HTTP response>",
  "recipient_hash": "<mailbox id derived by the relay>",
  "expires_at": "2026-10-18T12:00:00Z",
  "secret": "<32 bytes, standard base64>"
}
```

`expires_at` is UTC in exactly the form `YYYY-MM-DDTHH:MM:SSZ`.

### 5.3 Client validation

The client sends the secret back **only if all** of the following hold. Otherwise it MUST NOT call `/auth/verify` and MUST NOT reveal anything about the decrypted content:

1. the sealed box opens with the client's own private key and contains a JSON object;
2. `protocol == "hushbox-relay-auth-v1"` and `purpose == "mailbox-session"`;
3. `relay_audience` equals the audience computed from the client's configuration (section 3);
4. `challenge_id` equals the `challenge_id` of the HTTP response that carried this challenge;
5. `recipient_hash` equals the mailbox id of the client's own public key;
6. `expires_at` is not earlier than *now − 300 s* and not later than *now + 900 s*. The 300 s tolerance absorbs clock differences; the challenge is bound to this login attempt by point 4 anyway;
7. `secret` is canonical standard base64 of exactly 32 bytes.

A client MUST NOT offer a general "decrypt any sealed box" operation. The challenge path is the only use of the identity key for sealed boxes, and it only ever releases a secret from a document that passed all checks.

### 5.4 Session use and renewal

- Every authenticated request carries `Authorization: Bearer <access_token>`, at most 128 characters in total.
- Clients SHOULD log in again before a session runs out, early enough that a long poll (section 6.2) never starts on a session that would expire mid-wait. The reference client renews when less than 40 s remain, or less than half of the session lifetime for sessions shorter than 80 s, so that a relay issuing short sessions does not get a new login for every request.
- When an authenticated request returns **401**, the client SHOULD drop the token, log in again and repeat the request **once**. A second 401 is an authentication failure; do not loop.
- **403** means a valid session without rights for the target (for example another mailbox). Renewing will not help: back off for a long time and report it.
- Concurrent requests that need a token SHOULD share a single login in flight instead of each starting one.
- `POST /auth/logout` with the current token revokes the session (204). Clients SHOULD call it when they stop, best effort and with a short deadline.

---

## 6. Messages

### 6.1 Send: `POST /messages` (no authentication)

```json
{"to": "<recipient mailbox id>", "payload": "<encrypted message envelope>", "from": "<sender mailbox id>"}
```

- `to` and `payload` are required. `from` is optional; it lets the receiver find the sender among its contacts before decrypting.
- Success: **202** `{"ok": true, "id": "<relay message id>"}`. Clients MUST treat any other answer, or an answer without `"ok": true`, as not delivered.
- Errors: 400 (malformed body or ids), 413 (payload or body too large for this relay), 429 (rate limit or recipient queue full; honour `Retry-After` when present).

### 6.2 Poll: `GET /messages/<recipient_hash>` (authenticated)

Query parameters:

| Parameter | Meaning |
|---|---|
| `timeout` | seconds the relay may hold the request open waiting for new messages (long poll). The relay caps it at its own maximum and at the remaining session lifetime. The reference client sends 30 and uses a 35 s HTTP deadline. |
| `limit` | maximum number of messages (the reference client sends 50) |
| `since` | relay message id of the last message the client has *durably stored*. Only newer messages are returned. An unknown id, an id from another mailbox, or an id that was already acknowledged is ignored, and the queue is returned from the start. |

Response **200**:

```json
{"ok": true, "messages": [{"id": "...", "from": "<mailbox id or empty>", "payload": "...", "ts": 1760000000.0}]}
```

Messages are ordered oldest first. `ts` is the relay's receive time (informational). Clients SHOULD skip entries that are not objects, have non-string fields or have an empty `id`.

Errors: 401 (missing, invalid, expired or revoked token; also when the session expires during the wait), 403 (the session belongs to another mailbox), 400, 429, 503.

### 6.3 Acknowledge: `DELETE /messages/<recipient_hash>/<id>` (authenticated)

Removes a message from the mailbox. 200 `{"ok": true}`; **404** when it is not in *this* mailbox: either already deleted, or never there. A message in another mailbox looks exactly like a missing one. Other errors as for polling.

### 6.4 Durable before acknowledge

A client MUST acknowledge a message only **after** it has stored it durably, or durably decided to reject it. The recommended loop:

1. poll with `since` = last stored id;
2. for each message in order: store it locally (or record the rejection). On failure, stop the batch **without** acknowledging and retry later; the relay delivers the message again;
3. acknowledge it, then advance the in-memory `since`. If the acknowledgement fails, do **not** advance `since` and stop the batch: `since` returns only newer messages, so moving past an unacknowledged one would leave it in the queue for good.

A failed acknowledgement is not fatal: the message is already stored, and on redelivery it is recognised (by relay id or by the envelope's message id) and acknowledged again. The client backs off as for a network error before polling again. A 404 on the repeated `DELETE` after a token renewal means the first attempt already succeeded.

---

## 7. Errors and retries

| Answer | Client behaviour |
|---|---|
| network error, timeout, 5xx | retry with exponential backoff and jitter (reference: 1 s doubling up to 60 s, "equal jitter") |
| poll answered at once with nothing stored (no messages, or none could be stored yet) | wait at least 1 s before the next poll. A relay answers immediately instead of holding the poll when too many clients wait on one mailbox, so polling again at once would spin. |
| 429 | wait `Retry-After` seconds if present (capped at 3600), but never less than the normal backoff; a value that is not a finite number is ignored |
| 401 on an authenticated request | renew the session once (5.4) |
| 403 | stop retrying quickly; wait long (reference: 300 s) and tell the user |
| 3xx | error; never follow |
| insecure URL (section 4) | send nothing; wait long and tell the user |

Relays send `WWW-Authenticate: Bearer realm="hushbox-relay"` with 401 and `Cache-Control: no-store` on `/auth/*` and `/messages*`.

---

## 8. Versioning

The protocol is identified by the `protocol` field of the challenge document. A future incompatible version will use a new value (for example `hushbox-relay-auth-v2`). Clients MUST reject challenges with a protocol they do not implement.
