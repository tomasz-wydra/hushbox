# hushbox-relay-api

Store-and-forward relay server for end-to-end encrypted Hushbox messages.

The server has **zero knowledge** of message contents — it only sees:
- `pubkey_hash` of sender and recipient (SHA-256 of public key, hex)
- encrypted payload (base64 blob)

Persistence is provided by MongoDB with a TTL index for automatic expiry.

---

## API Endpoints

### `GET /health`

Returns server and MongoDB health status.

**Response `200 OK`:**
```json
{ "status": "ok", "mongo": true, "ts": 1700000000.0 }
```

**Response `503 Service Unavailable`** when MongoDB is unreachable:
```json
{ "status": "degraded", "mongo": false, "ts": 1700000000.0 }
```

---

### `GET /healthz`

Liveness only: answers `200 OK` as long as the process can serve requests. It
does **not** touch MongoDB, which is deliberate — this is the endpoint used by
the container healthcheck, and probing the database from a publicly reachable
path would turn every health probe into a free database round trip.

```json
{ "status": "ok", "ts": 1700000000.0 }
```

Use `/health` (above) for readiness, when you need to know whether MongoDB is
reachable. A green `/healthz` with a degraded `/health` means the process is
alive but cannot store or return messages.

---

### `POST /messages`

Send an encrypted message to a recipient.

**Request body:**
```json
{
  "to":      "<sha256(recipient_pubkey) hex — 64 chars>",
  "from":    "<sha256(sender_pubkey) hex — 64 chars>",
  "payload": "<base64 encrypted blob>"
}
```

- `to` — required; SHA-256 hex of the recipient's public key
- `from` — optional; SHA-256 hex of the sender's public key
- `payload` — required; max 65 536 bytes

**Response `202 Accepted`:**
```json
{ "ok": true, "id": "<uuid>" }
```

**Error responses:**
| Code | Reason |
|------|--------|
| `400` | Missing or invalid `to`/`from` hash, or missing `payload` |
| `413` | Payload exceeds `MAX_PAYLOAD` |
| `429` | Recipient queue is full (`MAX_QUEUE` messages) |

---

### `GET /messages/{recipient_hash}`

Retrieve pending messages for a recipient. Supports long polling.

**Path parameter:** `recipient_hash` — SHA-256 hex of the recipient's public key

**Query parameters:**
| Parameter | Default | Description |
|-----------|---------|-------------|
| `since`   | —       | Return only messages inserted after the message with this ID |
| `timeout` | `0`     | Long-poll timeout in seconds (capped at `LONG_POLL_TIMEOUT`) |
| `limit`   | `50`    | Maximum number of messages to return (max 200) |

**Response `200 OK`:**
```json
{
  "ok": true,
  "messages": [
    {
      "id":      "<uuid>",
      "from":    "<sender_hash or empty string>",
      "payload": "<base64 encrypted blob>",
      "ts":      1700000000.0
    }
  ]
}
```

**Error responses:**
| Code | Reason |
|------|--------|
| `400` | Invalid `recipient_hash`, or a non-numeric / negative query parameter |

---

### `DELETE /messages/{recipient_hash}/{msg_id}`

Acknowledge (delete) a message after successful delivery.

**Path parameters:**
- `recipient_hash` — SHA-256 hex of the recipient's public key
- `msg_id` — message UUID returned by `POST /messages`

**Response `200 OK`:**
```json
{ "ok": true }
```

**Error responses:**
| Code | Reason |
|------|--------|
| `400` | Invalid `recipient_hash`, or a non-numeric / negative query parameter |
| `404` | Message not found or does not belong to this recipient |

---

### `GET /stats`

Returns queue statistics.

**Authentication:** when `STATS_TOKEN` is set, the request must carry a matching
`X-Stats-Token` header (compared in constant time) or it is rejected with `401`.
Leaving the variable unset keeps the endpoint open for backward compatibility,
but traffic metadata is worth protecting — set a token on any public relay.

**Response `200 OK`:**
```json
{
  "recipients_with_messages": 42,
  "total_pending_messages":   157,
  "waiting_inboxes":          3,
  "message_ttl_seconds":      86400
}
```

---

## Running with Docker Compose

```bash
docker compose up -d
```

This starts:
- `hushbox-relay` — the relay API on port `5000`
- `hushbox-mongo` — MongoDB 7 (internal only, not exposed)

The relay waits for MongoDB to pass a health check before starting.

---

## Environment Variables

| Variable            | Default                           | Description |
|---------------------|-----------------------------------|-------------|
| `MONGO_URI`         | `mongodb://mongo:27017/hushbox`   | MongoDB connection URI (must include database name) |
| `MESSAGE_TTL`       | `86400`                           | Message TTL in seconds (MongoDB TTL index) |
| `MAX_QUEUE`         | `500`                             | Maximum pending messages per recipient |
| `LONG_POLL_TIMEOUT` | `30`                              | Maximum long-poll wait in seconds |
| `MAX_PAYLOAD`       | `65536`                           | Maximum payload size in bytes |
| `MAX_BODY_BYTES`    | `MAX_PAYLOAD + 8192`              | Hard request-body limit enforced by Flask *before* the JSON body is parsed into memory |
| `MAX_WAITERS`       | `10000`                           | Maximum number of inboxes waiting in a long poll at once; beyond it long polling degrades to plain polling instead of growing unbounded |
| `STATS_TOKEN`       | *(empty)*                         | When set, `/stats` requires a matching `X-Stats-Token` header |
| `PORT`              | `5000`                            | Port for direct `python -m` runs (not used by gunicorn) |

---

## Running Locally (Development)

```bash
pip install -r requirements.txt
MONGO_URI=mongodb://localhost:27017/hushbox python -m hushbox_relay_api.server
```

Or with gunicorn:

```bash
gunicorn --workers=1 --threads=32 --timeout=60 --bind=0.0.0.0:5000 hushbox_relay_api.server:app
```

> **One worker on purpose.** Long polling is coordinated through in-process
> `threading.Event` objects, which are not shared between worker processes. With
> several workers, a message stored by one worker does not wake a client parked
> in another, so delivery silently falls back to waiting out the full
> `LONG_POLL_TIMEOUT`. Scale with threads (I/O-bound work), or move the wakeup
> signal to a shared channel before scaling out processes.

---

## Running Tests

```bash
pip install flask pymongo mongomock pytest
python -m pytest tests/ -v
```

Tests use `mongomock` — no live MongoDB instance required.

---

## License

MIT — see [LICENSE](LICENSE).
