"""
Hushbox Relay Server — store-and-forward dla zaszyfrowanych wiadomości E2E.

Serwer NIE zna treści wiadomości — widzi tylko:
  - pubkey_hash nadawcy i odbiorcy (SHA-256 klucza publicznego)
  - zaszyfrowany blob (base64)

Persistence: MongoDB (pymongo)
  - kolekcja: messages
  - TTL index na polu ts (MESSAGE_TTL sekund)
  - indeks na polu recipient_hash

API:
  POST   /messages                        — wyślij wiadomość
  GET    /messages/{hash}                 — pobierz wiadomości (long polling)
  DELETE /messages/{hash}/{msg_id}        — potwierdź odbiór
  GET    /health                          — health check
  GET    /stats                           — statystyki kolejki
"""

import os
import time
import uuid
import logging
from threading import Event
from collections import defaultdict
from datetime import datetime, timezone

from flask import Flask, request, jsonify, abort
from pymongo import MongoClient, ASCENDING
from pymongo.collection import Collection

# ─────────────────────────────────────────────────────────────────
# Konfiguracja
# ─────────────────────────────────────────────────────────────────
MONGO_URI         = os.getenv("MONGO_URI", "mongodb://mongo:27017/hushbox")
MESSAGE_TTL       = int(os.getenv("MESSAGE_TTL",        str(24 * 3600)))
MAX_QUEUE         = int(os.getenv("MAX_QUEUE",          "500"))
LONG_POLL_TIMEOUT = int(os.getenv("LONG_POLL_TIMEOUT",  "30"))
MAX_PAYLOAD       = int(os.getenv("MAX_PAYLOAD",        str(64 * 1024)))

logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

app = Flask(__name__)

# ─────────────────────────────────────────────────────────────────
# MongoDB
# ─────────────────────────────────────────────────────────────────
_client: MongoClient | None = None
_col:    Collection  | None = None


def get_collection() -> Collection:
    """Lazy-init kolekcji MongoDB (singleton per process)."""
    global _client, _col
    if _col is None:
        _client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=5000)
        db   = _client.get_default_database()
        _col = db["messages"]

        # indeks TTL — MongoDB automatycznie usuwa dokumenty po MESSAGE_TTL sekundach
        _col.create_index(
            [("created_at", ASCENDING)],
            expireAfterSeconds=MESSAGE_TTL,
            name="ttl_idx",
            background=True,
        )
        # indeks na recipient_hash — szybkie wyszukiwanie wiadomości dla odbiorcy
        _col.create_index(
            [("recipient_hash", ASCENDING), ("created_at", ASCENDING)],
            name="recipient_idx",
            background=True,
        )
        # indeks na msg_id — szybkie ACK (DELETE)
        _col.create_index(
            [("msg_id", ASCENDING)],
            unique=True,
            name="msg_id_idx",
            background=True,
        )
        logger.info(f"MongoDB connected: {MONGO_URI}")
    return _col


def _serialize(doc: dict) -> dict:
    """Konwertuj dokument Mongo do JSON-friendly dict."""
    return {
        "id":      doc["msg_id"],
        "from":    doc.get("sender_hash", ""),
        "payload": doc["payload"],
        "ts":      doc["created_at"].timestamp(),
    }


# ─────────────────────────────────────────────────────────────────
# Long-poll events (in-memory, per process — wystarczy dla 1 instancji)
# ─────────────────────────────────────────────────────────────────
_new_msg_events: dict[str, Event] = defaultdict(Event)


def _validate_hash(h: str) -> bool:
    if len(h) != 64:
        return False
    try:
        int(h, 16)
        return True
    except ValueError:
        return False


# ─────────────────────────────────────────────────────────────────
# Endpoints
# ─────────────────────────────────────────────────────────────────

@app.route("/health", methods=["GET"])
def health():
    try:
        col = get_collection()
        col.database.client.admin.command("ping")
        mongo_ok = True
    except Exception as e:
        logger.warning(f"MongoDB health check failed: {e}")
        mongo_ok = False
    return jsonify({
        "status":    "ok" if mongo_ok else "degraded",
        "mongo":     mongo_ok,
        "ts":        time.time(),
    }), 200 if mongo_ok else 503


@app.route("/messages", methods=["POST"])
def send_message():
    """
    Wyślij zaszyfrowaną wiadomość.

    Body JSON:
      {
        "to":      "<sha256(recipient_pubkey) hex>",
        "from":    "<sha256(sender_pubkey) hex>",   // opcjonalne
        "payload": "<base64 encrypted blob>"
      }
    """
    data = request.get_json(silent=True) or {}

    to_hash   = data.get("to",      "").strip().lower()
    from_hash = data.get("from",    "").strip().lower()
    payload   = data.get("payload", "").strip()

    if not to_hash or not _validate_hash(to_hash):
        abort(400, "Invalid 'to' — expected SHA-256 hex")
    if not payload:
        abort(400, "Missing 'payload'")
    if len(payload) > MAX_PAYLOAD:
        abort(413, f"Payload too large (max {MAX_PAYLOAD} bytes)")
    if from_hash and not _validate_hash(from_hash):
        abort(400, "Invalid 'from' — expected SHA-256 hex")

    col = get_collection()

    # odrzuć jeśli kolejka przekracza MAX_QUEUE
    count = col.count_documents({"recipient_hash": to_hash})
    if count >= MAX_QUEUE:
        abort(429, f"Recipient queue full (max {MAX_QUEUE})")

    msg_id = str(uuid.uuid4())
    doc = {
        "msg_id":        msg_id,
        "recipient_hash": to_hash,
        "sender_hash":   from_hash,
        "payload":       payload,
        "created_at":    datetime.now(timezone.utc),
    }
    col.insert_one(doc)

    # sygnalizuj oczekującym long-poll
    _new_msg_events[to_hash].set()
    _new_msg_events[to_hash].clear()

    logger.info(f"MSG -> {to_hash[:8]}... id={msg_id[:8]}")
    return jsonify({"ok": True, "id": msg_id}), 202


@app.route("/messages/<recipient_hash>", methods=["GET"])
def get_messages(recipient_hash: str):
    """
    Pobierz wiadomości dla odbiorcy (long polling).

    Query params:
      since=<msg_id>  — zwróć wiadomości dodane PO wiadomości z tym ID
      timeout=<s>     — long polling (max LONG_POLL_TIMEOUT)
      limit=<n>       — max liczba wiadomości (domyślnie 50)
    """
    recipient_hash = recipient_hash.strip().lower()
    if not _validate_hash(recipient_hash):
        abort(400, "Invalid recipient hash")

    since   = request.args.get("since", "")
    timeout = min(int(request.args.get("timeout", 0)), LONG_POLL_TIMEOUT)
    limit   = min(int(request.args.get("limit",  50)), 200)

    col = get_collection()

    def _fetch():
        query: dict = {"recipient_hash": recipient_hash}

        if since:
            # Używamy _id jako naturalnego kursora — ObjectId jest monotonicznie
            # rosnący, więc $gt na _id daje poprawną kolejność nawet gdy
            # created_at ma tę samą rozdzielczość (np. w testach).
            anchor = col.find_one({"msg_id": since}, {"_id": 1})
            if anchor:
                query["_id"] = {"$gt": anchor["_id"]}

        docs = list(
            col.find(query, {"_id": 0})
               .sort("created_at", ASCENDING)
               .limit(limit)
        )
        return [_serialize(d) for d in docs]

    msgs = _fetch()

    if not msgs and timeout > 0:
        _new_msg_events[recipient_hash].wait(timeout=timeout)
        msgs = _fetch()

    return jsonify({"ok": True, "messages": msgs})


@app.route("/messages/<recipient_hash>/<msg_id>", methods=["DELETE"])
def ack_message(recipient_hash: str, msg_id: str):
    """Usuń wiadomość po potwierdzeniu odbioru."""
    recipient_hash = recipient_hash.strip().lower()
    if not _validate_hash(recipient_hash):
        abort(400, "Invalid recipient hash")

    col    = get_collection()
    result = col.delete_one({"msg_id": msg_id, "recipient_hash": recipient_hash})

    if result.deleted_count == 0:
        abort(404, "Message not found")

    return jsonify({"ok": True}), 200


@app.route("/stats", methods=["GET"])
def stats():
    col = get_collection()
    pipeline = [
        {"$group": {"_id": "$recipient_hash", "count": {"$sum": 1}}},
        {"$group": {"_id": None,
                    "recipients": {"$sum": 1},
                    "total":      {"$sum": "$count"}}},
    ]
    result = list(col.aggregate(pipeline))
    if result:
        recipients = result[0]["recipients"]
        total      = result[0]["total"]
    else:
        recipients = total = 0

    return jsonify({
        "recipients_with_messages": recipients,
        "total_pending_messages":   total,
        "message_ttl_seconds":      MESSAGE_TTL,
    })


# ─────────────────────────────────────────────────────────────────
# Start
# ─────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    port = int(os.getenv("PORT", 5000))
    logger.info(f"Hushbox Relay starting on port {port}")
    app.run(host="0.0.0.0", port=port, threaded=True)
