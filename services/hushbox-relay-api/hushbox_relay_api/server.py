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
  GET    /healthz                         — liveness (nie dotyka bazy)
  GET    /health                          — readiness (pinguje MongoDB)
  GET    /stats                           — statystyki kolejki (opcjonalnie za tokenem)

SKALOWANIE: long polling używa zdarzeń trzymanych w pamięci procesu, więc
serwer musi działać w JEDNYM procesie roboczym (patrz komentarz w Dockerfile).
Wiele procesów rozjeżdża powiadomienia: POST trafia do procesu A, a klient
czekający w procesie B przesypia cały timeout. Horyzontalne skalowanie wymaga
wspólnego pub/sub (Redis albo MongoDB change streams).
"""

import os
import time
import uuid
import logging
from hmac import compare_digest
from threading import Event, Lock
from datetime import datetime, timezone

from flask import Flask, request, jsonify, abort
from werkzeug.exceptions import HTTPException
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

# Token chroniący /stats. Endpoint ujawnia metadane ruchu (ilu odbiorców ma
# zaległe wiadomości), co dla komunikatora nastawionego na prywatność jest
# wyciekiem. Puste = endpoint otwarty (zachowanie legacy).
STATS_TOKEN       = os.getenv("STATS_TOKEN", "")

# Górny limit ciała żądania. MAX_PAYLOAD dotyczy samego pola "payload", ale bez
# tego limitu Flask sparsowałby najpierw cały JSON do pamięci — dowolnie duży.
# Zapas pokrywa kopertę JSON, dwa 64-znakowe hashe i narzut base64.
MAX_BODY_BYTES    = int(os.getenv("MAX_BODY_BYTES", str(MAX_PAYLOAD + 8 * 1024)))

# Ile jednocześnie oczekujących skrzynek dopuszczamy w rejestrze long-poll.
MAX_WAITERS        = int(os.getenv("MAX_WAITERS", "10000"))

logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = MAX_BODY_BYTES

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

class WaiterRegistry:
    """Rejestr zdarzeń long-poll z licznikiem referencji.

    Poprzednia implementacja (``defaultdict(Event)``) rosła bez ograniczeń:
    każde zapytanie o losowy hash zostawiało trwały obiekt ``Event`` w pamięci
    procesu. Nieuwierzytelniony klient mógł tak wyczerpać RAM serwera.

    Tutaj zdarzenie istnieje tylko dopóki ktoś na nie czeka, a liczba
    równoległych oczekujących skrzynek jest ograniczona przez ``MAX_WAITERS``.
    """

    def __init__(self, max_waiters: int = MAX_WAITERS):
        self._lock = Lock()
        self._events: dict[str, Event] = {}
        self._refs:   dict[str, int]   = {}
        self._max = max_waiters

    def acquire(self, key: str) -> Event | None:
        """Zarejestruj oczekującego. ``None`` = przekroczony limit."""
        with self._lock:
            if key not in self._events:
                if len(self._events) >= self._max:
                    return None
                self._events[key] = Event()
                self._refs[key] = 0
            self._refs[key] += 1
            return self._events[key]

    def release(self, key: str) -> None:
        """Wyrejestruj oczekującego; usuń zdarzenie, gdy nikt już nie czeka."""
        with self._lock:
            if key not in self._refs:
                return
            self._refs[key] -= 1
            if self._refs[key] <= 0:
                self._refs.pop(key, None)
                self._events.pop(key, None)

    def notify(self, key: str) -> None:
        """Obudź oczekujących na danej skrzynce (jeśli są)."""
        with self._lock:
            event = self._events.get(key)
        if event is not None:
            event.set()
            event.clear()

    def waiting_inboxes(self) -> int:
        with self._lock:
            return len(self._events)


_waiters = WaiterRegistry()


def _validate_hash(h: str) -> bool:
    if len(h) != 64:
        return False
    try:
        int(h, 16)
        return True
    except ValueError:
        return False


def _int_arg(name: str, default: int, cap: int) -> int:
    """Pobierz nieujemny parametr całkowitoliczbowy z query stringa.

    Wcześniej surowe ``int(request.args.get(...))`` wywracało się na HTTP 500
    przy dowolnej niecyfrowej wartości (``?timeout=abc``) — zdalny, trywialny
    sposób generowania błędów 5xx i zaśmiecania logów tracebackami.
    """
    raw = request.args.get(name)
    if raw is None or raw == "":
        return default
    try:
        value = int(raw)
    except (TypeError, ValueError):
        abort(400, f"Parametr '{name}' musi być liczbą całkowitą")
    if value < 0:
        abort(400, f"Parametr '{name}' nie może być ujemny")
    return min(value, cap)


# ─────────────────────────────────────────────────────────────────
# Obsługa błędów — zawsze JSON, nigdy HTML ani traceback
# ─────────────────────────────────────────────────────────────────

@app.errorhandler(HTTPException)
def _http_error(exc: HTTPException):
    return jsonify({"ok": False, "error": exc.description}), exc.code


@app.errorhandler(Exception)
def _unexpected_error(exc: Exception):
    # Logujemy pełny ślad po stronie serwera, klientowi nie mówimy nic.
    logger.exception(f"Unhandled error: {exc}")
    return jsonify({"ok": False, "error": "Internal server error"}), 500


# ─────────────────────────────────────────────────────────────────
# Endpoints
# ─────────────────────────────────────────────────────────────────

@app.route("/healthz", methods=["GET"])
def healthz():
    """Liveness — żyje sam proces WSGI.

    Celowo NIE dotyka MongoDB: docker healthcheck ma restartować kontener tylko
    wtedy, gdy zawinił sam serwer. Chwilowa niedostępność bazy nie powinna
    kaskadowo ubijać relaya. Do sprawdzenia gotowości (łącznie z bazą) służy
    ``/health``, który zwraca 503, gdy Mongo nie odpowiada.

    Endpoint jest nieuwierzytelniony, ale nie ujawnia nic wrażliwego — sam
    timestamp jest i tak widoczny w nagłówku HTTP ``Date``.
    """
    return jsonify({
        "status": "ok",
        "ts": time.time(),
    }), 200


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
    _waiters.notify(to_hash)

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
    timeout = _int_arg("timeout", 0,  LONG_POLL_TIMEOUT)
    limit   = _int_arg("limit",   50, 200)

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
        event = _waiters.acquire(recipient_hash)
        if event is None:
            # Zbyt wielu oczekujących — degradujemy do zwykłego pollingu zamiast
            # rosnąć w pamięci. Klient po prostu zapyta ponownie.
            logger.warning("Long-poll registry full, refusing to wait")
            return jsonify({"ok": True, "messages": []})
        try:
            event.wait(timeout=timeout)
            msgs = _fetch()
        finally:
            _waiters.release(recipient_hash)

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
    """Statystyki kolejki.

    Ujawnia metadane ruchu, dlatego można je zamknąć tokenem: ustaw zmienną
    środowiskową ``STATS_TOKEN`` i wysyłaj nagłówek ``X-Stats-Token``.
    Bez ustawionego tokenu endpoint pozostaje otwarty (kompatybilność wstecz).
    """
    if STATS_TOKEN:
        provided = request.headers.get("X-Stats-Token", "")
        if not compare_digest(provided, STATS_TOKEN):
            abort(403, "Nieprawidłowy token statystyk")

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
        "waiting_inboxes":          _waiters.waiting_inboxes(),
    })


# ─────────────────────────────────────────────────────────────────
# Start
# ─────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    port = int(os.getenv("PORT", 5000))
    logger.info(f"Hushbox Relay starting on port {port}")
    app.run(host="0.0.0.0", port=port, threaded=True)
