"""
RelayTransport — wysyłanie i odbieranie zaszyfrowanych wiadomości przez Hushbox Relay.

Serwer relay to store-and-forward HTTP — nie zna treści wiadomości.
Identyfikacja odbywa się przez SHA-256 klucza publicznego (pubkey_hash).

Architektura:
  - send()          → POST /messages  (synchroniczne, przez httpx)
  - start_polling() → wątek long-polling GET /messages/{my_hash}
  - stop_polling()  → zatrzymuje wątek
  - on_message      → callback(from_hash: str, payload: str)
"""

import hashlib
import threading
import time
import logging
import httpx
from typing import Callable

logger = logging.getLogger(__name__)

POLL_INTERVAL       = 1     # przerwa po błędzie (s)
LONG_POLL_TIMEOUT   = 30    # Relay trzyma połączenie otwarte (s)
REQUEST_TIMEOUT     = 35    # musi być > LONG_POLL_TIMEOUT
DEFAULT_RELAY_URL   = "http://localhost:5000"


def pubkey_to_hash(public_key_b64: str) -> str:
    """Oblicz SHA-256 klucza publicznego (base64) → hex string."""
    return hashlib.sha256(public_key_b64.encode()).hexdigest()


class RelayTransport:
    """Transport wiadomości przez Hushbox Relay Server."""

    def __init__(self,
                 relay_url: str,
                 my_pubkey_b64: str,
                 last_message_id: str = "",
                 on_last_id_change: Callable[[str], None] | None = None):
        """
        Args:
            relay_url:         URL serwera relay, np. "https://relay.twoja-domena.pl"
            my_pubkey_b64:     Własny klucz publiczny (base64) — do obliczenia hash odbiorcy
            last_message_id:   Ostatnie odebrane msg ID (do wznawiania po restarcie)
            on_last_id_change: Callback(new_id) — wywoływany przy zapisie nowego last_id
        """
        self.relay_url         = relay_url.rstrip("/")
        self.my_hash           = pubkey_to_hash(my_pubkey_b64)
        self._last_message_id  = last_message_id
        self._on_last_id_change = on_last_id_change

        self._polling_thread: threading.Thread | None = None
        self._stop_event = threading.Event()

        # callback(from_hash: str, payload: str) wywoływany w wątku pollingu
        self.on_message: Callable[[str, str], None] | None = None

    # ──────────────────────────────────────────────────────────────
    # Publiczne API
    # ──────────────────────────────────────────────────────────────

    def send(self, recipient_pubkey_b64: str, payload: str,
             sender_pubkey_b64: str = "") -> dict:
        """
        Wyślij zaszyfrowany payload do odbiorcy.

        Args:
            recipient_pubkey_b64: Klucz publiczny odbiorcy (base64)
            payload:              Zaszyfrowany blob (base64)
            sender_pubkey_b64:    Opcjonalnie — własny klucz publiczny
        Returns:
            Odpowiedź serwera {"ok": True, "id": "..."}
        """
        if not recipient_pubkey_b64:
            raise ValueError("recipient_pubkey_b64 nie może być pusty")
        if not payload:
            raise ValueError("payload nie może być pusty")

        body = {
            "to":      pubkey_to_hash(recipient_pubkey_b64),
            "payload": payload,
        }
        if sender_pubkey_b64:
            body["from"] = pubkey_to_hash(sender_pubkey_b64)

        with httpx.Client(timeout=REQUEST_TIMEOUT) as client:
            r = client.post(f"{self.relay_url}/messages", json=body)
            r.raise_for_status()
            result = r.json()

        if not result.get("ok"):
            raise RuntimeError(f"Relay error: {result}")
        logger.debug(f"[Relay] sent -> {body['to'][:8]}... id={result.get('id','?')[:8]}")
        return result

    def start_polling(self) -> None:
        """Uruchom wątek long-polling w tle."""
        if self._polling_thread and self._polling_thread.is_alive():
            return
        self._stop_event.clear()
        self._polling_thread = threading.Thread(
            target=self._poll_loop, daemon=True, name="RelayPoller"
        )
        self._polling_thread.start()
        logger.info(f"Relay polling started (hash={self.my_hash[:8]}...)")

    def stop_polling(self) -> None:
        """Zatrzymaj wątek pollingu (non-blocking)."""
        self._stop_event.set()
        logger.info("Relay polling stop requested.")

    @property
    def is_polling(self) -> bool:
        return bool(self._polling_thread and self._polling_thread.is_alive())

    # ──────────────────────────────────────────────────────────────
    # Wewnętrzne
    # ──────────────────────────────────────────────────────────────

    def _poll_loop(self) -> None:
        while not self._stop_event.is_set():
            try:
                self._fetch_messages()
            except Exception as e:
                logger.warning(f"Relay polling error: {e}")
                self._stop_event.wait(POLL_INTERVAL)

    def _fetch_messages(self) -> None:
        params: dict = {
            "timeout": LONG_POLL_TIMEOUT,
            "limit":   50,
        }
        if self._last_message_id:
            params["since"] = self._last_message_id

        with httpx.Client(timeout=REQUEST_TIMEOUT) as client:
            r = client.get(
                f"{self.relay_url}/messages/{self.my_hash}",
                params=params,
            )
            r.raise_for_status()
            data = r.json()

        messages = data.get("messages", [])
        logger.debug(f"[Relay] poll -> {len(messages)} messages (since={self._last_message_id[:8] if self._last_message_id else 'start'})")

        for msg in messages:
            msg_id   = msg.get("id", "")
            from_h   = msg.get("from", "")
            payload  = msg.get("payload", "")

            if msg_id:
                self._last_message_id = msg_id
                if self._on_last_id_change:
                    self._on_last_id_change(msg_id)

            if payload and self.on_message:
                self.on_message(from_h, payload)

            # Potwierdź odbiór (DELETE) w tle — nie blokuj pętli
            if msg_id:
                threading.Thread(
                    target=self._ack, args=(msg_id,), daemon=True
                ).start()

    def _ack(self, msg_id: str) -> None:
        """Potwierdź odbiór wiadomości — usuwa ją z kolejki serwera."""
        try:
            with httpx.Client(timeout=10) as client:
                client.delete(
                    f"{self.relay_url}/messages/{self.my_hash}/{msg_id}"
                )
        except Exception as e:
            logger.debug(f"[Relay] ack failed for {msg_id[:8]}: {e}")
