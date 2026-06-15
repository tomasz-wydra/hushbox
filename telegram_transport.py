"""
TelegramTransport — wysyłanie i odbieranie zaszyfrowanych wiadomości przez Telegram Bot API.

Każdy użytkownik ma własnego bota (token z BotFather).
Bot służy wyłącznie jako "listonosz" — przesyła zaszyfrowane blobs, nie zna treści.

Architektura:
  - send()     → POST /sendMessage  (synchroniczne, przez httpx)
  - start_polling() → uruchamia wątek pobierający nowe wiadomości co POLL_INTERVAL sekund
  - stop_polling()  → zatrzymuje wątek
  - on_message  → callback wywoływany gdy przyjdzie nowa wiadomość: (chat_id, text)
"""

import threading
import time
import logging
import httpx
from typing import Callable

logger = logging.getLogger(__name__)

POLL_INTERVAL = 1        # sekundy między kolejnymi getUpdates (fallback po błędzie)
LONG_POLL_TIMEOUT = 30   # Telegram trzyma połączenie otwarte — natychmiastowy push
REQUEST_TIMEOUT = 35     # musi być > LONG_POLL_TIMEOUT


class TelegramTransport:
    BASE = "https://api.telegram.org/bot{token}/{method}"

    def __init__(self, bot_token: str, last_update_id: int = 0,
                 on_update_id_change=None):
        self.token = bot_token.strip()
        self._last_update_id: int = last_update_id
        self._initialized: bool = last_update_id > 0  # jeśli mamy zapisany offset — od razu odbieramy
        self._on_update_id_change = on_update_id_change  # callback(new_id) — zapis do settings
        self._polling_thread: threading.Thread | None = None
        self._stop_event = threading.Event()
        # callback(chat_id: str, text: str) wywoływany w wątku pollingu
        self.on_message: Callable[[str, str], None] | None = None

    # ──────────────────────────────────────────────────────────────
    # API helpers
    # ──────────────────────────────────────────────────────────────

    def _url(self, method: str) -> str:
        return self.BASE.format(token=self.token, method=method)

    def _post(self, method: str, payload: dict) -> dict:
        with httpx.Client(timeout=REQUEST_TIMEOUT) as client:
            r = client.post(self._url(method), json=payload)
            r.raise_for_status()
            return r.json()

    def _get(self, method: str, params: dict | None = None) -> dict:
        with httpx.Client(timeout=REQUEST_TIMEOUT) as client:
            r = client.get(self._url(method), params=params or {})
            r.raise_for_status()
            return r.json()

    # ──────────────────────────────────────────────────────────────
    # Publiczne API
    # ──────────────────────────────────────────────────────────────

    def validate_token(self) -> dict:
        """
        Sprawdź poprawność tokena — wywołaj getMe.
        Zwraca słownik z danymi bota lub rzuca wyjątek.
        """
        data = self._get("getMe")
        if not data.get("ok"):
            raise ValueError(f"Token nieprawidłowy: {data}")
        return data["result"]

    def send(self, chat_id: str, text: str) -> dict:
        """
        Wyślij wiadomość tekstową do chat_id.
        chat_id może być numerycznym ID lub @username.
        Zwraca odpowiedź API lub rzuca wyjątek przy błędzie.
        """
        if not chat_id:
            raise ValueError("chat_id nie może być pusty.")
        if not text:
            raise ValueError("Wiadomość nie może być pusta.")

        payload = {
            "chat_id": chat_id,
            "text": text,
            # wyłączone podglądy linków — wiadomość to zaszyfrowany blob
            "disable_web_page_preview": True,
        }
        result = self._post("sendMessage", payload)
        if not result.get("ok"):
            raise RuntimeError(f"Telegram API error: {result}")
        return result

    def get_my_chat_id(self) -> str | None:
        """
        Zwróć chat_id ostatniej osoby która napisała do bota.
        Przydatne przy pierwszym uruchomieniu — użytkownik pisze /start,
        a aplikacja odczytuje jego chat_id.
        """
        data = self._get("getUpdates", {"limit": 1, "offset": -1})
        updates = data.get("result", [])
        if not updates:
            return None
        msg = updates[-1].get("message", {})
        chat = msg.get("chat", {})
        return str(chat.get("id", ""))

    # ──────────────────────────────────────────────────────────────
    # Polling
    # ──────────────────────────────────────────────────────────────

    def start_polling(self) -> None:
        """Uruchom wątek pobierający nowe wiadomości w tle."""
        if self._polling_thread and self._polling_thread.is_alive():
            return
        self._stop_event.clear()
        self._polling_thread = threading.Thread(
            target=self._poll_loop, daemon=True, name="TelegramPoller"
        )
        self._polling_thread.start()
        logger.info("Telegram polling started.")

    def stop_polling(self) -> None:
        """Zatrzymaj wątek pollingu (non-blocking)."""
        self._stop_event.set()
        # Nie czekamy na join() — wątek jest daemon, zakończy się sam.
        # join() blokowałby GUI na REQUEST_TIMEOUT sekund przy każdym restarcie.
        logger.info("Telegram polling stop requested.")

    @property
    def is_polling(self) -> bool:
        return bool(self._polling_thread and self._polling_thread.is_alive())

    def _poll_loop(self) -> None:
        while not self._stop_event.is_set():
            try:
                self._fetch_updates()
            except Exception as e:
                logger.warning(f"Polling error: {e}")
            # Krótka przerwa tylko po błędzie — przy long pollingu getUpdates
            # blokuje się sam przez LONG_POLL_TIMEOUT sekund
            if self._stop_event.is_set():
                break
            self._stop_event.wait(POLL_INTERVAL)

    def _fetch_updates(self) -> None:
        if not self._initialized:
            # INIT: pobierz wszystkie wiadomości które bot ma w kolejce (w tym "odczytane"
            # przez Telegram Mobile) — dostarczamy je od razu zamiast pomijać.
            # Używamy last_update_id+1 jeśli mamy zapisany offset, inaczej bez offsetu.
            if self._last_update_id > 0:
                init_params = {
                    "offset": self._last_update_id + 1,
                    "timeout": 0,
                    "allowed_updates": ["message"],
                }
            else:
                init_params = {
                    "timeout": 0,
                    "allowed_updates": ["message"],
                }
            data = self._get("getUpdates", init_params)
            updates = data.get("result", [])
            logger.debug(f"[TG] INIT getUpdates -> {len(updates)} updates (last_id={self._last_update_id})")
            # Dostarcz wszystkie oczekujące wiadomości natychmiast
            for update in updates:
                uid = update.get("update_id", 0)
                if uid > self._last_update_id:
                    self._last_update_id = uid
                    if self._on_update_id_change:
                        self._on_update_id_change(self._last_update_id)
                self._handle_update(update)
            self._initialized = True
            logger.debug(f"[TG] INIT done, last_update_id={self._last_update_id}")
            return

        # Normalny polling — long polling: Telegram trzyma połączenie do 30s
        # i odpowiada natychmiast gdy przyjdzie nowa wiadomość
        offset = self._last_update_id + 1
        params = {
            "offset": offset,
            "timeout": LONG_POLL_TIMEOUT,
            "allowed_updates": ["message"],
        }
        data = self._get("getUpdates", params)
        updates = data.get("result", [])
        logger.debug(f"[TG] getUpdates offset={offset} -> {len(updates)} updates")
        for u in updates:
            logger.debug(f"[TG] raw update: {u}")

        for update in updates:
            uid = update.get("update_id", 0)
            if uid > self._last_update_id:
                self._last_update_id = uid
                if self._on_update_id_change:
                    self._on_update_id_change(self._last_update_id)
            self._handle_update(update)

    def _handle_update(self, update: dict) -> None:
        msg = update.get("message")
        if not msg:
            return
        text = msg.get("text", "").strip()
        chat_id = str(msg.get("chat", {}).get("id", ""))
        logger.debug(f"[TG] update received: chat_id={chat_id!r}, text_len={len(text)}, has_callback={self.on_message is not None}")
        if text and chat_id and self.on_message:
            self.on_message(chat_id, text)
