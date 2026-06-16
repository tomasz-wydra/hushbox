"""
Ustawienia aplikacji Hushbox — persystowane w settings.json.

Migracja:
  v1: my_bot_token + last_update_id  (Telegram)
  v2: relay_url + last_message_id    (własny relay)
"""

import json
import logging
from pathlib import Path

logger = logging.getLogger(__name__)

SETTINGS_FILE = "settings.json"


class AppSettings:
    def __init__(self, data_dir: str = "."):
        self._path = Path(data_dir) / SETTINGS_FILE
        self._data: dict = {}
        self._load()

    def _load(self):
        if self._path.exists():
            try:
                with open(self._path, "r", encoding="utf-8") as f:
                    self._data = json.load(f)
            except Exception as e:
                logger.warning(f"Cannot read settings: {e}")
                self._data = {}

    def save(self):
        try:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            with open(self._path, "w", encoding="utf-8") as f:
                json.dump(self._data, f, indent=2, ensure_ascii=False)
        except Exception as e:
            logger.error(f"Cannot save settings: {e}")

    # ── Relay ────────────────────────────────────────────────────

    @property
    def relay_url(self) -> str:
        return self._data.get("relay_url", "")

    @relay_url.setter
    def relay_url(self, value: str):
        self._data["relay_url"] = value.strip()
        self.save()

    @property
    def last_message_id(self) -> str:
        return self._data.get("last_message_id", "")

    @last_message_id.setter
    def last_message_id(self, value: str):
        self._data["last_message_id"] = value
        self.save()

    # ── Telegram (legacy — zachowane dla migracji) ───────────────

    @property
    def my_bot_token(self) -> str:
        return self._data.get("my_bot_token", "")

    @my_bot_token.setter
    def my_bot_token(self, value: str):
        self._data["my_bot_token"] = value.strip()
        self.save()

    @property
    def last_update_id(self) -> int:
        return int(self._data.get("last_update_id", 0))

    @last_update_id.setter
    def last_update_id(self, value: int):
        self._data["last_update_id"] = value
        self.save()
