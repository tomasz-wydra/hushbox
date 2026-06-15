"""
AppSettings — globalne ustawienia aplikacji (przechowywane w settings.json).
"""
import json
from pathlib import Path


class AppSettings:
    def __init__(self, data_dir: str = "."):
        self._path = Path(data_dir) / "settings.json"
        self._data = self._load()

    def _load(self) -> dict:
        if self._path.exists():
            with open(self._path, "r", encoding="utf-8") as f:
                return json.load(f)
        return {}

    def _save(self) -> None:
        with open(self._path, "w", encoding="utf-8") as f:
            json.dump(self._data, f, indent=2, ensure_ascii=False)

    @property
    def my_bot_token(self) -> str:
        return self._data.get("my_bot_token", "")

    @my_bot_token.setter
    def my_bot_token(self, value: str) -> None:
        self._data["my_bot_token"] = value.strip()
        self._save()

    @property
    def last_update_id(self) -> int:
        """Ostatni przetworzony update_id — zapisywany między sesjami."""
        return self._data.get("last_update_id", 0)

    @last_update_id.setter
    def last_update_id(self, value: int) -> None:
        self._data["last_update_id"] = value
        self._save()
