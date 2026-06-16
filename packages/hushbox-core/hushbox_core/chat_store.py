"""
ChatStore - przechowuje historię rozmów i zarządza wiadomościami.
"""
from dataclasses import dataclass, field
from datetime import datetime
import json
from pathlib import Path


@dataclass
class Message:
    direction: str       # "out" | "in"
    plaintext: str
    ciphertext: str
    timestamp: str = field(default_factory=lambda: datetime.now().strftime("%H:%M:%S"))
    via_telegram: bool = False

    def to_dict(self) -> dict:
        return {
            "direction": self.direction,
            "plaintext": self.plaintext,
            "ciphertext": self.ciphertext,
            "timestamp": self.timestamp,
            "via_telegram": self.via_telegram,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "Message":
        return cls(
            direction=d["direction"],
            plaintext=d["plaintext"],
            ciphertext=d["ciphertext"],
            timestamp=d.get("timestamp", ""),
            via_telegram=d.get("via_telegram", False),
        )


class ChatStore:
    """Persystentna historia rozmów per-kontakt."""

    def __init__(self, data_dir: str = "."):
        self.data_dir = Path(data_dir) / "chat_history"
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self._histories: dict[str, list[Message]] = {}

    def _path(self, contact: str) -> Path:
        safe = contact.replace("/", "_").replace("\\", "_")
        return self.data_dir / f"{safe}.json"

    def load(self, contact: str) -> list[Message]:
        if contact not in self._histories:
            p = self._path(contact)
            if p.exists():
                with open(p, "r", encoding="utf-8") as f:
                    raw = json.load(f)
                self._histories[contact] = [Message.from_dict(m) for m in raw]
            else:
                self._histories[contact] = []
        return self._histories[contact]

    def add_message(self, contact: str, msg: Message) -> None:
        history = self.load(contact)
        history.append(msg)
        with open(self._path(contact), "w", encoding="utf-8") as f:
            json.dump([m.to_dict() for m in history], f, indent=2, ensure_ascii=False)

    def clear_history(self, contact: str) -> None:
        self._histories[contact] = []
        p = self._path(contact)
        if p.exists():
            p.unlink()

    def delete_contact_history(self, contact: str) -> None:
        self.clear_history(contact)
        self._histories.pop(contact, None)
