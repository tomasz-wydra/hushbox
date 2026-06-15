"""
EncryptionManager - obsługuje klucze NaCl i szyfrowanie/deszyfrowanie wiadomości.

contact_keys.json przechowuje pełne dane kontaktu:
{
  "Jan Kowalski": {
    "public_key": "base64...",
    "telegram_bot_token": "token bota Jana (Jan Ci go podaje)",
    "telegram_chat_id": "Chat ID Jana (Jan sprawdza przez @userinfobot)"
  }
}

Model Telegram: każdy użytkownik tworzy własnego bota i udostępnia
swojemu kontaktowi: token bota + swoje Chat ID.
Nadawca wysyła zaszyfrowany tekst przez bota ODBIORCY do Chat ID odbiorcy.
Odbiorca polluje swojego własnego bota i automatycznie odbiera wiadomości.
"""
from nacl.public import PrivateKey, PublicKey, Box
from nacl.encoding import Base64Encoder
import json
from pathlib import Path
from dataclasses import dataclass, field, asdict


@dataclass
class ContactInfo:
    public_key: str
    telegram_bot_token: str = ""      # token bota kontaktu (kontakt Ci podaje)
    telegram_chat_id: str = ""        # Chat ID kontaktu (kontakt sprawdza przez @userinfobot)

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict) -> "ContactInfo":
        # obsługa starego formatu (plain string zamiast dict)
        if isinstance(d, str):
            return cls(public_key=d)
        return cls(
            public_key=d.get("public_key", ""),
            telegram_chat_id=d.get("telegram_chat_id", ""),
            telegram_bot_token=d.get("telegram_bot_token", ""),
        )


class EncryptionManager:
    def __init__(self, data_dir: str = "."):
        self.data_dir = Path(data_dir)
        self.data_dir.mkdir(parents=True, exist_ok=True)

        self.private_key_path = self.data_dir / "my_private_key.bin"
        self.contact_keys_path = self.data_dir / "contact_keys.json"

        self.private_key = self._load_or_generate_private_key()
        self.public_key = self.private_key.public_key
        self.contacts: dict[str, ContactInfo] = self._load_contacts()

        # zachowana kompatybilność wsteczna — słownik name→public_key_b64
        self.contact_keys: dict[str, str] = {
            n: c.public_key for n, c in self.contacts.items()
        }

    # ------------------------------------------------------------------
    # Klucze własne
    # ------------------------------------------------------------------

    def _load_or_generate_private_key(self) -> PrivateKey:
        if self.private_key_path.exists():
            with open(self.private_key_path, "rb") as f:
                return PrivateKey(f.read())
        key = PrivateKey.generate()
        with open(self.private_key_path, "wb") as f:
            f.write(bytes(key))
        return key

    def export_public_key(self) -> str:
        return self.public_key.encode(encoder=Base64Encoder).decode()

    # ------------------------------------------------------------------
    # Kontakty
    # ------------------------------------------------------------------

    def _load_contacts(self) -> dict[str, "ContactInfo"]:
        if self.contact_keys_path.exists():
            with open(self.contact_keys_path, "r", encoding="utf-8") as f:
                raw = json.load(f)
            return {name: ContactInfo.from_dict(val) for name, val in raw.items()}
        return {}

    def _save_contacts(self) -> None:
        data = {name: c.to_dict() for name, c in self.contacts.items()}
        with open(self.contact_keys_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        # sync kompatybilny słownik
        self.contact_keys = {n: c.public_key for n, c in self.contacts.items()}

    def add_contact(self, name: str, public_key_b64: str,
                    telegram_bot_token: str = "",
                    telegram_chat_id: str = "") -> None:
        """Dodaj lub zaktualizuj kontakt."""
        name = name.strip()
        if not name:
            raise ValueError("Nazwa kontaktu nie może być pusta.")
        PublicKey(public_key_b64.encode(), encoder=Base64Encoder)  # walidacja
        # zachowaj istniejące dane Telegram jeśli nie podano nowych
        existing = self.contacts.get(name)
        self.contacts[name] = ContactInfo(
            public_key=public_key_b64,
            telegram_chat_id=telegram_chat_id or (existing.telegram_chat_id if existing else ""),
            telegram_bot_token=telegram_bot_token or (existing.telegram_bot_token if existing else ""),
        )
        self._save_contacts()

    def update_telegram(self, name: str, chat_id: str, bot_token: str) -> None:
        """Zaktualizuj dane Telegram dla istniejącego kontaktu."""
        if name not in self.contacts:
            raise KeyError(f"Kontakt '{name}' nie istnieje.")
        self.contacts[name].telegram_chat_id = chat_id.strip()
        self.contacts[name].telegram_bot_token = bot_token.strip()
        self._save_contacts()

    def get_contact(self, name: str) -> ContactInfo:
        if name not in self.contacts:
            raise KeyError(f"Kontakt '{name}' nie istnieje.")
        return self.contacts[name]

    def remove_contact(self, name: str) -> None:
        if name not in self.contacts:
            raise KeyError(f"Kontakt '{name}' nie istnieje.")
        del self.contacts[name]
        self._save_contacts()

    def rename_contact(self, old_name: str, new_name: str) -> None:
        new_name = new_name.strip()
        if old_name not in self.contacts:
            raise KeyError(f"Kontakt '{old_name}' nie istnieje.")
        if not new_name:
            raise ValueError("Nowa nazwa nie może być pusta.")
        self.contacts[new_name] = self.contacts.pop(old_name)
        self._save_contacts()

    def list_contacts(self) -> list[str]:
        return sorted(self.contacts.keys())

    def has_contact(self, name: str) -> bool:
        return name in self.contacts

    # ------------------------------------------------------------------
    # Szyfrowanie / Deszyfrowanie
    # ------------------------------------------------------------------

    def _get_box(self, contact_name: str) -> Box:
        if contact_name not in self.contacts:
            raise KeyError(f"Brak klucza publicznego dla kontaktu '{contact_name}'.")
        recipient_key = PublicKey(
            self.contacts[contact_name].public_key.encode(),
            encoder=Base64Encoder,
        )
        return Box(self.private_key, recipient_key)

    def encrypt(self, contact_name: str, plaintext: str) -> str:
        box = self._get_box(contact_name)
        encrypted = box.encrypt(plaintext.encode("utf-8"), encoder=Base64Encoder)
        return encrypted.decode()

    def decrypt(self, contact_name: str, ciphertext: str) -> str:
        box = self._get_box(contact_name)
        decrypted = box.decrypt(ciphertext.strip().encode(), encoder=Base64Encoder)
        return decrypted.decode("utf-8")
