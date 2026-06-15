"""
EncryptionManager — obsługuje klucze NaCl i szyfrowanie/deszyfrowanie wiadomości.

contact_keys.json przechowuje pełne dane kontaktu:
{
  "Jan Kowalski": {
    "public_key": "base64...",
    "relay_url":  "https://relay.twoja-domena.pl"   // opcjonalny override per kontakt
  }
}

Model relay: każdy użytkownik posiada własny klucz publiczny NaCl.
Nadawca szyfruje wiadomość kluczem odbiorcy i wysyła przez relay serwer.
Odbiorca pobiera wiadomości z relay używając hash swojego klucza publicznego.
"""
from nacl.public import PrivateKey, PublicKey, Box
from nacl.encoding import Base64Encoder
import hashlib
import json
from pathlib import Path
from dataclasses import dataclass, field, asdict


@dataclass
class ContactInfo:
    public_key: str
    relay_url:  str = ""   # opcjonalny override URL relay per kontakt

    # Pola legacy Telegram — zachowane dla migracji ze starszych wersji
    telegram_bot_token: str = ""
    telegram_chat_id:   str = ""

    @property
    def pubkey_hash(self) -> str:
        """SHA-256 klucza publicznego — identyfikator w relay."""
        return hashlib.sha256(self.public_key.encode()).hexdigest()

    def to_dict(self) -> dict:
        d = {
            "public_key": self.public_key,
            "relay_url":  self.relay_url,
        }
        # zachowaj pola Telegram jeśli niepuste (kompatybilność wsteczna)
        if self.telegram_bot_token:
            d["telegram_bot_token"] = self.telegram_bot_token
        if self.telegram_chat_id:
            d["telegram_chat_id"] = self.telegram_chat_id
        return d

    @classmethod
    def from_dict(cls, d: dict) -> "ContactInfo":
        # obsługa starego formatu (plain string zamiast dict)
        if isinstance(d, str):
            return cls(public_key=d)
        return cls(
            public_key=         d.get("public_key", ""),
            relay_url=          d.get("relay_url",  ""),
            telegram_bot_token= d.get("telegram_bot_token", ""),
            telegram_chat_id=   d.get("telegram_chat_id",  ""),
        )


class EncryptionManager:
    def __init__(self, data_dir: str = "."):
        self.data_dir = Path(data_dir)
        self.data_dir.mkdir(parents=True, exist_ok=True)

        self.private_key_path  = self.data_dir / "my_private_key.bin"
        self.contact_keys_path = self.data_dir / "contact_keys.json"

        self.private_key = self._load_or_generate_private_key()
        self.public_key  = self.private_key.public_key
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

    def my_pubkey_hash(self) -> str:
        """SHA-256 własnego klucza publicznego."""
        return hashlib.sha256(self.export_public_key().encode()).hexdigest()

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
                    relay_url: str = "",
                    # legacy Telegram params — ignorowane jeśli relay_url ustawiony
                    telegram_bot_token: str = "",
                    telegram_chat_id:   str = "") -> None:
        """Dodaj lub zaktualizuj kontakt."""
        name = name.strip()
        if not name:
            raise ValueError("Nazwa kontaktu nie może być pusta.")
        PublicKey(public_key_b64.encode(), encoder=Base64Encoder)  # walidacja
        existing = self.contacts.get(name)
        self.contacts[name] = ContactInfo(
            public_key=         public_key_b64,
            relay_url=          relay_url or (existing.relay_url if existing else ""),
            telegram_bot_token= telegram_bot_token or (existing.telegram_bot_token if existing else ""),
            telegram_chat_id=   telegram_chat_id   or (existing.telegram_chat_id   if existing else ""),
        )
        self._save_contacts()

    def update_relay(self, name: str, relay_url: str) -> None:
        """Zaktualizuj relay URL dla kontaktu."""
        if name not in self.contacts:
            raise KeyError(f"Kontakt '{name}' nie istnieje.")
        self.contacts[name].relay_url = relay_url.strip()
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

    def find_contact_by_pubkey_hash(self, pubkey_hash: str) -> str | None:
        """Znajdź nazwę kontaktu po SHA-256 jego klucza publicznego."""
        for name, info in self.contacts.items():
            if info.pubkey_hash == pubkey_hash:
                return name
        return None

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
