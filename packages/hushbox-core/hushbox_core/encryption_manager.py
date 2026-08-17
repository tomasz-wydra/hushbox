"""
EncryptionManager — obsługuje klucze NaCl i szyfrowanie/deszyfrowanie wiadomości.

contact_keys.json przechowuje pełne dane kontaktu:
{
  "Jan Kowalski": {
    "public_key": "base64...",
    "relay_url":  "https://relay.twoja-domena.pl",  // opcjonalny override per kontakt
    "verified":   true                              // fingerprint potwierdzony out-of-band
  }
}

Model relay: każdy użytkownik posiada własny klucz publiczny NaCl.
Nadawca szyfruje wiadomość kluczem odbiorcy i wysyła przez relay serwer.
Odbiorca pobiera wiadomości z relay używając hash swojego klucza publicznego.

DWA RÓŻNE SKRÓTY KLUCZA PUBLICZNEGO — nie mieszać:

  * ``pubkey_hash``  — SHA-256 nad **stringiem base64** klucza publicznego.
    To identyfikator skrzynki na relayu i część kontraktu protokołu przewodowego.
    Każdy nowy klient (mobilny, web) MUSI hashować base64, nie surowe bajty,
    inaczej skrzynki się rozjadą i wiadomości nie dotrą.

  * ``fingerprint``  — SHA-256 nad **surowymi 32 bajtami** klucza publicznego.
    To wartość pokazywana człowiekowi do weryfikacji out-of-band (TOFU).
    Liczona nad materiałem klucza, a nie nad jego transportowym kodowaniem,
    więc pozostaje stabilna niezależnie od wariantu base64.

Ochrona klucza prywatnego: patrz :mod:`hushbox_core.keyfile`. Hasło jest
opcjonalne — pliki legacy (surowe 32 bajty) są nadal wczytywane, żeby nie
zepsuć istniejących instalacji.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import os
from dataclasses import dataclass
from pathlib import Path

from nacl.encoding import Base64Encoder
from nacl.exceptions import CryptoError
from nacl.public import Box, PrivateKey, PublicKey

from . import keyfile
from .errors import (
    DecryptionError,
    FingerprintMismatch,
    InvalidCiphertextFormat,
    KeyConflictError,
)

# Ile znaków hex w grupie przy formatowaniu fingerprinta dla człowieka.
_FP_GROUP = 4


def _decode_pubkey(public_key_b64: str) -> bytes:
    """Zwaliduj i zdekoduj klucz publiczny base64 do surowych 32 bajtów."""
    key = PublicKey(public_key_b64.encode(), encoder=Base64Encoder)
    return bytes(key)


def fingerprint_for_pubkey(public_key_b64: str) -> str:
    """SHA-256 surowych bajtów klucza publicznego, w grupach po 4 znaki hex.

    Przykład: ``A1B2 C3D4 E5F6 ...`` — 64 znaki hex w 16 grupach.
    """
    digest = hashlib.sha256(_decode_pubkey(public_key_b64)).hexdigest().upper()
    return " ".join(
        digest[i : i + _FP_GROUP] for i in range(0, len(digest), _FP_GROUP)
    )


def normalize_fingerprint(value: str) -> str:
    """Zredukuj fingerprint do samych znaków hex (lowercase) do porównań.

    Pozwala porównywać wartość wpisaną przez użytkownika (ze spacjami,
    w dowolnej wielkości liter, wklejoną z SMS-a) z wartością wyliczoną.
    """
    return "".join(value.split()).lower()


@dataclass
class ContactInfo:
    public_key: str
    relay_url:  str = ""   # opcjonalny override URL relay per kontakt

    # TOFU — czy użytkownik potwierdził fingerprint kanałem out-of-band.
    verified: bool = False

    # Pola legacy Telegram — zachowane dla migracji ze starszych wersji
    telegram_bot_token: str = ""
    telegram_chat_id:   str = ""

    @property
    def pubkey_hash(self) -> str:
        """SHA-256 klucza publicznego (base64) — identyfikator w relay.

        Hashowany jest string base64, NIE surowe bajty. Patrz docstring modułu.
        """
        return hashlib.sha256(self.public_key.encode()).hexdigest()

    @property
    def fingerprint(self) -> str:
        """SHA-256 surowych bajtów klucza — do weryfikacji przez człowieka."""
        return fingerprint_for_pubkey(self.public_key)

    def to_dict(self) -> dict:
        d = {
            "public_key": self.public_key,
            "relay_url":  self.relay_url,
            "verified":   self.verified,
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
            # Kontakty z wersji przed TOFU są traktowane jako NIEzweryfikowane.
            verified=           bool(d.get("verified", False)),
            telegram_bot_token= d.get("telegram_bot_token", ""),
            telegram_chat_id=   d.get("telegram_chat_id",  ""),
        )


class EncryptionManager:
    def __init__(self, data_dir: str | os.PathLike[str] = ".",
                 passphrase: str | None = None):
        """
        :param data_dir: katalog na klucz prywatny i kontakty.
        :param passphrase: hasło do klucza prywatnego. Wymagane tylko wtedy, gdy
            plik klucza jest chroniony hasłem — sprawdź to bez hasła przez
            :func:`hushbox_core.keyfile.path_is_encrypted`. Jeśli podane przy
            pierwszym uruchomieniu, nowo wygenerowany klucz zostanie od razu
            zapisany w formie zaszyfrowanej.
        """
        self.data_dir = Path(data_dir)
        self.data_dir.mkdir(parents=True, exist_ok=True)

        self.private_key_path  = self.data_dir / "my_private_key.bin"
        self.contact_keys_path = self.data_dir / "contact_keys.json"

        self.private_key = self._load_or_generate_private_key(passphrase)
        self.public_key  = self.private_key.public_key
        self.contacts: dict[str, ContactInfo] = self._load_contacts()

        # zachowana kompatybilność wsteczna — słownik name→public_key_b64
        self.contact_keys: dict[str, str] = {
            n: c.public_key for n, c in self.contacts.items()
        }

    # ------------------------------------------------------------------
    # Klucze własne
    # ------------------------------------------------------------------

    def _load_or_generate_private_key(self, passphrase: str | None) -> PrivateKey:
        if self.private_key_path.exists():
            with open(self.private_key_path, "rb") as f:
                data = f.read()
            return PrivateKey(keyfile.unseal(data, passphrase))

        key = PrivateKey.generate()
        raw = bytes(key)
        payload = keyfile.seal(raw, passphrase) if passphrase else raw
        keyfile.write_atomic(self.private_key_path, payload)
        return key

    def is_key_encrypted(self) -> bool:
        """Czy plik klucza prywatnego jest chroniony hasłem."""
        return keyfile.path_is_encrypted(self.private_key_path)

    def set_passphrase(self, passphrase: str) -> None:
        """Ustaw lub zmień hasło chroniące klucz prywatny na dysku.

        Działa też jako migracja pliku legacy — klucz jest już wczytany do
        pamięci, więc wystarczy zapisać go ponownie w kontenerze v1. Zapis jest
        atomowy, więc przerwanie operacji nie zniszczy tożsamości.
        """
        if not passphrase:
            raise ValueError("Hasło nie może być puste.")
        sealed = keyfile.seal(bytes(self.private_key), passphrase)
        keyfile.write_atomic(self.private_key_path, sealed)

    def remove_passphrase(self) -> None:
        """Zapisz klucz prywatny bez ochrony hasłem (powrót do formatu legacy).

        Świadomie obniża bezpieczeństwo — udostępnione tylko dla scenariuszy
        automatyzacji/headless, gdzie prompt o hasło jest niemożliwy.
        """
        keyfile.write_atomic(self.private_key_path, bytes(self.private_key))

    def export_public_key(self) -> str:
        return self.public_key.encode(encoder=Base64Encoder).decode()

    def my_pubkey_hash(self) -> str:
        """SHA-256 własnego klucza publicznego (base64) — ID skrzynki relay."""
        return hashlib.sha256(self.export_public_key().encode()).hexdigest()

    def my_fingerprint(self) -> str:
        """Fingerprint własnego klucza — do odczytania rozmówcy out-of-band."""
        return fingerprint_for_pubkey(self.export_public_key())

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
                    *,
                    allow_key_change: bool = False,
                    # legacy Telegram params — ignorowane jeśli relay_url ustawiony
                    telegram_bot_token: str = "",
                    telegram_chat_id:   str = "") -> None:
        """Dodaj lub zaktualizuj kontakt.

        :param allow_key_change: jeśli kontakt o tej nazwie już istnieje z
            **innym** kluczem publicznym, domyślnie podnosimy
            :class:`~hushbox_core.errors.KeyConflictError` zamiast po cichu
            nadpisać klucz. Ciche nadpisanie było wektorem MITM: złośliwe
            oprogramowanie lub przejęty relay mogły podstawić własny klucz przy
            "aktualizacji" kontaktu. Ustaw ``True`` tylko po świadomej decyzji
            użytkownika (np. rozmówca faktycznie przeinstalował aplikację).
            Zmiana klucza zawsze zeruje flagę ``verified``.
        """
        name = name.strip()
        if not name:
            raise ValueError("Nazwa kontaktu nie może być pusta.")
        _decode_pubkey(public_key_b64)  # walidacja
        existing = self.contacts.get(name)

        key_changed = existing is not None and existing.public_key != public_key_b64
        if key_changed and not allow_key_change:
            raise KeyConflictError(
                name,
                existing.fingerprint,
                fingerprint_for_pubkey(public_key_b64),
            )

        # Weryfikacja dotyczy konkretnego klucza — po zmianie klucza wygasa.
        verified = False if (existing is None or key_changed) else existing.verified

        self.contacts[name] = ContactInfo(
            public_key=         public_key_b64,
            relay_url=          relay_url or (existing.relay_url if existing else ""),
            verified=           verified,
            telegram_bot_token= telegram_bot_token or (existing.telegram_bot_token if existing else ""),
            telegram_chat_id=   telegram_chat_id   or (existing.telegram_chat_id   if existing else ""),
        )
        self._save_contacts()

    # ── TOFU / weryfikacja tożsamości ─────────────────────────────────

    def fingerprint(self, name: str) -> str:
        """Fingerprint klucza publicznego kontaktu (do pokazania w UI)."""
        return self.get_contact(name).fingerprint

    def is_verified(self, name: str) -> bool:
        return self.get_contact(name).verified

    def verify_contact(self, name: str, expected_fingerprint: str) -> None:
        """Potwierdź tożsamość kontaktu fingerprintem z kanału out-of-band.

        Użytkownik odczytuje fingerprint od rozmówcy innym kanałem (telefon,
        spotkanie, wideo) i wpisuje go tutaj. Zgodność oznaczamy trwale w
        ``contact_keys.json``.

        Porównanie idzie przez :func:`hmac.compare_digest` — fingerprint nie jest
        sekretem, ale stały czas porównania nic nie kosztuje i eliminuje pytania
        audytorów o wyciek przez timing.

        :raises FingerprintMismatch: gdy wartości się różnią.
        """
        contact = self.get_contact(name)
        expected = normalize_fingerprint(expected_fingerprint)
        actual   = normalize_fingerprint(contact.fingerprint)

        if not expected:
            raise ValueError("Fingerprint do weryfikacji nie może być pusty.")
        if not hmac.compare_digest(expected, actual):
            raise FingerprintMismatch(
                f"Fingerprint kontaktu '{name}' nie zgadza się. "
                "Nie wysyłaj wiadomości i skontaktuj się z rozmówcą innym kanałem."
            )

        contact.verified = True
        self._save_contacts()

    def unverify_contact(self, name: str) -> None:
        """Wycofaj potwierdzenie tożsamości kontaktu."""
        self.get_contact(name).verified = False
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

    @staticmethod
    def _decode_ciphertext(ciphertext: str) -> bytes:
        """Znormalizuj i zdekoduj base64 ciphertext.

        Tryb manualny (kopiuj-wklej przez e-mail/komunikator) regularnie dokłada
        białe znaki — również *wewnątrz* stringa, gdy klient pocztowy zawinie
        linie. Dlatego usuwamy wszystkie białe znaki, a nie tylko brzegowe, a
        następnie walidujemy base64 rygorystycznie (``validate=True``).

        Normalizacja jest bezpieczna: białe znaki nie należą do alfabetu base64,
        więc ich usunięcie nie może zmienić odkodowanej treści, a jakakolwiek
        realna korupcja transmisji zostanie i tak wyłapana przez Poly1305.
        """
        compact = "".join(ciphertext.split())
        if not compact:
            raise InvalidCiphertextFormat("Ciphertext jest pusty.")
        try:
            return base64.b64decode(compact, validate=True)
        except (binascii.Error, ValueError) as exc:
            raise InvalidCiphertextFormat(
                "Ciphertext nie jest poprawnym base64."
            ) from exc

    def decrypt(self, contact_name: str, ciphertext: str) -> str:
        """Odszyfruj wiadomość od kontaktu.

        :raises KeyError: nieznany kontakt (błąd programisty, nie danych).
        :raises DecryptionError: niepoprawny base64, zmanipulowany szyfrogram,
            wiadomość od innego nadawcy albo nie-UTF-8 plaintext. Warstwa UI
            powinna łapać wyłącznie ten typ i pokazać komunikat użytkownikowi.
        """
        box = self._get_box(contact_name)
        raw = self._decode_ciphertext(ciphertext)
        try:
            decrypted = box.decrypt(raw)
        except CryptoError as exc:
            raise DecryptionError(
                "Nie udało się odszyfrować wiadomości — szyfrogram został "
                "zmieniony albo nie pochodzi od tego kontaktu."
            ) from exc
        try:
            return decrypted.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise DecryptionError(
                "Odszyfrowana treść nie jest poprawnym tekstem UTF-8."
            ) from exc
