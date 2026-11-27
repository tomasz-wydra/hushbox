# SPDX-License-Identifier: Apache-2.0
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

Message format: every message is a versioned envelope with a message ID and a
sender timestamp inside the ciphertext (see :mod:`hushbox_core.envelope`).
``decrypt`` accepts a message once per sender and message ID, within the
receive window; seen IDs are kept in ``seen_messages.json`` next to the key
unless another :class:`~hushbox_core.envelope.ReplayStore` is passed in.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import time
from dataclasses import dataclass
from pathlib import Path

from nacl.encoding import Base64Encoder
from nacl.public import Box, PrivateKey, PublicKey

from . import envelope, keyfile
from .envelope import (
    MAX_CLOCK_SKEW,
    MAX_MESSAGE_AGE,
    Clock,
    DecryptedMessage,
    EncryptedMessage,
    JsonFileReplayStore,
    ReplayStore,
)
from .errors import (
    FingerprintMismatch,
    KeyConflictError,
    ReplayedMessage,
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
                 passphrase: str | None = None,
                 *,
                 replay_store: ReplayStore | None = None,
                 max_message_age: float = MAX_MESSAGE_AGE,
                 max_clock_skew: float = MAX_CLOCK_SKEW,
                 clock: Clock = time.time):
        """
        :param data_dir: katalog na klucz prywatny i kontakty.
        :param passphrase: hasło do klucza prywatnego. Wymagane tylko wtedy, gdy
            plik klucza jest chroniony hasłem — sprawdź to bez hasła przez
            :func:`hushbox_core.keyfile.path_is_encrypted`. Jeśli podane przy
            pierwszym uruchomieniu, nowo wygenerowany klucz zostanie od razu
            zapisany w formie zaszyfrowanej.
        :param replay_store: register of accepted message IDs. Defaults to
            :class:`~hushbox_core.envelope.JsonFileReplayStore` in
            ``data_dir/seen_messages.json``.
        :param max_message_age: reject messages older than this (seconds).
        :param max_clock_skew: reject messages dated further than this in the
            future (seconds).
        :param clock: time source in seconds since the epoch (for tests).
        """
        self.data_dir = Path(data_dir)
        self.data_dir.mkdir(parents=True, exist_ok=True)

        self.private_key_path  = self.data_dir / "my_private_key.bin"
        self.contact_keys_path = self.data_dir / "contact_keys.json"

        if max_message_age <= 0 or max_clock_skew < 0:
            raise ValueError("max_message_age must be > 0 and max_clock_skew >= 0")
        self.max_message_age = max_message_age
        self.max_clock_skew = max_clock_skew
        self._clock = clock
        self.replay_store: ReplayStore = (
            replay_store if replay_store is not None
            else JsonFileReplayStore(self.data_dir / "seen_messages.json")
        )

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
        """Encrypt a message for a contact; returns the base64 envelope."""
        return self.encrypt_message(contact_name, plaintext).ciphertext

    def encrypt_message(self, contact_name: str, plaintext: str) -> EncryptedMessage:
        """Like :meth:`encrypt`, but also returns the message ID and timestamp."""
        box = self._get_box(contact_name)
        return envelope.seal(box, plaintext, clock=self._clock)

    def decrypt(self, contact_name: str, ciphertext: str) -> str:
        """Odszyfruj wiadomość od kontaktu i zapamiętaj ją jako odebraną.

        :raises KeyError: nieznany kontakt (błąd programisty, nie danych).
        :raises DecryptionError: niepoprawny base64 lub brak nagłówka koperty
            (``InvalidCiphertextFormat``), nowszy format
            (``UnsupportedMessageFormat``), zmanipulowany szyfrogram lub inny
            nadawca, wiadomość spoza okna czasu (``MessageExpired``) albo już
            odebrana (``ReplayedMessage``). Warstwa UI może łapać wyłącznie
            ten typ bazowy.
        """
        return self.decrypt_message(contact_name, ciphertext).text

    def decrypt_message(self, contact_name: str, ciphertext: str,
                        *, record: bool = True) -> DecryptedMessage:
        """Decrypt, check freshness and replay; return the message with its
        ID and timestamp.

        :param record: with ``True`` (default) the message is recorded in the
            replay store before it is returned, atomically with the replay
            check. With ``False`` it is only checked; the caller must call
            :meth:`mark_seen` once the message is safely stored, so a failure
            in between does not lose it (the relay delivers it again). The
            caller is then responsible for not processing the same message
            twice concurrently.
        :raises DecryptionError: see :meth:`decrypt`.
        """
        box = self._get_box(contact_name)
        sender = self.contacts[contact_name].pubkey_hash
        message = envelope.open_envelope(box, ciphertext)

        now = self._clock()
        envelope.check_freshness(
            message.timestamp_ms, now=now,
            max_age=self.max_message_age, max_skew=self.max_clock_skew,
        )
        if record:
            self.replay_store.prune(int((now - self.max_message_age) * 1000))
            if not self.replay_store.add(sender, message.message_id,
                                         message.timestamp_ms):
                raise self._replayed()
        elif self.replay_store.contains(sender, message.message_id):
            raise self._replayed()
        return message

    def mark_seen(self, contact_name: str, message: DecryptedMessage) -> None:
        """Record a message obtained with ``decrypt_message(record=False)``.

        :raises ReplayedMessage: the message was recorded in the meantime.
        """
        sender = self.get_contact(contact_name).pubkey_hash
        if not self.replay_store.add(sender, message.message_id,
                                     message.timestamp_ms):
            raise self._replayed()

    @staticmethod
    def _replayed() -> ReplayedMessage:
        return ReplayedMessage(
            "Ta wiadomość została już odebrana — odrzucono powtórzenie."
        )
