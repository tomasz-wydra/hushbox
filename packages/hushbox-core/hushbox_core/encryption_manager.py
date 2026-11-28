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

Message format: every message is a versioned envelope with a content type,
the sender's public key, a message ID and a sender timestamp inside the
ciphertext (see :mod:`hushbox_core.envelope`). Opening checks that the sender
key is the contact's, so our own message reflected back is rejected. ``decrypt``/``decrypt_message`` accept a
message once per sender and message ID, within the receive window; seen IDs
are kept in ``seen_messages.json`` next to the key unless another
:class:`~hushbox_core.envelope.ReplayStore` is passed in. File packages go
through :meth:`EncryptionManager.open_package` instead, without those checks.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Collection

from nacl.encoding import Base64Encoder
from nacl.public import PrivateKey, PublicKey

from . import envelope, keyfile, keys, signing
from .envelope import (
    MAX_CLOCK_SKEW,
    MAX_MESSAGE_AGE,
    Clock,
    DecryptedMessage,
    EncryptedMessage,
    MessageType,
    JsonFileReplayStore,
    ReplayStore,
)
from .errors import (
    FingerprintMismatch,
    KeyConflictError,
    ReplayedMessage,
    UnexpectedMessageType,
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

    @property
    def pubkey_hash(self) -> str:
        """SHA-256 klucza publicznego (base64) — identyfikator w relay.

        Hashowany jest kanoniczny string base64, NIE surowe bajty
        (:func:`hushbox_core.keys.mailbox_id`). Patrz docstring modułu.
        """
        return keys.mailbox_id(self.public_key)

    @property
    def fingerprint(self) -> str:
        """SHA-256 surowych bajtów klucza — do weryfikacji przez człowieka."""
        return fingerprint_for_pubkey(self.public_key)

    def to_dict(self) -> dict:
        return {
            "public_key": self.public_key,
            "relay_url":  self.relay_url,
            "verified":   self.verified,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "ContactInfo":
        # obsługa starego formatu (plain string zamiast dict)
        # Klucze zapisane przez starsze wersje (np. z końcem linii) dostają
        # kanoniczną pisownię, żeby identyfikator skrzynki był poprawny.
        if isinstance(d, str):
            return cls(public_key=keys.repair_public_key(d))
        # Unknown keys (e.g. the removed Telegram fields) are ignored and
        # dropped on the next save.
        return cls(
            public_key= keys.repair_public_key(d.get("public_key", "")),
            relay_url=  d.get("relay_url",  ""),
            # Kontakty z wersji przed TOFU są traktowane jako NIEzweryfikowane.
            verified=   bool(d.get("verified", False)),
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
        :param data_dir: katalog na klucz prywatny i kontakty. Only one
            process may use a data directory at a time: contacts and the
            default replay register are kept in memory and rewritten as whole
            files, so a second process would overwrite the first one's
            changes (lost contacts, replayable messages).
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
        # Ed25519 key derived from the X25519 key (hushbox_core.signing).
        self.signing_key = signing.derive_signing_key(self.private_key)
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

    def export_signing_public_key(self) -> str:
        """Base64 of the Ed25519 public key derived from this identity."""
        return signing.encode_verify_key(self.signing_key.verify_key)

    def sign(self, context: str, message: bytes) -> bytes:
        """Detached Ed25519 signature bound to ``context``
        (see :mod:`hushbox_core.signing`)."""
        return signing.sign(self.signing_key, context, message)

    def my_pubkey_hash(self) -> str:
        """SHA-256 własnego klucza publicznego (base64) — ID skrzynki relay."""
        return keys.mailbox_id(self.export_public_key())

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
        # Atomic (temp file + replace): a crash or a full disk mid-write must
        # not leave an empty or truncated contact list behind.
        keyfile.write_atomic(
            self.contact_keys_path,
            json.dumps(data, indent=2, ensure_ascii=False).encode("utf-8"),
        )
        # sync kompatybilny słownik
        self.contact_keys = {n: c.public_key for n, c in self.contacts.items()}

    def add_contact(self, name: str, public_key_b64: str,
                    relay_url: str = "",
                    *,
                    allow_key_change: bool = False) -> None:
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
        # Ścisła walidacja i kanoniczna pisownia: biały znak z kopiuj-wklej
        # jest usuwany, inne śmieci odrzucane. Bez tego klucz z końcem linii
        # trafiał do innej skrzynki relaya (audyt 0.9.1, ustalenie 2).
        public_key_b64 = keys.canonical_public_key(public_key_b64)
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
            public_key= public_key_b64,
            relay_url=  relay_url or (existing.relay_url if existing else ""),
            verified=   verified,
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
        # Porównanie bajtów: compare_digest na str spoza ASCII (literówka „ó”,
        # myślnik typograficzny) rzuca TypeError zamiast zwykłej niezgodności
        # (audyt 0.9.1, ustalenie 8).
        if not hmac.compare_digest(expected.encode("utf-8"), actual.encode("utf-8")):
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
        if new_name == old_name:
            return
        if new_name in self.contacts:
            # Nadpisanie skasowałoby klucz i weryfikację tamtego kontaktu, a pod
            # jego nazwą zostałby cudzy klucz (audyt 0.9.1, ustalenie 3).
            raise ValueError(f"Kontakt '{new_name}' już istnieje.")
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

    def _contact_key(self, contact_name: str) -> PublicKey:
        if contact_name not in self.contacts:
            raise KeyError(f"Brak klucza publicznego dla kontaktu '{contact_name}'.")
        return PublicKey(
            self.contacts[contact_name].public_key.encode(),
            encoder=Base64Encoder,
        )

    def encrypt(self, contact_name: str, plaintext: str,
                *, type: int = MessageType.TEXT) -> str:  # noqa: A002
        """Encrypt for a contact; returns the base64 envelope.

        :param type: content type (:class:`~hushbox_core.envelope.MessageType`
            or an application type 128–255). Defaults to text.
        """
        return self.encrypt_message(contact_name, plaintext, type=type).ciphertext

    def encrypt_message(self, contact_name: str, plaintext: str,
                        *, type: int = MessageType.TEXT) -> EncryptedMessage:  # noqa: A002
        """Like :meth:`encrypt`, but also returns the message ID and timestamp."""
        return envelope.seal(
            self.private_key, self._contact_key(contact_name), plaintext,
            type=type, clock=self._clock,
        )

    def open_package(self, contact_name: str, ciphertext: str) -> str:
        """Open a file package (:attr:`MessageType.FILE_PACKAGE`).

        A package is a stored object, not a message: it may be opened any
        number of times and at any age, so neither the replay register nor
        the receive window applies. Any other content type is refused.

        :raises UnexpectedMessageType: the envelope is not a file package.
        :raises DecryptionError: see :meth:`decrypt`.
        """
        return envelope.open_envelope(
            self.private_key, self._contact_key(contact_name), ciphertext,
            allowed_types=(MessageType.FILE_PACKAGE,),
        ).text

    def decrypt(self, contact_name: str, ciphertext: str) -> str:
        """Odszyfruj wiadomość tekstową od kontaktu i zapamiętaj ją jako odebraną.

        Accepts only :attr:`MessageType.TEXT`; other types raise
        ``UnexpectedMessageType``. Use :meth:`decrypt_message` to receive other
        message types and :meth:`open_package` for file packages.

        :raises KeyError: nieznany kontakt (błąd programisty, nie danych).
        :raises DecryptionError: niepoprawny base64 lub brak nagłówka koperty
            (``InvalidCiphertextFormat``), nowszy format
            (``UnsupportedMessageFormat``), zmanipulowany szyfrogram lub inny
            nadawca (także nasza własna wiadomość odbita z powrotem), wiadomość spoza okna czasu (``MessageExpired``) albo już
            odebrana (``ReplayedMessage``). Warstwa UI może łapać wyłącznie
            ten typ bazowy.
        """
        return self.decrypt_message(
            contact_name, ciphertext, types=(MessageType.TEXT,)
        ).text

    def decrypt_message(self, contact_name: str, ciphertext: str,
                        *, record: bool = True,
                        types: Collection[int] | None = None) -> DecryptedMessage:
        """Decrypt, check freshness and replay; return the message with its
        type, ID and timestamp.

        :param types: accepted content types. ``None`` accepts every message
            type; :attr:`MessageType.FILE_PACKAGE` is always refused here
            (packages are not messages, see :meth:`open_package`). Rejected
            types raise ``UnexpectedMessageType`` before anything is recorded.
        :param record: with ``True`` (default) the message is recorded in the
            replay store before it is returned, atomically with the replay
            check. With ``False`` it is only checked; the caller must call
            :meth:`mark_seen` once the message is safely stored, so a failure
            in between does not lose it (the relay delivers it again). The
            caller is then responsible for not processing the same message
            twice concurrently.
        :raises DecryptionError: see :meth:`decrypt`.
        """
        sender_key = self._contact_key(contact_name)
        sender = self.contacts[contact_name].pubkey_hash
        message = envelope.open_envelope(
            self.private_key, sender_key, ciphertext, allowed_types=types,
        )
        if message.type == MessageType.FILE_PACKAGE:
            raise UnexpectedMessageType(
                "Pakiet pliku nie jest wiadomością — otwórz go jako plik."
            )

        now = self._clock()
        envelope.check_freshness(
            message.timestamp_ms, now=now,
            max_age=self.max_message_age, max_skew=self.max_clock_skew,
        )
        if record:
            self.replay_store.prune(
                envelope.prune_cutoff_ms(now, message.timestamp_ms, self.max_message_age)
            )
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
