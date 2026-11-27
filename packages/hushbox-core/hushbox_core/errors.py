# SPDX-License-Identifier: Apache-2.0
"""Wyjątki domenowe hushbox-core.

Warstwa UI powinna łapać wyłącznie te wyjątki i nigdy nie eksponować
wewnętrznych śladów stosu PyNaCl użytkownikowi. Każdy wyjątek kryptograficzny
z ``nacl`` jest tłumaczony na jeden z poniższych typów.
"""
from __future__ import annotations


class HushboxError(Exception):
    """Wspólna baza dla wszystkich błędów hushbox-core."""


# ── klucz prywatny / passphrase ────────────────────────────────────

class KeyStoreError(HushboxError):
    """Problem z plikiem klucza prywatnego na dysku."""


class PassphraseRequired(KeyStoreError):
    """Plik klucza jest zaszyfrowany, ale nie podano hasła."""


class InvalidPassphrase(KeyStoreError):
    """Podane hasło nie odszyfrowuje pliku klucza."""


class UnsupportedKeyFormat(KeyStoreError):
    """Nagłówek pliku klucza pochodzi z nowszej, nieobsługiwanej wersji."""


# ── kontakty / tożsamość ──────────────────────────────────────────

class ContactError(HushboxError):
    """Problem z kontaktem lub jego kluczem publicznym."""


class KeyConflictError(ContactError):
    """Kontakt już istnieje z *innym* kluczem publicznym.

    Sygnalizuje potencjalne podmienienie klucza (MITM). Wywołujący musi
    świadomie zdecydować o nadpisaniu przez ``allow_key_change=True``.
    """

    def __init__(self, name: str, old_fingerprint: str, new_fingerprint: str):
        self.name = name
        self.old_fingerprint = old_fingerprint
        self.new_fingerprint = new_fingerprint
        super().__init__(
            f"Kontakt '{name}' ma już inny klucz publiczny "
            f"(zapisany: {old_fingerprint}, nowy: {new_fingerprint})."
        )


class FingerprintMismatch(ContactError):
    """Fingerprint podany do weryfikacji nie zgadza się z zapisanym kluczem."""


# ── szyfrowanie / deszyfrowanie ───────────────────────────────────

class DecryptionError(HushboxError):
    """Nie udało się odszyfrować wiadomości.

    Obejmuje zarówno niepoprawny base64, jak i nieudaną weryfikację
    Poly1305 (wiadomość zmanipulowana lub zaszyfrowana dla kogoś innego).
    Komunikat jest celowo ogólny — nie ujawniamy, *który* etap zawiódł.
    """


class InvalidCiphertextFormat(DecryptionError):
    """Ciphertext is not valid base64, has no envelope header (for example a
    pre-0.5.0 message) or is truncated."""


class UnsupportedMessageFormat(DecryptionError):
    """The envelope uses a format version this release does not accept."""


class UnsupportedMessageType(UnsupportedMessageFormat):
    """The envelope's content type is not defined in this release (for
    example a message type added by a newer client)."""


class UnexpectedMessageType(DecryptionError):
    """A known content type in the wrong place, for example a file package
    passed to the message path or a file descriptor to ``decrypt()``."""


class MessageExpired(DecryptionError):
    """The message timestamp is outside the receive window (too old, or too
    far in the future)."""


class ReplayedMessage(DecryptionError):
    """This message (same sender and message ID) was already accepted."""


# ── signatures ────────────────────────────────────────────────────

class SignatureError(HushboxError):
    """A signature or signing key is invalid or does not verify."""


# ── QR codes ──────────────────────────────────────────────────────

class QrPayloadError(HushboxError):
    """A scanned QR code cannot be used."""


class InvalidQrPayload(QrPayloadError):
    """Not a Hushbox QR code, or its fields are malformed."""


class UnsupportedQrPayload(QrPayloadError):
    """A Hushbox QR code of a newer version or an unsupported type."""


# ── local state ───────────────────────────────────────────────────

class ReplayStoreError(HushboxError):
    """The local register of received messages cannot be read or written."""
