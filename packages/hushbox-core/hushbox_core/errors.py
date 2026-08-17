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
    """Ciphertext nie jest poprawnym base64."""
