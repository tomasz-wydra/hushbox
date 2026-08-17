"""Format pliku klucza prywatnego — wersjonowany, opcjonalnie chroniony hasłem.

Historycznie ``my_private_key.bin`` przechowywał 32 surowe bajty klucza NaCl bez
żadnej ochrony. Ten moduł wprowadza wersjonowany format kontenera, zachowując
pełną kompatybilność wstecz: pliki bez nagłówka są nadal czytane jako legacy.

Format v1 (chroniony hasłem)::

    offset  len  pole
    0       4    magic  = b"HBK1"
    4       1    wersja = 1
    5       4    opslimit (uint32 big-endian)
    9       4    memlimit (uint32 big-endian)
    13      16   salt Argon2id
    29      ..   SecretBox(nonce || ciphertext) — XSalsa20-Poly1305

Klucz szyfrujący jest wyprowadzany przez Argon2id (``nacl.pwhash.argon2id``).
Parametry KDF są zapisane w nagłówku, więc podniesienie ich w przyszłości nie
unieważni istniejących plików.

Uwaga: format *nie* zawiera nazwy użytkownika ani żadnych metadanych — plik jest
nieodróżnialny od losowych bajtów poza 5-bajtowym nagłówkiem.
"""
from __future__ import annotations

import os
import struct
import tempfile
from pathlib import Path

from nacl.exceptions import CryptoError
from nacl.pwhash import argon2id
from nacl.secret import SecretBox

from .errors import (
    InvalidPassphrase,
    KeyStoreError,
    PassphraseRequired,
    UnsupportedKeyFormat,
)

MAGIC = b"HBK1"
VERSION = 1
_HEADER = struct.Struct(">4sBII")          # magic, wersja, opslimit, memlimit
_HEADER_LEN = _HEADER.size + argon2id.SALTBYTES
RAW_KEY_SIZE = 32

# Parametry domyślne — MODERATE to ~256 MiB / 3 iteracje. Rozsądny kompromis dla
# aplikacji desktopowej; INTERACTIVE byłby zbyt słaby dla klucza tożsamości.
DEFAULT_OPSLIMIT = argon2id.OPSLIMIT_MODERATE
DEFAULT_MEMLIMIT = argon2id.MEMLIMIT_MODERATE


def is_encrypted(data: bytes) -> bool:
    """Czy bufor to kontener chroniony hasłem (a nie legacy raw key)."""
    return data[: len(MAGIC)] == MAGIC


def path_is_encrypted(path: str | os.PathLike[str]) -> bool:
    """Sprawdź *bez* podawania hasła, czy plik klucza wymaga hasła.

    Pozwala warstwie UI zdecydować, czy pokazać prompt o hasło, jeszcze przed
    konstrukcją :class:`~hushbox_core.EncryptionManager`.
    """
    p = Path(path)
    if not p.exists():
        return False
    with open(p, "rb") as f:
        return is_encrypted(f.read(len(MAGIC)))


def _derive(passphrase: str, salt: bytes, opslimit: int, memlimit: int) -> bytes:
    return argon2id.kdf(
        SecretBox.KEY_SIZE,
        passphrase.encode("utf-8"),
        salt,
        opslimit=opslimit,
        memlimit=memlimit,
    )


def seal(
    raw_key: bytes,
    passphrase: str,
    *,
    opslimit: int = DEFAULT_OPSLIMIT,
    memlimit: int = DEFAULT_MEMLIMIT,
) -> bytes:
    """Zaszyfruj surowy klucz prywatny hasłem, zwróć kontener v1."""
    if len(raw_key) != RAW_KEY_SIZE:
        raise KeyStoreError(f"Klucz prywatny musi mieć {RAW_KEY_SIZE} bajtów.")
    if not passphrase:
        raise KeyStoreError("Hasło nie może być puste.")

    salt = os.urandom(argon2id.SALTBYTES)
    derived = _derive(passphrase, salt, opslimit, memlimit)
    blob = SecretBox(derived).encrypt(raw_key)
    return _HEADER.pack(MAGIC, VERSION, opslimit, memlimit) + salt + bytes(blob)


def unseal(data: bytes, passphrase: str | None) -> bytes:
    """Wyciągnij surowy klucz prywatny z kontenera lub pliku legacy.

    Pliki legacy (bez nagłówka) są zwracane bez zmian — dzięki temu istniejące
    instalacje działają dalej bez migracji.
    """
    if not is_encrypted(data):
        if len(data) != RAW_KEY_SIZE:
            raise KeyStoreError(
                f"Nieprawidłowy plik klucza legacy — oczekiwano {RAW_KEY_SIZE} "
                f"bajtów, otrzymano {len(data)}."
            )
        return data

    if len(data) < _HEADER_LEN:
        raise KeyStoreError("Plik klucza jest obcięty.")

    _, version, opslimit, memlimit = _HEADER.unpack(data[: _HEADER.size])
    if version != VERSION:
        raise UnsupportedKeyFormat(
            f"Plik klucza w wersji {version}; ta wersja hushbox-core obsługuje "
            f"tylko wersję {VERSION}. Zaktualizuj aplikację."
        )

    if passphrase is None:
        raise PassphraseRequired(
            "Plik klucza prywatnego jest chroniony hasłem — podaj hasło."
        )

    salt = data[_HEADER.size : _HEADER_LEN]
    blob = data[_HEADER_LEN:]
    derived = _derive(passphrase, salt, opslimit, memlimit)
    try:
        return SecretBox(derived).decrypt(blob)
    except CryptoError as exc:
        # Nie różnicujemy "złe hasło" od "uszkodzony plik" — oba wyglądają
        # identycznie dla Poly1305 i różnicowanie nie daje nic użytkownikowi.
        raise InvalidPassphrase("Nieprawidłowe hasło do klucza prywatnego.") from exc


def write_atomic(path: str | os.PathLike[str], data: bytes) -> None:
    """Zapisz plik klucza atomowo, z uprawnieniami 0600.

    Zapis przez plik tymczasowy + ``os.replace`` gwarantuje, że przerwana
    operacja (np. brak miejsca, kill procesu) nie zostawi uszkodzonego klucza
    tożsamości. ``fsync`` przed podmianą wymusza trwałość na dysku.
    """
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)

    fd, tmp = tempfile.mkstemp(dir=str(p.parent), prefix=".hbkey-", suffix=".tmp")
    try:
        os.chmod(tmp, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, p)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise

    # os.replace zachowuje uprawnienia pliku tymczasowego, ale na wypadek
    # istniejącego pliku o luźniejszych prawach ustawiamy je jeszcze raz.
    try:
        os.chmod(p, 0o600)
    except OSError:
        # Windows / egzotyczne systemy plików — brak POSIX-owych uprawnień.
        pass
