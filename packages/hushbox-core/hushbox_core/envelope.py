# SPDX-License-Identifier: Apache-2.0
"""Versioned message envelope (format v2).

Until 0.4.0 a message was a bare NaCl ``Box`` ciphertext in base64: no version,
no message ID and no timestamp, so a receiver could neither evolve the format
nor tell a replayed message from a new one. 0.5.0 introduced envelope v1;
0.6.0 replaces it with v2, which adds a content type. Only v2 is accepted:
bare 0.4.0 ciphertexts and v1 envelopes (0.5.0, never shipped in a client
release) are rejected.

Wire format (the whole thing is standard base64 for transport)::

    offset  len  field
    0       4    magic   = b"HBM1"   (format family; the version byte follows)
    4       1    version = 2
    5       ..   Box(nonce || ciphertext)   X25519 + XSalsa20-Poly1305

Plaintext inside the ``Box``::

    offset  len  field
    0       5    copy of the outer header (magic + version)
    5       1    content type (:class:`MessageType`)
    6       16   message ID (random, os.urandom)
    22      8    sender timestamp, milliseconds since the Unix epoch
                 (uint64 big-endian)
    30      ..   body, UTF-8

The content type tells the receiver what the body is before it interprets it,
so new kinds of messages (read receipts, group headers, key rotation notices)
need no guessing from the body, and an older client can reject a type it does
not know instead of showing it as text. It sits inside the ciphertext: the
relay must not learn which deliveries are, say, read receipts.

Values 1–127 are defined by hushbox-core (every client must handle or reject
them); 128–255 are free for application-specific content and opaque to the
core; 0 is invalid. Only core-defined types listed in :class:`MessageType`
and application types are accepted when opening; any other value raises
:class:`~hushbox_core.errors.UnsupportedMessageType`.

File packages (:attr:`MessageType.FILE_PACKAGE`) are stored objects rather
than messages: they are opened with :func:`open_envelope` but are not subject
to the replay register or the receive window, and the message path of
:class:`~hushbox_core.EncryptionManager` refuses them. The type binds that
distinction cryptographically, so a package cannot be passed off as a message
(and replayed without limits) or the other way round.

Why the header is repeated inside: NaCl ``Box`` has no associated data, so the
outer header is not authenticated by Poly1305. Repeating it inside the
ciphertext and comparing after decryption binds the version to the
authenticated content: a parser for one version cannot be fed a payload
sealed under another version without detection.

The message ID and the timestamp are inside the ciphertext, so the relay sees
neither. Only the 5-byte header is visible, which tells an observer that the
blob is a Hushbox message — the relay knows that anyway.

Replay protection (:class:`ReplayStore`) is local to the receiving device: a
message is accepted once per ``(sender, message ID)`` within the time window.
See :func:`check_freshness` for the window rules.
"""
from __future__ import annotations

import base64
import binascii
import hmac
import json
import os
import struct
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import IntEnum
from pathlib import Path
from typing import Callable, Collection, Protocol, runtime_checkable

from nacl.exceptions import CryptoError
from nacl.public import Box

from . import keyfile
from .errors import (
    DecryptionError,
    InvalidCiphertextFormat,
    MessageExpired,
    ReplayedMessage,
    ReplayStoreError,
    UnsupportedMessageFormat,
    UnexpectedMessageType,
    UnsupportedMessageType,
)

MAGIC = b"HBM1"
VERSION = 2
_HEADER = struct.Struct(">4sB")                 # magic, version
HEADER = _HEADER.pack(MAGIC, VERSION)
MESSAGE_ID_SIZE = 16
_INNER = struct.Struct(f">{_HEADER.size}sB{MESSAGE_ID_SIZE}sQ")
# Bytes the envelope adds around the body: outer header, nonce, Poly1305 tag
# and the inner header (header copy, type, message ID, timestamp).
OVERHEAD = _HEADER.size + Box.NONCE_SIZE + 16 + _INNER.size
_MIN_BOX_SIZE = Box.NONCE_SIZE + 16             # nonce + Poly1305 tag

# Receive window. A message older than MAX_MESSAGE_AGE, or dated more than
# MAX_CLOCK_SKEW in the future, is rejected. IDs are remembered for as long as
# a message with that timestamp would still be accepted, then pruned.
MAX_MESSAGE_AGE = 30 * 24 * 60 * 60.0           # seconds
MAX_CLOCK_SKEW = 10 * 60.0                      # seconds

APP_TYPE_MIN = 128                              # 128–255: application-specific

Clock = Callable[[], float]


class MessageType(IntEnum):
    """Content types defined by hushbox-core (1–127)."""

    TEXT = 1
    """UTF-8 text meant to be shown to the user."""

    FILE_DESCRIPTOR = 2
    """Announces a stored file package; the body is an application-defined
    reference (NULLGIS: JSON with an opaque ``object_ref``). A message."""

    FILE_PACKAGE = 3
    """An encrypted file package (``.hbx`` content, S3 object). A stored
    object, not a message: no replay register, no receive window."""


def _check_type(content_type: int) -> int:
    """Validate a content type value; return it as int (or MessageType)."""
    if not isinstance(content_type, int) or isinstance(content_type, bool):
        raise UnsupportedMessageType("Typ treści musi być liczbą całkowitą.")
    if content_type >= APP_TYPE_MIN and content_type <= 255:
        return content_type
    try:
        return MessageType(content_type)
    except ValueError:
        raise UnsupportedMessageType(
            f"Nieznany typ treści wiadomości ({content_type}). Zaktualizuj aplikację."
        ) from None


@dataclass(frozen=True)
class EncryptedMessage:
    """Result of sealing: the wire text plus what the sender may want to keep
    (for example to match a later read receipt)."""

    ciphertext: str
    message_id: str          # 32 lowercase hex characters
    timestamp_ms: int
    type: int = MessageType.TEXT


@dataclass(frozen=True)
class DecryptedMessage:
    """An authentic envelope. From the message path of
    :class:`~hushbox_core.EncryptionManager` it is also fresh and not seen
    before."""

    text: str
    message_id: str          # 32 lowercase hex characters
    timestamp_ms: int
    type: int = MessageType.TEXT
    """:class:`MessageType` for core types, plain ``int`` for 128–255."""

    @property
    def sent_at(self) -> datetime:
        """Sender's clock at sealing time, as an aware UTC datetime."""
        return datetime.fromtimestamp(self.timestamp_ms / 1000, tz=timezone.utc)


# ──────────────────────────────────────────────────────────────────
# Sealing / opening
# ──────────────────────────────────────────────────────────────────

def seal(
    box: Box,
    text: str,
    *,
    type: int = MessageType.TEXT,  # noqa: A002 - mirrors the wire field
    message_id: bytes | None = None,
    timestamp_ms: int | None = None,
    clock: Clock = time.time,
) -> EncryptedMessage:
    """Encrypt ``text`` into an envelope of the given content ``type``.

    ``message_id`` and ``timestamp_ms`` exist for tests and for re-sending the
    *same* logical message; normal callers leave them out.

    :raises UnsupportedMessageType: ``type`` is 0, outside 0–255 or an
        undefined core type.
    """
    content_type = _check_type(type)
    if message_id is None:
        message_id = os.urandom(MESSAGE_ID_SIZE)
    if len(message_id) != MESSAGE_ID_SIZE:
        raise ValueError(f"message_id must be {MESSAGE_ID_SIZE} bytes")
    if timestamp_ms is None:
        timestamp_ms = int(clock() * 1000)
    if timestamp_ms < 0:
        raise ValueError("timestamp_ms must not be negative")

    inner = _INNER.pack(HEADER, content_type, message_id, timestamp_ms)
    wire = HEADER + bytes(box.encrypt(inner + text.encode("utf-8")))
    return EncryptedMessage(
        ciphertext=base64.b64encode(wire).decode("ascii"),
        message_id=message_id.hex(),
        timestamp_ms=timestamp_ms,
        type=content_type,
    )


def decode_wire(ciphertext: str) -> bytes:
    """Strip whitespace and strictly decode base64.

    Manual copy-paste channels (e-mail, chat) add whitespace, also *inside* the
    string when lines get wrapped. Whitespace is not part of the base64
    alphabet, so removing it cannot change the decoded bytes; real corruption
    is still caught by Poly1305.
    """
    compact = "".join(ciphertext.split())
    if not compact:
        raise InvalidCiphertextFormat("Ciphertext jest pusty.")
    try:
        return base64.b64decode(compact, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise InvalidCiphertextFormat("Ciphertext nie jest poprawnym base64.") from exc


def open_envelope(
    box: Box,
    ciphertext: str,
    *,
    allowed_types: Collection[int] | None = None,
) -> DecryptedMessage:
    """Decrypt and parse an envelope. Does **not** check freshness or replay.

    :param allowed_types: if given, any other content type raises
        :class:`~hushbox_core.errors.UnexpectedMessageType` (checked after
        authentication, so it cannot be used to probe keys).
    :raises InvalidCiphertextFormat: not base64, no envelope header (for
        example a 0.4.0 ciphertext) or truncated.
    :raises UnsupportedMessageFormat: envelope of another format version.
    :raises UnsupportedMessageType: content type this version does not know.
    :raises UnexpectedMessageType: known type, but not one of ``allowed_types``.
    :raises DecryptionError: Poly1305 failure, wrong sender, header mismatch
        or a body that is not UTF-8.
    """
    raw = decode_wire(ciphertext)
    if raw[: len(MAGIC)] != MAGIC:
        raise InvalidCiphertextFormat(
            "Szyfrogram nie ma nagłówka koperty — pochodzi z wersji sprzed "
            "0.5.0 albo nie jest wiadomością Hushbox."
        )
    if len(raw) < _HEADER.size:
        raise InvalidCiphertextFormat("Szyfrogram jest obcięty.")
    _, version = _HEADER.unpack(raw[: _HEADER.size])
    if version > VERSION:
        raise UnsupportedMessageFormat(
            f"Wiadomość w formacie {version}; ta wersja hushbox-core obsługuje "
            f"tylko format {VERSION}. Zaktualizuj aplikację."
        )
    if version != VERSION:
        raise UnsupportedMessageFormat(
            f"Wiadomość w starszym formacie {version}; ta wersja hushbox-core "
            f"obsługuje tylko format {VERSION}. Nadawca musi zaktualizować aplikację."
        )
    if len(raw) < _HEADER.size + _MIN_BOX_SIZE:
        raise InvalidCiphertextFormat("Szyfrogram jest obcięty.")

    try:
        inner = box.decrypt(raw[_HEADER.size :])
    except CryptoError as exc:
        raise DecryptionError(
            "Nie udało się odszyfrować wiadomości — szyfrogram został "
            "zmieniony albo nie pochodzi od tego kontaktu."
        ) from exc

    if len(inner) < _INNER.size:
        raise DecryptionError("Odszyfrowana koperta jest niekompletna.")
    inner_header, content_type, message_id, timestamp_ms = _INNER.unpack(
        inner[: _INNER.size]
    )
    if not hmac.compare_digest(inner_header, raw[: _HEADER.size]):
        raise DecryptionError(
            "Nagłówek koperty nie zgadza się z zaszyfrowaną treścią."
        )
    content_type = _check_type(content_type)
    if allowed_types is not None and content_type not in allowed_types:
        raise UnexpectedMessageType(
            f"Nieoczekiwany typ treści ({content_type}) w tym miejscu."
        )
    try:
        text = inner[_INNER.size :].decode("utf-8")
    except UnicodeDecodeError as exc:
        raise DecryptionError(
            "Odszyfrowana treść nie jest poprawnym tekstem UTF-8."
        ) from exc
    return DecryptedMessage(text=text, message_id=message_id.hex(),
                            timestamp_ms=timestamp_ms, type=content_type)


def check_freshness(
    timestamp_ms: int,
    *,
    now: float,
    max_age: float = MAX_MESSAGE_AGE,
    max_skew: float = MAX_CLOCK_SKEW,
) -> None:
    """Reject messages outside the receive window.

    A message is accepted when ``now - max_age <= timestamp <= now + max_skew``
    (both ends inclusive).

    :raises MessageExpired: the timestamp is outside the window.
    """
    ts = timestamp_ms / 1000
    if ts < now - max_age:
        raise MessageExpired(
            "Wiadomość jest starsza niż dopuszczalne okno odbioru i została "
            "odrzucona."
        )
    if ts > now + max_skew:
        raise MessageExpired(
            "Wiadomość ma znacznik czasu z przyszłości — sprawdź zegar "
            "nadawcy i swój."
        )


def prune_cutoff_ms(now: float, accepted_timestamp_ms: int,
                    max_age: float = MAX_MESSAGE_AGE) -> int:
    """Oldest sender timestamp (ms) a replay register must still keep.

    Counted from the *earlier* of the local clock and the timestamp of the
    message being accepted. A receiver clock that runs ahead (say 20 days)
    would otherwise prune IDs that are still inside the real window, and
    once the clock is corrected those messages could be replayed. A message
    that passed :func:`check_freshness` is at most ``MAX_CLOCK_SKEW`` ahead of
    the local clock, so a sender clock cannot push the cutoff forward either.
    """
    return int((min(now, accepted_timestamp_ms / 1000) - max_age) * 1000)


# ──────────────────────────────────────────────────────────────────
# Replay store
# ──────────────────────────────────────────────────────────────────

@runtime_checkable
class ReplayStore(Protocol):
    """Remembers which ``(sender, message ID)`` pairs were already accepted.

    ``sender`` is an opaque string chosen by the caller;
    :class:`~hushbox_core.EncryptionManager` uses the sender's ``pubkey_hash``,
    so renaming a contact does not reset its history.

    Implementations must be safe to call from several threads. Whether they
    must also be safe across processes depends on how they are shared.
    """

    def contains(self, sender: str, message_id: str) -> bool:
        """Was this message already accepted?"""
        ...

    def add(self, sender: str, message_id: str, timestamp_ms: int) -> bool:
        """Record the message. Return ``False`` if it was already present
        (check and insert must be atomic)."""
        ...

    def prune(self, older_than_ms: int) -> None:
        """Forget messages whose *sender timestamp* is below ``older_than_ms``.
        They would be rejected as expired anyway."""
        ...


def _key(sender: str, message_id: str) -> str:
    return f"{sender}:{message_id}"


class MemoryReplayStore:
    """In-process store. Forgets everything on restart — fine for tests and
    short-lived tools, not for a desktop client."""

    def __init__(self) -> None:
        self._seen: dict[str, int] = {}
        self._lock = threading.Lock()

    def contains(self, sender: str, message_id: str) -> bool:
        with self._lock:
            return _key(sender, message_id) in self._seen

    def add(self, sender: str, message_id: str, timestamp_ms: int) -> bool:
        key = _key(sender, message_id)
        with self._lock:
            if key in self._seen:
                return False
            self._seen[key] = timestamp_ms
            return True

    def prune(self, older_than_ms: int) -> None:
        with self._lock:
            self._seen = {k: t for k, t in self._seen.items() if t >= older_than_ms}

    def __len__(self) -> int:
        with self._lock:
            return len(self._seen)


class JsonFileReplayStore(MemoryReplayStore):
    """Store persisted as a JSON file, rewritten atomically on every change.

    A reference implementation for :class:`~hushbox_core.EncryptionManager`.

    **One process per file.** The register lives in memory and the whole
    file is rewritten on every change, so two processes using the same file
    (say an application and a command-line tool on one data directory)
    overwrite each other's entries, and the lost IDs can be replayed. Share a
    register between processes through a :class:`ReplayStore` backed by a
    database instead.
    Every accepted message rewrites the whole file, which is fine for the
    message volume of one person but not for a server; applications with a
    database should implement :class:`ReplayStore` on top of it, ideally in
    the same transaction that stores the message.

    The file holds message IDs, sender key hashes and timestamps — metadata,
    not content. It is written with owner-only permissions.

    File format::

        {"version": 1, "seen": {"<sender>:<message id>": <timestamp ms>, ...}}

    A corrupted or unreadable file raises :class:`ReplayStoreError` instead of
    silently starting empty, because an empty store would accept replays.
    """

    FORMAT_VERSION = 1

    def __init__(self, path: str | os.PathLike[str]) -> None:
        super().__init__()
        self.path = Path(path)
        self._seen = self._load()

    def _load(self) -> dict[str, int]:
        if not self.path.exists():
            return {}
        try:
            with open(self.path, "r", encoding="utf-8") as f:
                data = json.load(f)
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ReplayStoreError(
                f"Nie można wczytać rejestru odebranych wiadomości ({self.path})."
            ) from exc
        if (
            not isinstance(data, dict)
            or data.get("version") != self.FORMAT_VERSION
            or not isinstance(data.get("seen"), dict)
            or not all(
                isinstance(k, str) and isinstance(v, int) and not isinstance(v, bool)
                for k, v in data["seen"].items()
            )
        ):
            raise ReplayStoreError(
                f"Rejestr odebranych wiadomości ma nieobsługiwany format ({self.path})."
            )
        return dict(data["seen"])

    def _save(self) -> None:
        payload = json.dumps(
            {"version": self.FORMAT_VERSION, "seen": self._seen},
            separators=(",", ":"),
        ).encode("utf-8")
        keyfile.write_atomic(self.path, payload)

    def add(self, sender: str, message_id: str, timestamp_ms: int) -> bool:
        key = _key(sender, message_id)
        with self._lock:
            if key in self._seen:
                return False
            self._seen[key] = timestamp_ms
            try:
                self._save()
            except BaseException:
                # Keep memory and disk in agreement: an unsaved entry would be
                # forgotten on restart, so do not pretend it was recorded.
                del self._seen[key]
                raise
            return True

    def prune(self, older_than_ms: int) -> None:
        with self._lock:
            kept = {k: t for k, t in self._seen.items() if t >= older_than_ms}
            if len(kept) == len(self._seen):
                return
            previous, self._seen = self._seen, kept
            try:
                self._save()
            except BaseException:
                self._seen = previous
                raise
