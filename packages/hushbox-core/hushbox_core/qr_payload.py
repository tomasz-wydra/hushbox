# SPDX-License-Identifier: Apache-2.0
"""Versioned content of Hushbox QR codes (format v1).

A QR code carries compact JSON with a format version and a content type, so a
scanner can tell what it is looking at and refuse what it does not understand
instead of guessing::

    {"v": 1, "type": "contact", "public_key": "<base64 X25519>", "relay_url": "https://..."}

Fields:

* ``v`` (int, required): format version. Only ``1`` is accepted.
* ``type`` (str, required): content type. ``"contact"`` is defined;
  ``"invite"`` and ``"message"`` are reserved for organisation invitations and
  messages in a QR code and are rejected until they are specified.
* ``public_key`` (str, required for ``contact``): the contact's public key,
  standard base64 of 32 bytes.
* ``relay_url`` (str, optional for ``contact``): the relay on which the
  contact receives messages, ``http`` or ``https``, without credentials.

Unknown *fields* are ignored, so a later v1 revision can add optional fields
without breaking older scanners; anything that changes the meaning of existing
fields needs a new ``v``. The pre-0.7.0 payload (``{"public_key": ...}``
without ``v``) is not accepted.

Security: the payload is neither encrypted nor signed. Anyone who sees the
code learns the public key and the relay address, and anyone who can swap the
printed or displayed code can substitute a key. Identity still rests on the
out-of-band fingerprint check (see :func:`hushbox_core.fingerprint_for_pubkey`);
a scanner must treat the result like a manually entered key, unverified.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from urllib.parse import urlsplit

from . import keys
from .encryption_manager import fingerprint_for_pubkey
from .errors import InvalidQrPayload, UnsupportedQrPayload

VERSION = 1
TYPE_CONTACT = "contact"
# Reserved: named so a scanner can say "not supported yet" rather than
# "not a Hushbox code". Not accepted until they are specified.
RESERVED_TYPES = frozenset({"invite", "message"})

# Largest QR code (version 40, level L) holds 2953 bytes in byte mode; nothing
# longer can come from a real code, so parse() refuses it before json.loads.
MAX_PAYLOAD_CHARS = 2953
MAX_RELAY_URL_CHARS = 2048


@dataclass(frozen=True)
class ContactCard:
    """A contact read from (or written to) a QR code."""

    public_key: str
    relay_url: str = ""

    @property
    def fingerprint(self) -> str:
        """Fingerprint to compare out of band before trusting the key."""
        return fingerprint_for_pubkey(self.public_key)


def _check_public_key(value: object) -> str:
    if not isinstance(value, str) or not value:
        raise InvalidQrPayload("Kod QR nie zawiera klucza publicznego.")
    # Strict: only the canonical spelling, no whitespace (keys.py).
    if not keys.is_canonical_public_key(value):
        raise InvalidQrPayload("Klucz publiczny w kodzie QR jest nieprawidłowy.")
    return value


def _check_relay_url(value: object) -> str:
    if value is None:
        return ""
    if not isinstance(value, str):
        raise InvalidQrPayload("Adres relaya w kodzie QR jest nieprawidłowy.")
    url = value.strip()
    if not url:
        return ""
    if (
        len(url) > MAX_RELAY_URL_CHARS
        or any(ch.isspace() or ord(ch) < 0x20 for ch in url)
    ):
        raise InvalidQrPayload("Adres relaya w kodzie QR jest nieprawidłowy.")
    try:
        parts = urlsplit(url)
        _ = parts.port  # raises ValueError for a malformed port
    except ValueError as exc:
        raise InvalidQrPayload("Adres relaya w kodzie QR jest nieprawidłowy.") from exc
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise InvalidQrPayload("Adres relaya w kodzie QR musi zaczynać się od http(s)://.")
    if parts.username is not None or parts.password is not None:
        # Credentials in a QR code would leak to anyone who sees it.
        raise InvalidQrPayload("Adres relaya w kodzie QR nie może zawierać loginu ani hasła.")
    return url


def contact_payload(public_key: str, relay_url: str = "") -> str:
    """Build the QR text for a contact card.

    The output is compact JSON; ``relay_url`` is left out when empty.

    :raises InvalidQrPayload: invalid key or relay URL (the same rules as
        :func:`parse`, so a generated code always scans back).
    """
    payload: dict[str, object] = {
        "v": VERSION,
        "type": TYPE_CONTACT,
        "public_key": _check_public_key(public_key),
    }
    url = _check_relay_url(relay_url)
    if url:
        payload["relay_url"] = url
    text = json.dumps(payload, separators=(",", ":"), ensure_ascii=True)
    if len(text) > MAX_PAYLOAD_CHARS:
        raise InvalidQrPayload("Treść kodu QR jest za długa.")
    return text


def parse(text: str) -> ContactCard:
    """Parse and validate scanned QR text.

    :raises InvalidQrPayload: not a Hushbox QR code, or malformed fields.
    :raises UnsupportedQrPayload: a Hushbox code of a newer version or of a
        type this release does not handle (including the reserved types).
    """
    if not isinstance(text, str) or len(text) > MAX_PAYLOAD_CHARS:
        raise InvalidQrPayload("To nie jest kod QR Hushbox.")
    try:
        data = json.loads(text)
    except (json.JSONDecodeError, RecursionError) as exc:
        raise InvalidQrPayload("To nie jest kod QR Hushbox.") from exc
    if not isinstance(data, dict) or "v" not in data:
        raise InvalidQrPayload("To nie jest kod QR Hushbox.")

    version = data["v"]
    if not isinstance(version, int) or isinstance(version, bool) or version < 1:
        raise InvalidQrPayload("Kod QR ma nieprawidłową wersję.")
    if version != VERSION:
        raise UnsupportedQrPayload(
            f"Kod QR w wersji {version}; ta wersja obsługuje tylko {VERSION}. "
            "Zaktualizuj aplikację."
        )

    kind = data.get("type")
    if not isinstance(kind, str) or not kind:
        raise InvalidQrPayload("Kod QR nie określa typu treści.")
    if kind in RESERVED_TYPES:
        raise UnsupportedQrPayload(
            f"Kody QR typu „{kind}” nie są jeszcze obsługiwane. Zaktualizuj aplikację."
        )
    if kind != TYPE_CONTACT:
        raise UnsupportedQrPayload(
            f"Nieznany typ kodu QR („{kind}”). Zaktualizuj aplikację."
        )

    return ContactCard(
        public_key=_check_public_key(data.get("public_key")),
        relay_url=_check_relay_url(data.get("relay_url")),
    )
