# SPDX-License-Identifier: Apache-2.0
"""Public key spelling and the relay mailbox id, defined once.

A public key travels as standard base64 of its 32 raw bytes. Exactly one
spelling is canonical: 44 characters, ``=``-padded, as ``base64.b64encode``
writes it. The relay mailbox id is SHA-256 over that *text* (not over the raw
bytes), so two spellings of the same key would address two mailboxes. Every
place that derives a mailbox id must therefore use :func:`mailbox_id`.

* :func:`canonical_public_key` is for **new input** (a pasted key, a contact
  being added): whitespace from copy-paste channels is removed, anything else
  outside the base64 alphabet is rejected, and the canonical spelling is
  returned for storing.
* :func:`mailbox_id` accepts any spelling that decodes to 32 bytes, the way
  NaCl's ``Base64Encoder`` does, and hashes its canonical form. Contacts saved
  by earlier versions with a stray newline therefore address the right
  mailbox again without a migration.
"""
from __future__ import annotations

import base64
import binascii
import hashlib

from nacl.public import PublicKey

KEY_SIZE = PublicKey.SIZE          # 32


def canonical_public_key(value: str) -> str:
    """Validate a base64 public key and return its canonical spelling.

    Whitespace anywhere (line breaks, spaces from SMS or e-mail) is removed;
    any other character outside the base64 alphabet is an error, so a key with
    stray junk is never silently "repaired" into a different-looking one.

    :raises ValueError: not a string, not strict base64 or not 32 bytes.
    """
    if not isinstance(value, str):
        raise ValueError("Klucz publiczny musi być tekstem base64.")
    compact = "".join(value.split())
    try:
        raw = base64.b64decode(compact.encode("ascii"), validate=True)
    except (binascii.Error, ValueError, UnicodeEncodeError):
        raise ValueError("Klucz publiczny nie jest poprawnym base64.") from None
    if len(raw) != KEY_SIZE:
        raise ValueError(f"Klucz publiczny musi mieć {KEY_SIZE} bajty.")
    return base64.b64encode(raw).decode("ascii")


def is_canonical_public_key(value: object) -> bool:
    """True only for the exact canonical spelling (no whitespace, no junk)."""
    if not isinstance(value, str):
        return False
    try:
        return canonical_public_key(value) == value
    except ValueError:
        return False


def _lenient_raw(value: str) -> bytes:
    # Same decoding as nacl's Base64Encoder (characters outside the alphabet
    # are skipped), so the mailbox matches the key a Box would actually use.
    try:
        raw = base64.b64decode(value.encode("ascii", "ignore"))
    except (binascii.Error, ValueError):
        raise ValueError("Klucz publiczny nie jest poprawnym base64.") from None
    if len(raw) != KEY_SIZE:
        raise ValueError(f"Klucz publiczny musi mieć {KEY_SIZE} bajty.")
    return raw


def mailbox_id(public_key_b64: str) -> str:
    """Relay mailbox id: SHA-256 hex over the canonical base64 text of a key.

    Part of the wire protocol (``docs/relay-auth.md`` section 2).

    :raises ValueError: the value does not decode to a 32-byte key.
    """
    if not isinstance(public_key_b64, str):
        raise ValueError("Klucz publiczny musi być tekstem base64.")
    canonical = base64.b64encode(_lenient_raw(public_key_b64)).decode("ascii")
    return hashlib.sha256(canonical.encode("ascii")).hexdigest()


def repair_public_key(value: str) -> str:
    """Canonical spelling of a key *already stored* by an earlier version
    (lenient, like :func:`mailbox_id`); the value unchanged if it does not
    decode. Not for new input: use :func:`canonical_public_key`."""
    try:
        return base64.b64encode(_lenient_raw(value)).decode("ascii")
    except (ValueError, AttributeError):
        return value
