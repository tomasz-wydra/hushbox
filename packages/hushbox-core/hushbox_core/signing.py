# SPDX-License-Identifier: Apache-2.0
"""Ed25519 signing key next to the X25519 encryption key.

Every identity gets a signing key without a new secret: the Ed25519 seed is
derived from the existing 32-byte X25519 private key with keyed BLAKE2b and a
fixed personalisation (domain separation)::

    seed = BLAKE2b-256(key = x25519_private_key,
                       data = b"signing-key/v1",
                       person = b"hushbox:ed25519:")

Consequences, by design:

* nothing new is stored: the key file format and application storage stay as
  they are, and existing identities have a signing key immediately;
* the derivation is one-way: the signing key reveals nothing about the X25519
  key (and vice versa), but whoever holds the X25519 private key can recompute
  the signing key. The two keys are one identity and are rotated together;
* the derivation is fixed by ``v1`` in the input; changing it would change
  every signing key, so it never changes silently.

Signatures are detached Ed25519 signatures over a *context-bound* message, so a
signature made for one purpose (say, an organisation certificate) can never be
accepted for another (say, a group header)::

    signed bytes = b"HBS1" | len(context) (1 byte) | context (ASCII) | message

``context`` is a short ASCII label, lowercase letters, digits and ``.-_:``,
1–64 characters, chosen by the protocol that signs (for example
``"org-cert"``). Distribution and trust of other people's signing keys are not
defined yet (planned with organisation certificates); this module only
provides the key and the primitives.
"""
from __future__ import annotations

import base64
import binascii
import re

from nacl.encoding import RawEncoder
from nacl.exceptions import BadSignatureError
from nacl.hash import blake2b
from nacl.public import PrivateKey
from nacl.signing import SigningKey, VerifyKey

from .errors import SignatureError

_PERSON = b"hushbox:ed25519:"           # exactly 16 bytes (BLAKE2b personal)
_DERIVATION_INPUT = b"signing-key/v1"
_PREFIX = b"HBS1"
SIGNATURE_SIZE = 64
_CONTEXT_RE = re.compile(r"[a-z0-9._:-]{1,64}")


def derive_signing_key(private_key: PrivateKey | bytes) -> SigningKey:
    """Derive the Ed25519 signing key from an X25519 private key."""
    raw = bytes(private_key)
    if len(raw) != PrivateKey.SIZE:
        raise ValueError("X25519 private key must be 32 bytes")
    seed = blake2b(
        _DERIVATION_INPUT,
        digest_size=32,
        key=raw,
        person=_PERSON,
        encoder=RawEncoder,
    )
    return SigningKey(seed)


def encode_verify_key(verify_key: VerifyKey) -> str:
    """Standard base64 of the 32-byte Ed25519 public key."""
    return base64.b64encode(bytes(verify_key)).decode("ascii")


def decode_verify_key(value: str) -> VerifyKey:
    """Parse a base64 Ed25519 public key strictly (canonical, 32 bytes).

    :raises SignatureError: not a valid key.
    """
    try:
        raw = base64.b64decode(value.encode("ascii"), validate=True)
    except (binascii.Error, ValueError, UnicodeEncodeError, AttributeError) as exc:
        raise SignatureError("Nieprawidłowy klucz podpisu.") from exc
    if len(raw) != 32 or base64.b64encode(raw).decode("ascii") != value:
        raise SignatureError("Nieprawidłowy klucz podpisu.")
    return VerifyKey(raw)


def _signed_bytes(context: str, message: bytes) -> bytes:
    if not isinstance(context, str) or not _CONTEXT_RE.fullmatch(context):
        raise ValueError(
            "context must be 1-64 characters of lowercase letters, digits and .-_:"
        )
    if not isinstance(message, (bytes, bytearray, memoryview)):
        raise TypeError("message must be bytes")
    ctx = context.encode("ascii")
    return _PREFIX + bytes([len(ctx)]) + ctx + bytes(message)


def sign(signing_key: SigningKey, context: str, message: bytes) -> bytes:
    """Detached 64-byte signature of ``message`` under ``context``."""
    return signing_key.sign(_signed_bytes(context, message)).signature


def verify(
    verify_key: VerifyKey | str, context: str, message: bytes, signature: bytes
) -> None:
    """Check a signature made by :func:`sign` with the same ``context``.

    :param verify_key: ``VerifyKey`` or its base64 form.
    :raises SignatureError: invalid key, malformed or wrong signature, or a
        signature made under another context.
    """
    if isinstance(verify_key, str):
        verify_key = decode_verify_key(verify_key)
    if not isinstance(signature, (bytes, bytearray)) or len(signature) != SIGNATURE_SIZE:
        raise SignatureError("Nieprawidłowy podpis.")
    try:
        verify_key.verify(_signed_bytes(context, message), bytes(signature))
    except BadSignatureError as exc:
        raise SignatureError("Podpis się nie zgadza.") from exc
