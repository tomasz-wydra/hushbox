# SPDX-License-Identifier: Apache-2.0
from . import envelope, keyfile, qr_payload, relay_auth, signing
from .encryption_manager import (
    EncryptionManager,
    ContactInfo,
    fingerprint_for_pubkey,
    normalize_fingerprint,
)
from .envelope import (
    DecryptedMessage,
    EncryptedMessage,
    JsonFileReplayStore,
    MemoryReplayStore,
    MessageType,
    ReplayStore,
)
from .qr_payload import ContactCard
from .relay_auth import (
    AuthenticatedRelayTransport,
    RelaySession,
    pubkey_to_hash,
    send_message,
)
from .errors import (
    HushboxError,
    KeyStoreError,
    PassphraseRequired,
    InvalidPassphrase,
    UnsupportedKeyFormat,
    ContactError,
    KeyConflictError,
    FingerprintMismatch,
    DecryptionError,
    InvalidCiphertextFormat,
    UnsupportedMessageFormat,
    UnsupportedMessageType,
    UnexpectedMessageType,
    MessageExpired,
    ReplayedMessage,
    ReplayStoreError,
    RelayError,
    RelayAuthError,
    RelayPermissionError,
    RelayInsecureTransportError,
    RelayRateLimited,
    RelayUnavailable,
    RelayRequestStopped,
    LocalDeliveryError,
    SignatureError,
    QrPayloadError,
    InvalidQrPayload,
    UnsupportedQrPayload,
)

__all__ = [
    "EncryptionManager", "ContactInfo",
    "fingerprint_for_pubkey", "normalize_fingerprint",
    "AuthenticatedRelayTransport", "RelaySession", "send_message", "pubkey_to_hash",
    "keyfile", "envelope", "qr_payload", "relay_auth", "signing", "ContactCard",
    "EncryptedMessage", "DecryptedMessage", "MessageType",
    "ReplayStore", "MemoryReplayStore", "JsonFileReplayStore",
    # wyjątki domenowe
    "HushboxError",
    "KeyStoreError", "PassphraseRequired", "InvalidPassphrase",
    "UnsupportedKeyFormat",
    "ContactError", "KeyConflictError", "FingerprintMismatch",
    "DecryptionError", "InvalidCiphertextFormat",
    "UnsupportedMessageFormat", "UnsupportedMessageType", "UnexpectedMessageType",
    "MessageExpired", "ReplayedMessage",
    "ReplayStoreError",
    "RelayError", "RelayAuthError", "RelayPermissionError",
    "RelayInsecureTransportError", "RelayRateLimited", "RelayUnavailable",
    "RelayRequestStopped", "LocalDeliveryError",
    "SignatureError",
    "QrPayloadError", "InvalidQrPayload", "UnsupportedQrPayload",
]
