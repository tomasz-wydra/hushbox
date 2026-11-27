# SPDX-License-Identifier: Apache-2.0
"""Relay client with mailbox authentication (``hushbox-relay-auth-v1``).

A Hushbox relay is a store-and-forward mailbox server that never sees
plaintext. Mailboxes are identified by ``pubkey_hash`` (SHA-256 of the
recipient's base64 public key). Sending needs no credentials; reading and
acknowledging a mailbox needs a session bound to it, obtained by proving
possession of the mailbox's X25519 private key without ever sending it:

1. ``POST /auth/challenge {public_key}``: the relay encrypts a challenge
   document to our public key with a NaCl sealed box.
2. We open it locally, check *every* context field (protocol, purpose,
   audience, challenge id, our own mailbox hash, expiry) and only then send
   back the 32-byte secret from that document.
3. ``POST /auth/verify`` returns a short-lived bearer token, kept **in memory
   only**, never written to disk or logs.

:class:`AuthenticatedRelayTransport` uses such a session to long-poll and
acknowledge (``DELETE``) the mailbox. Delivery is *durable before ACK*: each
message is handed to ``on_delivery`` synchronously and acknowledged only after
the handler reports that it was stored.

Transport security: the token is a bearer credential, so it only travels over
HTTPS. Plain HTTP is accepted for loopback hosts (local development) and, for
remote hosts, only with ``allow_insecure_http=True``. Redirects are never
followed, so a token cannot be forwarded to another origin.

The full client-side protocol is specified in ``docs/relay-auth.md`` of this
repository.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import ipaddress
import json
import logging
import random
import re
import threading
import time
from collections.abc import Callable
from datetime import datetime, timezone
from urllib.parse import urlsplit

import httpx
from nacl.encoding import Base64Encoder
from nacl.exceptions import CryptoError
from nacl.public import PrivateKey, SealedBox

from ._cancellable_http import CancellableRelayHTTP
from .errors import (
    LocalDeliveryError,
    RelayAuthError,
    RelayInsecureTransportError,
    RelayPermissionError,
    RelayRateLimited,
    RelayRequestStopped,
    RelayUnavailable,
)

logger = logging.getLogger(__name__)

PROTOCOL = "hushbox-relay-auth-v1"
PURPOSE = "mailbox-session"

LONG_POLL_TIMEOUT = 30       # seconds the relay may hold a poll open
REQUEST_TIMEOUT = 35         # must be > LONG_POLL_TIMEOUT
SEND_TIMEOUT = 35
AUTH_TIMEOUT = 15.0          # challenge / verify requests
ACK_TIMEOUT = 10.0
LOGOUT_TIMEOUT = 1.0         # best effort: one deadline for the whole request, no retry
POLL_LIMIT = 50
# Renew the token when less than this remains, so a long poll never starts on a
# session that expires mid-wait (the relay also caps the wait server-side).
RENEW_MARGIN = LONG_POLL_TIMEOUT + 10
# Tolerated difference between our clock and the relay's when checking the
# challenge's ``expires_at``. The challenge is additionally bound to the
# ``challenge_id`` of the very response that carried it.
CLOCK_SKEW = 300
MAX_CHALLENGE_LIFETIME = 600
MAX_ENCRYPTED_CHALLENGE_LEN = 4096
MAX_SESSION_LIFETIME = 24 * 3600

# Poll-loop backoff.
BACKOFF_BASE = 1.0
BACKOFF_MAX = 60.0
PERMANENT_ERROR_DELAY = 300.0

_URLSAFE_43 = re.compile(r"^[A-Za-z0-9_-]{43}$")
_STD_B64_32 = re.compile(r"^[A-Za-z0-9+/]{43}=$")
_DEFAULT_PORTS = {"http": 80, "https": 443}

ClientFactory = Callable[..., httpx.Client]


# ─────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────

def pubkey_to_hash(public_key_b64: str) -> str:
    """Mailbox id: SHA-256 hex over the **base64 text** of a public key.

    Part of the wire protocol: hashing the raw 32 bytes instead would address
    a different mailbox.
    """
    return hashlib.sha256(public_key_b64.encode()).hexdigest()


def canonical_audience(url: str) -> str:
    """Canonical relay identifier, byte for byte the relay's own function.

    Lowercase scheme and host, default port dropped, trailing slashes of the
    path dropped. Derived from the relay URL in *our* configuration, never
    from anything the relay or an attacker sends, so a challenge minted for a
    different relay deployment is rejected.
    """
    parts = urlsplit((url or "").strip())
    scheme = parts.scheme.lower()
    if scheme not in _DEFAULT_PORTS:
        raise RelayAuthError("relay URL must start with http:// or https://")
    if parts.username or parts.password or parts.query or parts.fragment:
        raise RelayAuthError("relay URL must not contain credentials, query or fragment")
    host = (parts.hostname or "").lower()
    if not host:
        raise RelayAuthError("relay URL has no host")
    try:
        port = parts.port
    except ValueError as exc:
        raise RelayAuthError("relay URL has an invalid port") from exc
    if ":" in host:
        host = f"[{host}]"
    netloc = host if port in (None, _DEFAULT_PORTS[scheme]) else f"{host}:{port}"
    return f"{scheme}://{netloc}{parts.path.rstrip('/')}"


def is_loopback_host(host: str) -> bool:
    host = (host or "").strip("[]").lower()
    if host == "localhost" or host.endswith(".localhost"):
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def check_transport_security(relay_url: str, allow_insecure_http: bool = False) -> None:
    """Raise unless sending a bearer credential to ``relay_url`` is acceptable."""
    parts = urlsplit(relay_url)
    scheme = parts.scheme.lower()
    if scheme == "https":
        return
    if scheme == "http" and (is_loopback_host(parts.hostname or "") or allow_insecure_http):
        return
    raise RelayInsecureTransportError(
        "Relay requires HTTPS for authentication. Use an https:// relay URL "
        "(plain HTTP is only allowed for localhost or when explicitly enabled)."
    )


def _retry_after(resp: httpx.Response) -> float | None:
    raw = resp.headers.get("Retry-After", "")
    try:
        value = float(raw)
    except ValueError:
        return None
    return min(max(value, 0.0), 3600.0)


def _parse_utc(value: object) -> datetime:
    if not isinstance(value, str):
        raise RelayAuthError("challenge has no valid expiry")
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError as exc:
        raise RelayAuthError("challenge has no valid expiry") from exc


def _strict_b64(value: object, max_len: int) -> bytes:
    if not isinstance(value, str) or not value or len(value) > max_len or len(value) % 4:
        raise RelayAuthError("malformed base64 from relay")
    try:
        return base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise RelayAuthError("malformed base64 from relay") from exc


# ─────────────────────────────────────────────────────────────────
# Sending (no credentials)
# ─────────────────────────────────────────────────────────────────

def send_message(
    relay_url: str,
    recipient_pubkey_b64: str,
    payload: str,
    *,
    sender_pubkey_b64: str = "",
    allow_insecure_http: bool = False,
    client_factory: ClientFactory | None = None,
    timeout: float = SEND_TIMEOUT,
) -> dict:
    """Store an encrypted ``payload`` in the recipient's mailbox.

    ``POST /messages {"to": hash, "payload": ..., "from": hash?}``. No session
    is needed: the payload is end-to-end encrypted and only the mailbox owner
    can read it back. ``sender_pubkey_b64`` adds the sender's mailbox hash as
    ``from`` (metadata visible to the relay), which receivers use to look up
    the sender. The same HTTPS rule as for sessions applies
    (:func:`check_transport_security`), because the mailbox ids are metadata.

    :returns: the relay's JSON answer, ``{"ok": true, "id": "..."}``.
    :raises ValueError: empty recipient or payload.
    :raises RelayInsecureTransportError: plain HTTP to a remote host without
        ``allow_insecure_http``; nothing is sent.
    :raises RelayRateLimited: HTTP 429.
    :raises RelayUnavailable: network error, timeout, redirect, other non-2xx
        status or an answer without ``"ok": true``.
    """
    if not recipient_pubkey_b64:
        raise ValueError("recipient_pubkey_b64 must not be empty")
    if not payload:
        raise ValueError("payload must not be empty")
    body = {"to": pubkey_to_hash(recipient_pubkey_b64), "payload": payload}
    if sender_pubkey_b64:
        body["from"] = pubkey_to_hash(sender_pubkey_b64)
    base = (relay_url or "").strip().rstrip("/")
    check_transport_security(base, allow_insecure_http)
    url = f"{base}/messages"
    factory = client_factory or httpx.Client
    try:
        with factory(timeout=timeout, follow_redirects=False) as client:
            resp = client.post(url, json=body)
    except httpx.HTTPError as exc:
        raise RelayUnavailable(type(exc).__name__) from None
    if resp.status_code == 429:
        raise RelayRateLimited(_retry_after(resp))
    if not 200 <= resp.status_code < 300:
        raise RelayUnavailable(f"HTTP {resp.status_code}")
    try:
        result = resp.json()
    except ValueError:
        raise RelayUnavailable("send response is not JSON") from None
    if not isinstance(result, dict) or result.get("ok") is not True:
        raise RelayUnavailable("relay did not accept the message")
    logger.debug("[Relay] sent -> %s… id=%s", body["to"][:8], str(result.get("id", "?"))[:8])
    return result


# ─────────────────────────────────────────────────────────────────
# Session
# ─────────────────────────────────────────────────────────────────

class RelaySession:
    """One in-memory relay session for one (relay URL, identity) pair.

    Thread-safe and single-flight: concurrent callers that need a token while
    a login is in progress wait for that login instead of starting their own.

    :param client_factory: optional synchronous ``httpx.Client`` factory
        (``factory(timeout=..., follow_redirects=False)``), for tests and
        custom transports. Without it requests use cancellable HTTP, so
        :meth:`cancel_pending` can interrupt a long poll immediately.
    """

    def __init__(
        self,
        relay_url: str,
        private_key: PrivateKey,
        *,
        allow_insecure_http: bool = False,
        client_factory: ClientFactory | None = None,
        clock: Callable[[], float] = time.monotonic,
        wallclock: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
    ):
        self.base_url = (relay_url or "").strip().rstrip("/")
        self._audience = canonical_audience(self.base_url)
        self._allow_insecure_http = bool(allow_insecure_http)
        self._sk = private_key
        self.public_key_b64 = private_key.public_key.encode(encoder=Base64Encoder).decode()
        self.recipient_hash = pubkey_to_hash(self.public_key_b64)
        self._client_factory = client_factory
        self._http = CancellableRelayHTTP()
        self._clock = clock
        self._wallclock = wallclock
        self._lock = threading.Lock()
        self._token: str | None = None
        self._expires_at = 0.0          # monotonic deadline
        self._closed = False
        self.login_count = 0            # observable for tests/diagnostics

    # ── HTTP ─────────────────────────────────────────────────────
    def _client(self, timeout: float) -> httpx.Client:
        # follow_redirects=False: a 3xx is an error, never a reason to resend
        # credentials somewhere else. TLS verification stays at httpx default.
        assert self._client_factory is not None
        return self._client_factory(timeout=timeout, follow_redirects=False)

    def _url(self, path: str) -> str:
        return f"{self.base_url}{path}"

    def _raw(self, method: str, path: str, *, timeout: float,
             token: str | None = None, allow_shutdown: bool = False, **kw) -> httpx.Response:
        check_transport_security(self.base_url, self._allow_insecure_http)
        headers = dict(kw.pop("headers", {}) or {})
        if token is not None:
            headers["Authorization"] = f"Bearer {token}"
        try:
            if self._client_factory is None:
                resp = self._http.request(
                    method, self._url(path), timeout=timeout, headers=headers,
                    allow_shutdown=allow_shutdown, **kw,
                )
            else:
                if self._http.stopping and not allow_shutdown:
                    raise RelayRequestStopped
                with self._client(timeout) as client:
                    resp = client.request(method, self._url(path), headers=headers, **kw)
        except httpx.HTTPError as exc:
            raise RelayUnavailable(type(exc).__name__) from None
        if 300 <= resp.status_code < 400:
            raise RelayAuthError("relay answered with a redirect; refusing to follow it")
        if resp.status_code == 429:
            raise RelayRateLimited(_retry_after(resp))
        if resp.status_code >= 500:
            raise RelayUnavailable(f"HTTP {resp.status_code}")
        return resp

    # ── token management ─────────────────────────────────────────
    @property
    def has_token(self) -> bool:
        with self._lock:
            return self._token is not None

    def token(self) -> str:
        """Return a valid token, logging in (once, under the lock) if needed."""
        with self._lock:
            if self._closed or self._http.stopping:
                raise RelayAuthError("relay session closed")
            if self._token and self._expires_at - self._clock() > RENEW_MARGIN:
                return self._token
            self._token = None
            token, lifetime = self._login()
            self._token = token
            self._expires_at = self._clock() + lifetime
            return token

    def invalidate(self, token: str) -> None:
        """Drop ``token`` if it is still the current one (a newer token
        obtained by another thread in the meantime is kept)."""
        with self._lock:
            if self._token == token:
                self._token = None

    def _login(self) -> tuple[str, float]:
        self.login_count += 1
        resp = self._raw("POST", "/auth/challenge", timeout=AUTH_TIMEOUT,
                         json={"public_key": self.public_key_b64})
        if resp.status_code != 200:
            raise RelayAuthError(f"challenge refused (HTTP {resp.status_code})")
        try:
            body = resp.json()
        except ValueError:
            raise RelayAuthError("challenge response is not JSON") from None
        if not isinstance(body, dict):
            raise RelayAuthError("challenge response is not an object")
        challenge_id = body.get("challenge_id")
        if not isinstance(challenge_id, str) or not _URLSAFE_43.match(challenge_id):
            raise RelayAuthError("challenge response has an invalid challenge_id")
        sealed = _strict_b64(body.get("encrypted_challenge"), MAX_ENCRYPTED_CHALLENGE_LEN)

        secret_b64 = self._open_challenge(sealed, challenge_id)

        resp = self._raw("POST", "/auth/verify", timeout=AUTH_TIMEOUT,
                         json={"challenge_id": challenge_id, "response": secret_b64})
        if resp.status_code != 200:
            raise RelayAuthError(f"challenge verification failed (HTTP {resp.status_code})")
        try:
            out = resp.json()
        except ValueError:
            raise RelayAuthError("verify response is not JSON") from None
        token = out.get("access_token") if isinstance(out, dict) else None
        if not isinstance(token, str) or not _URLSAFE_43.match(token):
            raise RelayAuthError("verify response has no valid access_token")
        if out.get("token_type") != "Bearer":
            raise RelayAuthError("unexpected token_type")
        expires_in = out.get("expires_in")
        if (not isinstance(expires_in, int) or isinstance(expires_in, bool)
                or not 0 < expires_in <= MAX_SESSION_LIFETIME):
            raise RelayAuthError("verify response has an invalid expires_in")
        logger.info("Relay session established for mailbox %s…", self.recipient_hash[:8])
        return token, float(expires_in)

    def _open_challenge(self, sealed: bytes, challenge_id: str) -> str:
        """Decrypt and fully validate the challenge; return only its secret.

        Deliberately not a generic "decrypt any sealed box" oracle: anything
        that is not a well-formed challenge for *this* relay, *this* mailbox
        and *this* login attempt is rejected without revealing its content.
        """
        try:
            plain = SealedBox(self._sk).decrypt(sealed)
            doc = json.loads(plain.decode("utf-8"))
        except (CryptoError, UnicodeDecodeError, ValueError):
            raise RelayAuthError("challenge could not be opened") from None
        if not isinstance(doc, dict):
            raise RelayAuthError("challenge has an invalid format")
        if doc.get("protocol") != PROTOCOL:
            raise RelayAuthError("challenge uses an unexpected protocol")
        if doc.get("purpose") != PURPOSE:
            raise RelayAuthError("challenge has an unexpected purpose")
        if doc.get("relay_audience") != self._audience:
            raise RelayAuthError("challenge was issued for a different relay")
        if doc.get("challenge_id") != challenge_id:
            raise RelayAuthError("challenge id mismatch")
        if doc.get("recipient_hash") != self.recipient_hash:
            raise RelayAuthError("challenge is bound to a different mailbox")
        expires = _parse_utc(doc.get("expires_at"))
        now = self._wallclock()
        remaining = (expires - now).total_seconds()
        if remaining < -CLOCK_SKEW or remaining > MAX_CHALLENGE_LIFETIME + CLOCK_SKEW:
            raise RelayAuthError("challenge expired or has an implausible expiry")
        secret = doc.get("secret")
        if not isinstance(secret, str) or not _STD_B64_32.match(secret):
            raise RelayAuthError("challenge secret has an invalid format")
        if len(_strict_b64(secret, 44)) != 32:
            raise RelayAuthError("challenge secret has an invalid length")
        return secret

    # ── authenticated requests ───────────────────────────────────
    def request(self, method: str, path: str, *, timeout: float, **kw) -> tuple[httpx.Response, bool]:
        """Send an authenticated request.

        On 401 the token is renewed and the request repeated **once**. Returns
        ``(response, retried)`` so idempotency-sensitive callers (ACK) can
        interpret the second answer. 403 raises :class:`RelayPermissionError`.
        """
        token = self.token()
        resp = self._raw(method, path, timeout=timeout, token=token, **kw)
        retried = False
        if resp.status_code == 401:
            self.invalidate(token)
            with self._lock:
                closed = self._closed
            if closed:
                raise RelayAuthError("relay session closed")
            token = self.token()
            resp = self._raw(method, path, timeout=timeout, token=token, **kw)
            retried = True
            if resp.status_code == 401:
                self.invalidate(token)
                raise RelayAuthError("relay rejected a freshly issued session")
        if resp.status_code == 403:
            raise RelayPermissionError("relay denied access to this mailbox")
        return resp, retried

    def close(self, *, logout: bool = True) -> None:
        """Forget the token; optionally revoke it on the relay (best effort)."""
        self.cancel_pending()
        with self._lock:
            token, self._token = self._token, None
            self._closed = True
        if logout and token:
            try:
                self._raw(
                    "POST", "/auth/logout", timeout=LOGOUT_TIMEOUT,
                    token=token, allow_shutdown=True,
                )
            except Exception as exc:  # noqa: BLE001 - best effort only
                logger.debug("Relay logout failed: %s", type(exc).__name__)

    def cancel_pending(self) -> None:
        """Interrupt in-flight HTTP, also during a login that holds the lock."""
        self._http.cancel_pending()


# ─────────────────────────────────────────────────────────────────
# Transport
# ─────────────────────────────────────────────────────────────────

class AuthenticatedRelayTransport:
    """Send to any mailbox; long-poll and acknowledge our own.

    Receiving is *durable before ACK*:

    1. each delivery is handed to ``on_delivery(msg_id, from_hash, payload)``
       *synchronously*; the handler stores it and returns ``True`` only once
       that is durable;
    2. only then is the message acknowledged (``DELETE``) and the in-memory
       ``since`` cursor advanced;
    3. if the handler returns ``False`` or raises, the batch stops (no ACK, no
       cursor move) and the poll loop backs off and fetches again later.

    Without an ``on_delivery`` handler nothing is fetched-and-acknowledged at
    all, so a message can never be deleted from the relay before it was stored.
    The durable cursor is the application's job: pass the last stored
    relay message id as ``last_message_id`` when constructing.

    :param my_pubkey_b64: our public key; must match ``private_key`` (a
        mismatch raises ``ValueError``).
    :param on_status: optional callback for persistent problems worth showing
        to the user (access denied, HTTPS required, local storage failing).
        Each distinct message is reported once; recovery is not reported.
    """

    def __init__(
        self,
        relay_url: str,
        my_pubkey_b64: str,
        private_key: PrivateKey,
        *,
        allow_insecure_http: bool = False,
        last_message_id: str = "",
        on_status: Callable[[str], None] | None = None,
        client_factory: ClientFactory | None = None,
    ):
        self.relay_url = (relay_url or "").strip().rstrip("/")
        self.my_hash = pubkey_to_hash(my_pubkey_b64)
        self._my_pubkey_b64 = my_pubkey_b64
        self._last_message_id = last_message_id
        self._client_factory = client_factory
        self._polling_thread: threading.Thread | None = None
        self._stop_event = threading.Event()
        self.session = RelaySession(
            self.relay_url,
            private_key,
            allow_insecure_http=allow_insecure_http,
            client_factory=client_factory,
        )
        if self.session.public_key_b64 != my_pubkey_b64 or self.session.recipient_hash != self.my_hash:
            raise ValueError("private key does not match the configured public key")
        self.on_status = on_status
        self._last_status = ""
        # (relay_msg_id, from_hash, payload) -> bool "durably handled".
        self.on_delivery: Callable[[str, str, str], bool] | None = None

    # ── sending ──────────────────────────────────────────────────
    def send(self, recipient_pubkey_b64: str, payload: str,
             sender_pubkey_b64: str = "") -> dict:
        """Send ``payload`` to a mailbox on this relay (see :func:`send_message`)."""
        return send_message(
            self.relay_url, recipient_pubkey_b64, payload,
            sender_pubkey_b64=sender_pubkey_b64,
            allow_insecure_http=self.session._allow_insecure_http,
            client_factory=self._client_factory,
        )

    # ── lifecycle ────────────────────────────────────────────────
    def start_polling(self) -> None:
        """Start long-polling in a background thread (idempotent)."""
        if self._polling_thread and self._polling_thread.is_alive():
            return
        self._stop_event.clear()
        self._polling_thread = threading.Thread(
            target=self._poll_loop, daemon=True, name="RelayPoller"
        )
        self._polling_thread.start()
        logger.info("Relay polling started (hash=%s…)", self.my_hash[:8])

    @property
    def is_polling(self) -> bool:
        return bool(self._polling_thread and self._polling_thread.is_alive())

    def stop_polling(self) -> None:
        """Stop polling without blocking: cancel in-flight requests and revoke
        the session in a background thread (see :meth:`wait_stopped`)."""
        self._stop_event.set()
        self.session.cancel_pending()
        if getattr(self, "_logout_thread", None) is None:
            self._logout_thread = threading.Thread(
                target=self.session.close, daemon=True, name="RelayLogout"
            )
            self._logout_thread.start()

    def wait_stopped(self, timeout: float | None = 0) -> bool:
        """Wait for the background logout started by :meth:`stop_polling`."""
        thread = getattr(self, "_logout_thread", None)
        if thread is not None:
            thread.join(timeout)
        return thread is None or not thread.is_alive()

    def logout(self) -> None:
        """Forget and revoke the session synchronously."""
        self.session.close(logout=True)

    # ── status reporting ─────────────────────────────────────────
    def _report(self, text: str) -> None:
        if text == self._last_status:
            return
        self._last_status = text
        if text and self.on_status:
            try:
                self.on_status(text)
            except Exception:  # noqa: BLE001 - UI callback must not kill polling
                logger.debug("on_status callback failed", exc_info=True)

    # ── polling ──────────────────────────────────────────────────
    def _poll_loop(self) -> None:
        failures = 0
        while not self._stop_event.is_set():
            try:
                self._fetch_messages()
                failures = 0
                self._report("")
                continue
            except RelayRequestStopped:
                break  # deliberate shutdown, not a failure and no reason to retry
            except RelayRateLimited as exc:
                failures += 1
                delay = exc.retry_after if exc.retry_after is not None else self._backoff(failures)
                logger.warning("Relay %s rate-limited us; retrying in %.0fs", self.relay_url, delay)
            except (RelayPermissionError, RelayInsecureTransportError) as exc:
                # Renewing the token cannot fix these: wait long, don't loop.
                delay = PERMANENT_ERROR_DELAY
                logger.error("Relay %s: %s", self.relay_url, exc)
                self._report(f"Relay {self.relay_url}: {exc}")
            except LocalDeliveryError as exc:
                failures += 1
                delay = self._backoff(failures)
                logger.error("Relay %s: %s; message left on relay", self.relay_url, exc)
                self._report(
                    f"Relay {self.relay_url}: could not save incoming message locally "
                    "— it stays on the relay and will be retried"
                )
            except Exception as exc:  # noqa: BLE001 - network, auth, 5xx
                failures += 1
                delay = self._backoff(failures)
                logger.warning(
                    "Relay polling error (%s): %s: %s; retrying in %.1fs",
                    self.relay_url, type(exc).__name__, str(exc), delay,
                )
            self._stop_event.wait(delay)

    @staticmethod
    def _backoff(failures: int) -> float:
        cap = min(BACKOFF_MAX, BACKOFF_BASE * (2 ** min(failures, 10)))
        return random.uniform(cap / 2, cap)   # "equal jitter"

    def _fetch_messages(self) -> None:
        params: dict = {"timeout": LONG_POLL_TIMEOUT, "limit": POLL_LIMIT}
        if self._last_message_id:
            params["since"] = self._last_message_id

        resp, _ = self.session.request(
            "GET", f"/messages/{self.my_hash}", timeout=REQUEST_TIMEOUT, params=params,
        )
        if resp.status_code != 200:
            raise RelayAuthError(f"unexpected HTTP {resp.status_code} while polling")
        try:
            data = resp.json()
        except ValueError:
            raise RelayUnavailable("poll response is not JSON") from None
        messages = data.get("messages", []) if isinstance(data, dict) else []
        if not isinstance(messages, list):
            messages = []

        handler = self.on_delivery
        if handler is None:
            return
        for msg in messages:
            if self._stop_event.is_set():
                break
            if not isinstance(msg, dict):
                continue
            msg_id = msg.get("id", "")
            from_h = msg.get("from", "")
            payload = msg.get("payload", "")
            if not all(isinstance(v, str) for v in (msg_id, from_h, payload)):
                continue
            if not msg_id:
                # Relays always assign ids; without one there is nothing to
                # dedupe on or acknowledge, so skip rather than process twice.
                continue

            try:
                handled = handler(msg_id, from_h, payload)
            except LocalDeliveryError:
                raise
            except Exception as exc:  # noqa: BLE001 - never ACK on failure
                raise LocalDeliveryError(type(exc).__name__) from exc
            if not handled:
                break  # not durable: no ACK, no cursor move, retry later
            if self._stop_event.is_set():
                break  # stored; a redelivery is deduplicated and acknowledged then

            self._ack(msg_id)
            self._last_message_id = msg_id

    def _ack(self, msg_id: str) -> bool:
        """DELETE the message (synchronously, after it was stored).

        A 404 after a token renewal means the first attempt most likely
        already succeeded and is treated as done. A failed ACK is not fatal:
        the message is already stored, so a redelivery is deduplicated by the
        application and acknowledged again.
        """
        try:
            resp, retried = self.session.request(
                "DELETE", f"/messages/{self.my_hash}/{msg_id}", timeout=ACK_TIMEOUT,
            )
            if resp.status_code == 404 and retried:
                logger.debug("[Relay] ack %s: already gone after renewal", msg_id[:8])
                return True
            if resp.status_code not in (200, 404):
                logger.debug("[Relay] ack %s: HTTP %s", msg_id[:8], resp.status_code)
                return False
            return True
        except Exception as exc:  # noqa: BLE001 - stored already; redelivery is deduplicated
            logger.debug("[Relay] ack failed for %s: %s", msg_id[:8], type(exc).__name__)
            return False
