"""Client side of ``hushbox-relay-auth-v1`` against a scripted fake relay.

The fake relay (``httpx.MockTransport``) speaks the protocol and can forge or
tamper with challenge documents, answer 401/403/429/5xx, redirect, and serve
messages. A real local HTTP server is used only to check that stopping the
transport interrupts a parked long poll.
"""
from __future__ import annotations

import base64
import json
import os
import secrets
import threading
import time
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import httpx
import pytest
from nacl.encoding import Base64Encoder
from nacl.public import PrivateKey, PublicKey, SealedBox

from hushbox_core import (
    AuthenticatedRelayTransport,
    HushboxError,
    LocalDeliveryError,
    RelayAuthError,
    RelayError,
    RelayInsecureTransportError,
    RelayPermissionError,
    RelayRateLimited,
    RelaySession,
    RelayUnavailable,
    pubkey_to_hash,
    relay_auth,
    send_message,
)

RELAY = "https://relay.test"
_Client = httpx.Client


def _pk(sk: PrivateKey) -> str:
    return sk.public_key.encode(encoder=Base64Encoder).decode()


class FakeRelay:
    """Minimal relay speaking the auth protocol, with knobs for misbehaviour."""

    def __init__(self, public_key_b64: str, audience: str = RELAY):
        self.pk_b64 = public_key_b64
        self.audience = audience
        self.tamper: dict = {}
        self.encrypt_to: str | None = None    # encrypt challenge to another key
        self.messages_status: list[int] = []  # scripted statuses for /messages/*
        self.challenge_status = 200
        self.retry_after: str | None = None
        self.inbox: list[dict] = []           # served by GET until DELETEd
        self.sent: list[dict] = []            # bodies of POST /messages
        self.send_status = 200
        self.requests: list[httpx.Request] = []
        self.logins = 0
        self.issued: list[str] = []
        self.logouts: list[str] = []
        self.lock = threading.Lock()
        self._pending = None

    def factory(self, **kw):
        assert "verify" not in kw, "TLS verification must not be overridden"
        assert kw.get("follow_redirects") is False
        return _Client(transport=httpx.MockTransport(self.handle), **kw)

    def _authorized(self, request) -> bool:
        auth = request.headers.get("Authorization", "")
        return auth.startswith("Bearer ") and auth[7:] in self.issued

    def handle(self, request: httpx.Request) -> httpx.Response:
        with self.lock:
            self.requests.append(request)
        path = request.url.path
        if path == "/auth/challenge":
            with self.lock:
                self.logins += 1
            if self.challenge_status != 200:
                headers = {"Retry-After": self.retry_after} if self.retry_after else {}
                return httpx.Response(self.challenge_status, headers=headers, json={})
            cid = secrets.token_urlsafe(32)
            doc = {
                "protocol": "hushbox-relay-auth-v1",
                "purpose": "mailbox-session",
                "relay_audience": self.audience,
                "challenge_id": cid,
                "recipient_hash": pubkey_to_hash(self.pk_b64),
                "expires_at": (datetime.now(timezone.utc) + timedelta(seconds=60))
                .strftime("%Y-%m-%dT%H:%M:%SZ"),
                "secret": base64.b64encode(os.urandom(32)).decode(),
            }
            doc.update(self.tamper)
            target = PublicKey(base64.b64decode(self.encrypt_to or self.pk_b64))
            sealed = base64.b64encode(SealedBox(target).encrypt(json.dumps(doc).encode())).decode()
            self._pending = (cid, doc.get("secret"))
            return httpx.Response(200, json={"challenge_id": cid, "encrypted_challenge": sealed,
                                             "expires_in": 60})
        if path == "/auth/verify":
            body = json.loads(request.content)
            if (body["challenge_id"], body["response"]) != self._pending:
                return httpx.Response(401, json={})
            token = secrets.token_urlsafe(32)
            self.issued.append(token)
            return httpx.Response(200, json={"access_token": token, "token_type": "Bearer",
                                             "expires_in": 900})
        if path == "/auth/logout":
            self.logouts.append(request.headers.get("Authorization", ""))
            return httpx.Response(204)
        if path == "/messages" and request.method == "POST":
            self.sent.append(json.loads(request.content))
            if self.send_status != 200:
                headers = {"Retry-After": self.retry_after} if self.retry_after else {}
                return httpx.Response(self.send_status, headers=headers, json={"ok": False})
            return httpx.Response(200, json={"ok": True, "id": secrets.token_hex(8)})
        if path.startswith("/messages/"):
            status = self.messages_status.pop(0) if self.messages_status else 200
            if status in (301, 302, 307, 308):
                return httpx.Response(status, headers={"Location": "https://evil.test/steal"})
            if status == 200 and not self._authorized(request):
                status = 401
            if status != 200:
                headers = {"Retry-After": self.retry_after} if self.retry_after else {}
                return httpx.Response(status, headers=headers, json={"ok": False})
            if request.method == "DELETE":
                msg_id = path.rsplit("/", 1)[-1]
                before = len(self.inbox)
                self.inbox = [m for m in self.inbox if m["id"] != msg_id]
                return httpx.Response(200 if len(self.inbox) < before else 404, json={"ok": True})
            since = request.url.params.get("since")
            msgs = self.inbox
            if since:
                ids = [m["id"] for m in msgs]
                msgs = msgs[ids.index(since) + 1:] if since in ids else msgs
            return httpx.Response(200, json={"ok": True, "messages": msgs})
        return httpx.Response(404)

    def paths(self, prefix: str, method: str | None = None) -> list[httpx.Request]:
        return [r for r in self.requests
                if r.url.path.startswith(prefix) and (method is None or r.method == method)]


@pytest.fixture
def key():
    return PrivateKey.generate()


def _session(sk, fake, url=RELAY, **kw):
    return RelaySession(url, sk, client_factory=fake.factory, **kw)


def _transport(sk, fake, url=RELAY, **kw):
    return AuthenticatedRelayTransport(url, _pk(sk), sk, client_factory=fake.factory, **kw)


# ─────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────

class TestHelpers:

    def test_pubkey_to_hash_is_sha256_of_base64_text(self, key):
        import hashlib
        b64 = _pk(key)
        assert pubkey_to_hash(b64) == hashlib.sha256(b64.encode()).hexdigest()
        assert len(pubkey_to_hash(b64)) == 64

    @pytest.mark.parametrize("url,expected", [
        ("https://Relay.Example.COM/", "https://relay.example.com"),
        ("https://relay.example.com:443", "https://relay.example.com"),
        ("http://relay.example.com:80/", "http://relay.example.com"),
        ("https://relay.example.com:8443/base//", "https://relay.example.com:8443/base"),
        ("http://[::1]:5000", "http://[::1]:5000"),
        ("  https://relay.example.com  ", "https://relay.example.com"),
    ])
    def test_canonical_audience(self, url, expected):
        assert relay_auth.canonical_audience(url) == expected

    @pytest.mark.parametrize("url", [
        "ftp://relay.example.com", "relay.example.com", "https://",
        "https://user:pw@relay.example.com", "https://relay.example.com/?q=1",
        "https://relay.example.com/#f", "https://relay.example.com:99999",
    ])
    def test_canonical_audience_rejects(self, url):
        with pytest.raises(RelayAuthError):
            relay_auth.canonical_audience(url)

    def test_errors_share_a_base(self):
        for exc in (RelayAuthError, RelayPermissionError, RelayInsecureTransportError,
                    RelayRateLimited, RelayUnavailable, LocalDeliveryError):
            assert issubclass(exc, RelayError)
        assert issubclass(RelayError, HushboxError)


# ─────────────────────────────────────────────────────────────────
# Sending
# ─────────────────────────────────────────────────────────────────

class TestSend:

    def test_posts_hashes_and_payload(self, key):
        fake = FakeRelay(_pk(key))
        other = _pk(PrivateKey.generate())
        result = send_message(RELAY + "/", other, "ciphertext", sender_pubkey_b64=_pk(key),
                              client_factory=fake.factory)
        assert result["ok"] is True
        assert fake.sent == [{"to": pubkey_to_hash(other), "payload": "ciphertext",
                              "from": pubkey_to_hash(_pk(key))}]
        assert fake.paths("/messages")[0].url == httpx.URL(RELAY + "/messages")

    def test_from_is_optional(self, key):
        fake = FakeRelay(_pk(key))
        send_message(RELAY, _pk(key), "x", client_factory=fake.factory)
        assert "from" not in fake.sent[0]

    def test_needs_no_session(self, key):
        fake = FakeRelay(_pk(key))
        _transport(key, fake).send(_pk(key), "x")
        assert fake.logins == 0
        assert "Authorization" not in fake.paths("/messages")[0].headers

    @pytest.mark.parametrize("recipient,payload", [("", "x"), ("k", "")])
    def test_rejects_empty(self, recipient, payload):
        with pytest.raises(ValueError):
            send_message(RELAY, recipient, payload)

    def test_server_error_is_unavailable(self, key):
        fake = FakeRelay(_pk(key))
        fake.send_status = 500
        with pytest.raises(RelayUnavailable):
            send_message(RELAY, _pk(key), "x", client_factory=fake.factory)

    def test_rate_limit(self, key):
        fake = FakeRelay(_pk(key))
        fake.send_status = 429
        fake.retry_after = "3"
        with pytest.raises(RelayRateLimited) as info:
            send_message(RELAY, _pk(key), "x", client_factory=fake.factory)
        assert info.value.retry_after == 3

    def test_not_ok_answer_is_unavailable(self, key):
        def factory(**kw):
            return _Client(transport=httpx.MockTransport(
                lambda r: httpx.Response(200, json={"ok": False})), **kw)
        with pytest.raises(RelayUnavailable):
            send_message(RELAY, _pk(key), "x", client_factory=factory)

    def test_redirect_is_not_followed(self, key):
        def factory(**kw):
            assert kw.get("follow_redirects") is False
            return _Client(transport=httpx.MockTransport(
                lambda r: httpx.Response(307, headers={"Location": "https://evil.test/"})), **kw)
        with pytest.raises(RelayUnavailable):
            send_message(RELAY, _pk(key), "x", client_factory=factory)

    @pytest.mark.parametrize("url,allow,ok", [
        ("http://relay.example.com", False, False),
        ("http://relay.example.com", True, True),
        ("http://localhost:5001", False, True),
        ("ftp://relay.example.com", True, False),
    ])
    def test_http_policy(self, key, url, allow, ok):
        fake = FakeRelay(_pk(key))
        if ok:
            send_message(url, _pk(key), "x", allow_insecure_http=allow,
                         client_factory=fake.factory)
        else:
            with pytest.raises(RelayInsecureTransportError):
                send_message(url, _pk(key), "x", allow_insecure_http=allow,
                             client_factory=fake.factory)
            assert fake.requests == []

    def test_transport_send_uses_its_http_policy(self, key):
        fake = FakeRelay(_pk(key), audience="http://relay.example.com")
        strict = _transport(key, fake, url="http://relay.example.com")
        with pytest.raises(RelayInsecureTransportError):
            strict.send(_pk(key), "x")
        relaxed = _transport(key, fake, url="http://relay.example.com", allow_insecure_http=True)
        relaxed.send(_pk(key), "x")
        assert len(fake.sent) == 1

    def test_network_error_is_unavailable(self, key):
        def factory(**kw):
            def boom(request):
                raise httpx.ConnectError("refused", request=request)
            return _Client(transport=httpx.MockTransport(boom), **kw)
        with pytest.raises(RelayUnavailable):
            send_message(RELAY, _pk(key), "x", client_factory=factory)


# ─────────────────────────────────────────────────────────────────
# Session (challenge-response)
# ─────────────────────────────────────────────────────────────────

class TestSession:

    def test_happy_path(self, key):
        fake = FakeRelay(_pk(key))
        s = _session(key, fake)
        token = s.token()
        assert token in fake.issued
        assert s.token() == token and fake.logins == 1

    @pytest.mark.parametrize("field,value", [
        ("protocol", "hushbox-relay-auth-v2"),
        ("purpose", "something-else"),
        ("relay_audience", "https://other-relay.test"),
        ("challenge_id", "B" * 43),
        ("recipient_hash", "0" * 64),
        ("expires_at", "2000-01-01T00:00:00Z"),
        ("expires_at", "2999-01-01T00:00:00Z"),
        ("expires_at", "yesterday"),
        ("secret", "short"),
        ("secret", 12345),
    ])
    def test_rejects_tampered_challenge(self, key, field, value):
        fake = FakeRelay(_pk(key))
        fake.tamper = {field: value}
        with pytest.raises(RelayAuthError):
            _session(key, fake).token()
        assert fake.paths("/auth/verify") == [], "secret must not be sent back"

    def test_rejects_challenge_for_other_key(self, key):
        fake = FakeRelay(_pk(key))
        fake.encrypt_to = _pk(PrivateKey.generate())
        with pytest.raises(RelayAuthError):
            _session(key, fake).token()
        assert fake.paths("/auth/verify") == []

    def test_audience_comes_from_client_config_not_relay(self, key):
        fake = FakeRelay(_pk(key), audience=RELAY)
        with pytest.raises(RelayAuthError):
            _session(key, fake, url="https://my-real-relay.test").token()

    def test_concurrent_callers_single_login(self, key):
        fake = FakeRelay(_pk(key))
        s = _session(key, fake)
        barrier = threading.Barrier(12)
        tokens = []

        def worker():
            barrier.wait()
            tokens.append(s.token())

        threads = [threading.Thread(target=worker) for _ in range(12)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(5)
        assert fake.logins == 1
        assert len(set(tokens)) == 1

    def test_token_renewed_before_expiry(self, key):
        fake = FakeRelay(_pk(key))
        now = [0.0]
        s = RelaySession(RELAY, key, client_factory=fake.factory, clock=lambda: now[0])
        first = s.token()
        now[0] = 900 - relay_auth.RENEW_MARGIN + 1
        assert s.token() != first and fake.logins == 2

    def test_401_renews_once_then_gives_up(self, key):
        fake = FakeRelay(_pk(key))
        fake.messages_status = [401, 401]
        s = _session(key, fake)
        with pytest.raises(RelayAuthError):
            s.request("GET", "/messages/x", timeout=5)
        assert len(fake.paths("/messages/")) == 2
        assert fake.logins == 2

    def test_401_then_success(self, key):
        fake = FakeRelay(_pk(key))
        fake.messages_status = [401, 200]
        s = _session(key, fake)
        resp, retried = s.request("GET", "/messages/x", timeout=5)
        assert resp.status_code == 200 and retried
        reqs = fake.paths("/messages/")
        assert reqs[0].headers["Authorization"] != reqs[1].headers["Authorization"]

    def test_403_raises_without_relogin(self, key):
        fake = FakeRelay(_pk(key))
        fake.messages_status = [403]
        s = _session(key, fake)
        with pytest.raises(RelayPermissionError):
            s.request("GET", "/messages/x", timeout=5)
        assert fake.logins == 1 and len(fake.paths("/messages/")) == 1

    def test_redirect_is_not_followed(self, key):
        fake = FakeRelay(_pk(key))
        fake.messages_status = [307]
        s = _session(key, fake)
        with pytest.raises(RelayAuthError):
            s.request("GET", "/messages/x", timeout=5)
        assert all(r.url.host == "relay.test" for r in fake.requests)

    def test_rate_limit_surfaces_retry_after(self, key):
        fake = FakeRelay(_pk(key))
        fake.challenge_status = 429
        fake.retry_after = "17"
        with pytest.raises(RelayRateLimited) as info:
            _session(key, fake).token()
        assert info.value.retry_after == 17

    def test_server_error_is_unavailable(self, key):
        fake = FakeRelay(_pk(key))
        fake.challenge_status = 503
        with pytest.raises(RelayUnavailable):
            _session(key, fake).token()

    @pytest.mark.parametrize("url,allow,ok", [
        ("http://relay.example.com", False, False),
        ("http://relay.example.com", True, True),
        ("http://localhost:5001", False, True),
        ("http://127.0.0.1:5001", False, True),
        ("http://[::1]:5001", False, True),
        ("https://relay.example.com", False, True),
    ])
    def test_http_policy(self, key, url, allow, ok):
        fake = FakeRelay(_pk(key), audience=relay_auth.canonical_audience(url))
        s = _session(key, fake, url=url, allow_insecure_http=allow)
        if ok:
            assert s.token()
        else:
            with pytest.raises(RelayInsecureTransportError):
                s.token()
            assert fake.requests == [], "nothing may be sent over insecure HTTP"

    def test_close_revokes_and_forgets(self, key):
        fake = FakeRelay(_pk(key))
        s = _session(key, fake)
        token = s.token()
        s.close()
        assert fake.logouts == [f"Bearer {token}"]
        assert not s.has_token
        with pytest.raises(RelayAuthError):
            s.token()


# ─────────────────────────────────────────────────────────────────
# Transport: durable before ACK
# ─────────────────────────────────────────────────────────────────

def _msg(n: int, payload: str = "p") -> dict:
    return {"id": f"m{n}", "from": "f" * 64, "payload": f"{payload}{n}"}


class TestTransport:

    def test_mismatched_private_key_is_rejected(self, key):
        fake = FakeRelay(_pk(key))
        with pytest.raises(ValueError):
            AuthenticatedRelayTransport(RELAY, _pk(PrivateKey.generate()), key,
                                        client_factory=fake.factory)

    def test_delivered_then_acked_and_cursor_moves(self, key):
        fake = FakeRelay(_pk(key))
        fake.inbox = [_msg(1), _msg(2)]
        t = _transport(key, fake)
        seen = []

        def on_delivery(msg_id, from_h, payload):
            # durable-before-ACK: the message is still on the relay
            assert any(m["id"] == msg_id for m in fake.inbox)
            seen.append((msg_id, payload))
            return True

        t.on_delivery = on_delivery
        t._fetch_messages()
        assert seen == [("m1", "p1"), ("m2", "p2")]
        assert fake.inbox == [] and t._last_message_id == "m2"
        poll = fake.paths("/messages/", "GET")[0]
        assert poll.url.path == f"/messages/{t.my_hash}"
        assert poll.url.params["limit"] == "50"

    def test_cursor_is_sent_as_since(self, key):
        fake = FakeRelay(_pk(key))
        t = _transport(key, fake, last_message_id="m7")
        t.on_delivery = lambda *a: True
        t._fetch_messages()
        assert fake.paths("/messages/", "GET")[0].url.params["since"] == "m7"

    def test_not_durable_means_no_ack_and_no_cursor_move(self, key):
        fake = FakeRelay(_pk(key))
        fake.inbox = [_msg(1), _msg(2)]
        t = _transport(key, fake)
        t.on_delivery = lambda *a: False
        t._fetch_messages()
        assert len(fake.inbox) == 2 and t._last_message_id == ""
        assert fake.paths("/messages/", "DELETE") == []

    def test_handler_error_raises_local_delivery_error_without_ack(self, key):
        fake = FakeRelay(_pk(key))
        fake.inbox = [_msg(1)]
        t = _transport(key, fake)

        def broken(*_):
            raise OSError("disk full")

        t.on_delivery = broken
        with pytest.raises(LocalDeliveryError):
            t._fetch_messages()
        assert len(fake.inbox) == 1

    def test_without_handler_nothing_is_acked(self, key):
        fake = FakeRelay(_pk(key))
        fake.inbox = [_msg(1)]
        _transport(key, fake)._fetch_messages()
        assert len(fake.inbox) == 1 and fake.paths("/messages/", "DELETE") == []

    @pytest.mark.parametrize("bad", [
        "not a dict", {"id": 5, "from": "f", "payload": "p"},
        {"id": "", "from": "f", "payload": "p"},
    ])
    def test_malformed_entries_are_skipped(self, key, bad):
        fake = FakeRelay(_pk(key))
        fake.inbox = [bad, _msg(1)]
        t = _transport(key, fake)
        seen = []
        t.on_delivery = lambda i, f, p: seen.append(i) or True
        t._fetch_messages()
        assert seen == ["m1"]

    def test_ack_404_after_renewal_is_treated_as_done(self, key):
        fake = FakeRelay(_pk(key))
        t = _transport(key, fake)
        fake.messages_status = [401, 404]
        assert t._ack("msg-1") is True
        assert len(fake.paths("/messages/", "DELETE")) == 2

    def test_failed_ack_is_not_fatal(self, key):
        fake = FakeRelay(_pk(key))
        fake.inbox = [_msg(1)]
        t = _transport(key, fake)
        t.on_delivery = lambda *a: True
        t.session.token()
        fake.messages_status = [200, 500]   # poll ok, DELETE fails
        t._fetch_messages()
        assert t._last_message_id == "m1"
        assert len(fake.inbox) == 1        # redelivered later, deduplicated by the app

    def test_start_and_stop_polling(self, key):
        fake = FakeRelay(_pk(key))
        t = _transport(key, fake)
        t.on_delivery = lambda *a: True
        assert not t.is_polling
        t.start_polling()
        t.start_polling()          # idempotent
        assert t.is_polling
        t.stop_polling()
        t._polling_thread.join(5)
        assert not t.is_polling
        assert t.wait_stopped(5)

    def test_run_poll_loop_in_own_thread(self, key):
        fake = FakeRelay(_pk(key))
        fake.inbox = [_msg(1)]
        t = _transport(key, fake)
        got = threading.Event()
        t.on_delivery = lambda *a: got.set() or True
        worker = threading.Thread(target=t.run_poll_loop, daemon=True)
        worker.start()
        assert got.wait(5)
        t.stop_polling()
        worker.join(5)
        assert not worker.is_alive()

    def test_stop_polling_revokes_session(self, key):
        fake = FakeRelay(_pk(key))
        t = _transport(key, fake)
        token = t.session.token()
        t.stop_polling()
        assert t.wait_stopped(5)
        assert fake.logouts == [f"Bearer {token}"]


# ─────────────────────────────────────────────────────────────────
# Poll loop: bounded retries
# ─────────────────────────────────────────────────────────────────

def _run_loop(t: AuthenticatedRelayTransport, seconds: float):
    th = threading.Thread(target=t._poll_loop, daemon=True)
    th.start()
    time.sleep(seconds)
    t._stop_event.set()
    th.join(3)
    assert not th.is_alive()


class TestPollLoop:

    def test_403_waits_long(self, key, monkeypatch):
        monkeypatch.setattr(relay_auth, "PERMANENT_ERROR_DELAY", 30.0)
        fake = FakeRelay(_pk(key))
        fake.messages_status = [403] * 100
        statuses = []
        t = _transport(key, fake, on_status=statuses.append)
        _run_loop(t, 0.4)
        assert len(fake.paths("/messages/")) == 1
        assert fake.logins == 1
        assert statuses and "denied" in statuses[0]

    def test_relay_down_backs_off(self, key, monkeypatch):
        monkeypatch.setattr(relay_auth, "BACKOFF_BASE", 0.05)
        calls = []

        def down(**kw):
            calls.append(1)

            def handler(request):
                raise httpx.ConnectError("refused", request=request)
            return _Client(transport=httpx.MockTransport(handler), **kw)

        t = AuthenticatedRelayTransport(RELAY, _pk(key), key, client_factory=down)
        _run_loop(t, 0.8)
        assert 1 <= len(calls) < 10

    def test_insecure_url_never_sends(self, key, monkeypatch):
        monkeypatch.setattr(relay_auth, "PERMANENT_ERROR_DELAY", 30.0)
        fake = FakeRelay(_pk(key), audience="http://relay.example.com")
        statuses = []
        t = _transport(key, fake, url="http://relay.example.com", on_status=statuses.append)
        _run_loop(t, 0.2)
        assert fake.requests == []
        assert statuses and "HTTPS" in statuses[0]

    def test_local_delivery_error_is_reported(self, key, monkeypatch):
        monkeypatch.setattr(relay_auth, "BACKOFF_BASE", 10.0)
        fake = FakeRelay(_pk(key))
        fake.inbox = [_msg(1)]
        statuses = []
        t = _transport(key, fake, on_status=statuses.append)

        def broken(*_):
            raise OSError("disk full")

        t.on_delivery = broken
        _run_loop(t, 0.3)
        assert statuses and "could not save" in statuses[0]
        assert len(fake.inbox) == 1

    def test_status_callback_errors_do_not_kill_polling(self, key, monkeypatch):
        monkeypatch.setattr(relay_auth, "PERMANENT_ERROR_DELAY", 30.0)
        fake = FakeRelay(_pk(key))
        fake.messages_status = [403]

        def bad_callback(text):
            raise RuntimeError("ui gone")

        t = _transport(key, fake, on_status=bad_callback)
        _run_loop(t, 0.2)


# ─────────────────────────────────────────────────────────────────
# Real socket: stopping interrupts a parked long poll
# ─────────────────────────────────────────────────────────────────

def test_stop_interrupts_parked_long_poll_on_a_real_socket(key):
    fake = FakeRelay(_pk(key), audience="http://127.0.0.1")
    parked = threading.Event()
    release = threading.Event()

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def _serve(self):
            body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
            path = self.path.split("?")[0]
            if self.command == "GET" and path.startswith("/messages/"):
                parked.set()
                release.wait(10)      # the relay holds the long poll open
            resp = fake.handle(httpx.Request(
                self.command, "http://127.0.0.1" + self.path, content=body,
                headers=dict(self.headers),
            ))
            self.send_response(resp.status_code)
            for k, v in resp.headers.items():
                if k.lower() not in ("content-length", "transfer-encoding"):
                    self.send_header(k, v)
            self.send_header("Content-Length", str(len(resp.content)))
            self.end_headers()
            self.wfile.write(resp.content)

        do_GET = do_POST = do_DELETE = _serve

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    server.daemon_threads = True
    threading.Thread(target=server.serve_forever, daemon=True).start()
    url = f"http://127.0.0.1:{server.server_address[1]}"
    fake.audience = relay_auth.canonical_audience(url)
    try:
        t = AuthenticatedRelayTransport(url, _pk(key), key)   # real, cancellable HTTP
        t.on_delivery = lambda *a: True
        t.start_polling()
        assert parked.wait(5), "poll never reached the relay"
        started = time.monotonic()
        t.stop_polling()
        t._polling_thread.join(5)
        assert not t.is_polling
        assert time.monotonic() - started < 2, "stop did not interrupt the long poll"
    finally:
        release.set()
        server.shutdown()
        server.server_close()
