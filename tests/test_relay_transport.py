"""
Testy jednostkowe dla RelayTransport.

Mockujemy httpx.Client — testy nie wymagają działającego serwera.
"""

import time
import threading
import unittest
from unittest.mock import MagicMock, patch, call

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from relay_transport import RelayTransport, pubkey_to_hash


# ─────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────
FAKE_PUBKEY   = "dGVzdHB1YmtleQ=="          # base64("testpubkey")
FAKE_PUBKEY2  = "cmVjaXBpZW50a2V5"           # base64("recipientkey")
RELAY_URL     = "https://relay.example.com"


def _make_transport(**kwargs) -> RelayTransport:
    return RelayTransport(
        relay_url=RELAY_URL,
        my_pubkey_b64=FAKE_PUBKEY,
        **kwargs,
    )


def _mock_response(json_data: dict, status_code: int = 200):
    resp = MagicMock()
    resp.status_code = status_code
    resp.json.return_value = json_data
    resp.raise_for_status = MagicMock()
    return resp


# ─────────────────────────────────────────────────────────────────
# pubkey_to_hash
# ─────────────────────────────────────────────────────────────────
class TestPubkeyToHash(unittest.TestCase):

    def test_returns_64_char_hex(self):
        h = pubkey_to_hash(FAKE_PUBKEY)
        self.assertEqual(len(h), 64)
        int(h, 16)  # musi być poprawny hex

    def test_deterministic(self):
        self.assertEqual(pubkey_to_hash(FAKE_PUBKEY), pubkey_to_hash(FAKE_PUBKEY))

    def test_different_keys_different_hashes(self):
        self.assertNotEqual(pubkey_to_hash(FAKE_PUBKEY), pubkey_to_hash(FAKE_PUBKEY2))


# ─────────────────────────────────────────────────────────────────
# send()
# ─────────────────────────────────────────────────────────────────
class TestRelayTransportSend(unittest.TestCase):

    @patch("relay_transport.httpx.Client")
    def test_send_posts_correct_fields(self, MockClient):
        ctx = MockClient.return_value.__enter__.return_value
        ctx.post.return_value = _mock_response({"ok": True, "id": "abc123"})

        t = _make_transport()
        result = t.send(FAKE_PUBKEY2, "encrypted_blob")

        self.assertTrue(result["ok"])
        args, kwargs = ctx.post.call_args
        body = kwargs.get("json") or args[1]
        self.assertIn("to", body)
        self.assertIn("payload", body)
        self.assertEqual(body["payload"], "encrypted_blob")
        self.assertEqual(body["to"], pubkey_to_hash(FAKE_PUBKEY2))

    @patch("relay_transport.httpx.Client")
    def test_send_includes_from_when_provided(self, MockClient):
        ctx = MockClient.return_value.__enter__.return_value
        ctx.post.return_value = _mock_response({"ok": True, "id": "xyz"})

        t = _make_transport()
        t.send(FAKE_PUBKEY2, "blob", sender_pubkey_b64=FAKE_PUBKEY)

        _, kwargs = ctx.post.call_args
        body = kwargs.get("json") or ctx.post.call_args[0][1]
        self.assertIn("from", body)

    @patch("relay_transport.httpx.Client")
    def test_send_raises_on_empty_recipient(self, MockClient):
        t = _make_transport()
        with self.assertRaises(ValueError):
            t.send("", "payload")

    @patch("relay_transport.httpx.Client")
    def test_send_raises_on_empty_payload(self, MockClient):
        t = _make_transport()
        with self.assertRaises(ValueError):
            t.send(FAKE_PUBKEY2, "")

    @patch("relay_transport.httpx.Client")
    def test_send_raises_on_server_error(self, MockClient):
        ctx = MockClient.return_value.__enter__.return_value
        ctx.post.return_value = _mock_response({"ok": False, "error": "fail"})

        t = _make_transport()
        with self.assertRaises(RuntimeError):
            t.send(FAKE_PUBKEY2, "blob")


# ─────────────────────────────────────────────────────────────────
# start_polling / stop_polling / is_polling
# ─────────────────────────────────────────────────────────────────
class TestRelayPolling(unittest.TestCase):

    @patch("relay_transport.httpx.Client")
    def test_start_polling_creates_thread(self, MockClient):
        ctx = MockClient.return_value.__enter__.return_value
        ctx.get.return_value = _mock_response({"ok": True, "messages": []})

        t = _make_transport()
        t.start_polling()
        time.sleep(0.05)
        self.assertTrue(t.is_polling)
        t.stop_polling()

    @patch("relay_transport.httpx.Client")
    def test_start_polling_idempotent(self, MockClient):
        ctx = MockClient.return_value.__enter__.return_value
        ctx.get.return_value = _mock_response({"ok": True, "messages": []})

        t = _make_transport()
        t.start_polling()
        thread1 = t._polling_thread
        t.start_polling()  # drugi start — nie powinien tworzyć nowego wątku
        self.assertIs(t._polling_thread, thread1)
        t.stop_polling()

    def test_stop_polling_clears_is_polling(self):
        with patch("relay_transport.httpx.Client") as MockClient:
            ctx = MockClient.return_value.__enter__.return_value
            ctx.get.return_value = _mock_response({"ok": True, "messages": []})

            t = _make_transport()
            t.start_polling()
            time.sleep(0.05)
            t.stop_polling()
            # wątek jest daemon — czekamy chwilę aż się zatrzyma
            if t._polling_thread:
                t._polling_thread.join(timeout=2)
            self.assertFalse(t.is_polling)

    @patch("relay_transport.httpx.Client")
    def test_not_polling_initially(self, MockClient):
        t = _make_transport()
        self.assertFalse(t.is_polling)


# ─────────────────────────────────────────────────────────────────
# on_message callback
# ─────────────────────────────────────────────────────────────────
class TestRelayOnMessage(unittest.TestCase):

    @patch("relay_transport.httpx.Client")
    def test_on_message_called_for_each_message(self, MockClient):
        messages = [
            {"id": "id1", "from": "hash_a", "payload": "enc1"},
            {"id": "id2", "from": "hash_b", "payload": "enc2"},
        ]

        call_count = [0]
        responses = [
            _mock_response({"ok": True, "messages": messages}),
            _mock_response({"ok": True, "messages": []}),   # kolejne pollingi puste
        ]
        responses_iter = iter(responses)

        def _side_effect(*args, **kwargs):
            try:
                return next(responses_iter)
            except StopIteration:
                return _mock_response({"ok": True, "messages": []})

        ctx = MockClient.return_value.__enter__.return_value
        ctx.get.side_effect = _side_effect
        ctx.delete.return_value = _mock_response({}, 200)

        received = []
        t = _make_transport()
        t.on_message = lambda from_h, payload: received.append((from_h, payload))
        t.start_polling()
        time.sleep(0.3)
        t.stop_polling()

        self.assertEqual(len(received), 2)
        self.assertEqual(received[0], ("hash_a", "enc1"))
        self.assertEqual(received[1], ("hash_b", "enc2"))

    @patch("relay_transport.httpx.Client")
    def test_last_message_id_updated(self, MockClient):
        messages = [{"id": "msg-999", "from": "h", "payload": "p"}]

        responses = iter([
            _mock_response({"ok": True, "messages": messages}),
        ])

        def _side_effect(*args, **kwargs):
            try:
                return next(responses)
            except StopIteration:
                return _mock_response({"ok": True, "messages": []})

        ctx = MockClient.return_value.__enter__.return_value
        ctx.get.side_effect = _side_effect
        ctx.delete.return_value = _mock_response({}, 200)

        ids = []
        t = _make_transport(on_last_id_change=lambda mid: ids.append(mid))
        t.on_message = MagicMock()
        t.start_polling()
        time.sleep(0.3)
        t.stop_polling()

        self.assertIn("msg-999", ids)

    @patch("relay_transport.httpx.Client")
    def test_no_callback_no_crash(self, MockClient):
        """Brak on_message — wiadomości są ignorowane bez wyjątku."""
        ctx = MockClient.return_value.__enter__.return_value
        ctx.get.return_value = _mock_response({
            "ok": True,
            "messages": [{"id": "x", "from": "h", "payload": "p"}]
        })
        ctx.delete.return_value = _mock_response({}, 200)

        t = _make_transport()
        # on_message = None (domyślnie)
        t.start_polling()
        time.sleep(0.2)
        t.stop_polling()  # nie powinno rzucić wyjątku


# ─────────────────────────────────────────────────────────────────
# my_hash
# ─────────────────────────────────────────────────────────────────
class TestRelayMyHash(unittest.TestCase):

    def test_my_hash_matches_pubkey_to_hash(self):
        t = _make_transport()
        self.assertEqual(t.my_hash, pubkey_to_hash(FAKE_PUBKEY))


if __name__ == "__main__":
    unittest.main()
