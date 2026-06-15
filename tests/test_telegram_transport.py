"""
Testy jednostkowe dla TelegramTransport.

Wszystkie testy mockują HTTP — nie wykonują prawdziwych żądań do API Telegram.
"""
import time
import pytest
from unittest.mock import MagicMock, patch, call
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).parent.parent))

from telegram_transport import TelegramTransport


DUMMY_TOKEN = "123456789:ABCdefGhIJKlmNoPQRsTUVwxyz_DUMMY"


# ─────────────────────────────────────────────────────────────────
# Fixtures
# ─────────────────────────────────────────────────────────────────

@pytest.fixture
def tg():
    return TelegramTransport(DUMMY_TOKEN)


def make_mock_response(data: dict, status_code: int = 200):
    """Utwórz mock obiektu httpx.Response."""
    r = MagicMock()
    r.status_code = status_code
    r.json.return_value = data
    r.raise_for_status = MagicMock()
    if status_code >= 400:
        from httpx import HTTPStatusError
        r.raise_for_status.side_effect = HTTPStatusError(
            "error", request=MagicMock(), response=r
        )
    return r


# ─────────────────────────────────────────────────────────────────
# Inicjalizacja
# ─────────────────────────────────────────────────────────────────

class TestInit:
    def test_token_is_stripped(self):
        tg = TelegramTransport("  " + DUMMY_TOKEN + "  ")
        assert tg.token == DUMMY_TOKEN

    def test_initial_state(self, tg):
        assert tg._last_update_id == 0
        assert tg.on_message is None
        assert not tg.is_polling


# ─────────────────────────────────────────────────────────────────
# validate_token
# ─────────────────────────────────────────────────────────────────

class TestValidateToken:

    def test_valid_token_returns_bot_info(self, tg):
        bot_info = {"id": 123, "username": "hushbox_bot", "is_bot": True}
        mock_resp = make_mock_response({"ok": True, "result": bot_info})

        with patch("httpx.Client") as mock_client_cls:
            mock_client = mock_client_cls.return_value.__enter__.return_value
            mock_client.get.return_value = mock_resp
            result = tg.validate_token()

        assert result == bot_info

    def test_invalid_token_raises(self, tg):
        mock_resp = make_mock_response({"ok": False, "description": "Unauthorized"})

        with patch("httpx.Client") as mock_client_cls:
            mock_client = mock_client_cls.return_value.__enter__.return_value
            mock_client.get.return_value = mock_resp
            with pytest.raises(ValueError, match="Token nieprawidłowy"):
                tg.validate_token()

    def test_http_error_propagates(self, tg):
        mock_resp = make_mock_response({}, status_code=401)

        with patch("httpx.Client") as mock_client_cls:
            mock_client = mock_client_cls.return_value.__enter__.return_value
            mock_client.get.return_value = mock_resp
            with pytest.raises(Exception):
                tg.validate_token()


# ─────────────────────────────────────────────────────────────────
# send()
# ─────────────────────────────────────────────────────────────────

class TestSend:

    def test_send_posts_correct_payload(self, tg):
        mock_resp = make_mock_response({"ok": True, "result": {"message_id": 1}})

        with patch("httpx.Client") as mock_client_cls:
            mock_client = mock_client_cls.return_value.__enter__.return_value
            mock_client.post.return_value = mock_resp
            result = tg.send("987654321", "Hello encrypted world")

        assert result["ok"] is True
        called_payload = mock_client.post.call_args[1]["json"]
        assert called_payload["chat_id"] == "987654321"
        assert called_payload["text"] == "Hello encrypted world"
        assert called_payload["disable_web_page_preview"] is True

    def test_send_empty_chat_id_raises(self, tg):
        with pytest.raises(ValueError, match="chat_id"):
            tg.send("", "some text")

    def test_send_empty_text_raises(self, tg):
        with pytest.raises(ValueError, match="Wiadomość"):
            tg.send("123", "")

    def test_send_api_error_raises(self, tg):
        mock_resp = make_mock_response({"ok": False, "description": "chat not found"})

        with patch("httpx.Client") as mock_client_cls:
            mock_client = mock_client_cls.return_value.__enter__.return_value
            mock_client.post.return_value = mock_resp
            with pytest.raises(RuntimeError, match="Telegram API error"):
                tg.send("999", "test")

    def test_send_uses_correct_url(self, tg):
        mock_resp = make_mock_response({"ok": True, "result": {}})

        with patch("httpx.Client") as mock_client_cls:
            mock_client = mock_client_cls.return_value.__enter__.return_value
            mock_client.post.return_value = mock_resp
            tg.send("123", "hi")

        url_called = mock_client.post.call_args[0][0]
        assert DUMMY_TOKEN in url_called
        assert "sendMessage" in url_called


# ─────────────────────────────────────────────────────────────────
# get_my_chat_id()
# ─────────────────────────────────────────────────────────────────

class TestGetMyChatId:

    def test_returns_chat_id_from_last_update(self, tg):
        updates = [{"update_id": 1, "message": {"chat": {"id": 42}, "text": "/start"}}]
        mock_resp = make_mock_response({"ok": True, "result": updates})

        with patch("httpx.Client") as mock_client_cls:
            mock_client = mock_client_cls.return_value.__enter__.return_value
            mock_client.get.return_value = mock_resp
            result = tg.get_my_chat_id()

        assert result == "42"

    def test_returns_none_when_no_updates(self, tg):
        mock_resp = make_mock_response({"ok": True, "result": []})

        with patch("httpx.Client") as mock_client_cls:
            mock_client = mock_client_cls.return_value.__enter__.return_value
            mock_client.get.return_value = mock_resp
            result = tg.get_my_chat_id()

        assert result is None


# ─────────────────────────────────────────────────────────────────
# Polling
# ─────────────────────────────────────────────────────────────────

class TestPolling:

    def test_start_polling_sets_is_polling(self, tg):
        with patch.object(tg, "_fetch_updates"):
            tg.start_polling()
            assert tg.is_polling
            tg.stop_polling()

    def test_stop_polling_clears_is_polling(self, tg):
        # stop_polling() jest non-blocking (bez join()) — wątek kończy się asynchronicznie.
        # Czekamy max 2s na faktyczne zakończenie wątku.
        with patch.object(tg, "_fetch_updates"):
            tg.start_polling()
            tg.stop_polling()
            if tg._polling_thread:
                tg._polling_thread.join(timeout=2)
            assert not tg.is_polling

    def test_double_start_does_not_create_second_thread(self, tg):
        with patch.object(tg, "_fetch_updates"):
            tg.start_polling()
            thread1 = tg._polling_thread
            tg.start_polling()
            thread2 = tg._polling_thread
            assert thread1 is thread2
            tg.stop_polling()

    def test_on_message_callback_called_with_correct_args(self, tg):
        received = []
        tg.on_message = lambda chat_id, text: received.append((chat_id, text))

        updates = {
            "result": [
                {
                    "update_id": 10,
                    "message": {
                        "chat": {"id": 555},
                        "text": "encrypted_blob_xyz",
                    },
                }
            ]
        }
        mock_resp = make_mock_response(updates)

        with patch("httpx.Client") as mock_client_cls:
            mock_client = mock_client_cls.return_value.__enter__.return_value
            mock_client.get.return_value = mock_resp
            tg._fetch_updates()

        assert len(received) == 1
        assert received[0] == ("555", "encrypted_blob_xyz")

    def test_last_update_id_advances(self, tg):
        updates = {
            "result": [
                {"update_id": 100, "message": {"chat": {"id": 1}, "text": "a"}},
                {"update_id": 101, "message": {"chat": {"id": 1}, "text": "b"}},
            ]
        }
        mock_resp = make_mock_response(updates)

        with patch("httpx.Client") as mock_client_cls:
            mock_client = mock_client_cls.return_value.__enter__.return_value
            mock_client.get.return_value = mock_resp
            tg.on_message = MagicMock()
            tg._fetch_updates()

        assert tg._last_update_id == 101

    def test_empty_updates_does_not_call_callback(self, tg):
        tg.on_message = MagicMock()
        mock_resp = make_mock_response({"result": []})

        with patch("httpx.Client") as mock_client_cls:
            mock_client = mock_client_cls.return_value.__enter__.return_value
            mock_client.get.return_value = mock_resp
            tg._fetch_updates()

        tg.on_message.assert_not_called()

    def test_update_without_message_is_ignored(self, tg):
        tg.on_message = MagicMock()
        updates = {"result": [{"update_id": 5}]}  # brak klucza "message"
        mock_resp = make_mock_response(updates)

        with patch("httpx.Client") as mock_client_cls:
            mock_client = mock_client_cls.return_value.__enter__.return_value
            mock_client.get.return_value = mock_resp
            tg._fetch_updates()

        tg.on_message.assert_not_called()

    def test_polling_survives_network_error(self, tg):
        """Błąd sieci w trakcie pollingu nie powinien zatrzymać wątku."""
        call_count = [0]

        def flaky_fetch():
            call_count[0] += 1
            if call_count[0] == 1:
                raise ConnectionError("timeout")

        with patch.object(tg, "_fetch_updates", side_effect=flaky_fetch):
            with patch("telegram_transport.POLL_INTERVAL", 0.05):
                tg.start_polling()
                time.sleep(0.15)
                tg.stop_polling()

        assert call_count[0] >= 2, "Polling powinien kontynuować po błędzie sieci"
