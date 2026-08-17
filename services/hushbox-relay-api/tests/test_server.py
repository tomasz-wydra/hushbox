"""
Testy integracyjne relay serwera (Flask test client + mongomock).

mongomock zastępuje prawdziwe MongoDB — testy nie wymagają uruchomionej bazy.
"""

import sys
import os
import time
import uuid
from datetime import datetime, timezone
from unittest.mock import patch, MagicMock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from hushbox_relay_api import server
import hushbox_relay_api.server as server

import pytest
import mongomock

# ── patch MongoDB zanim server.py zrobi import ──────────────────
@pytest.fixture(autouse=True)
def mock_mongo(monkeypatch):
    """Podmień get_collection() na mongomock kolekcję."""
    client = mongomock.MongoClient()
    db     = client["hushbox"]
    col    = db["messages"]

    # odwzoruj indeksy (mongomock je ignoruje, ale create_index nie rzuca błędu)
    monkeypatch.setattr(server, "_col",    col)
    monkeypatch.setattr(server, "_client", client)

    def _get_col():
        return col

    monkeypatch.setattr(server, "get_collection", _get_col)
    yield col
    col.drop()


@pytest.fixture
def client():
    server.app.config["TESTING"] = True
    with server.app.test_client() as c:
        yield c


VALID_HASH_A = "a" * 64
VALID_HASH_B = "b" * 64


# ─────────────────────────────────────────────────────────────────
# Health
# ─────────────────────────────────────────────────────────────────
class TestHealth:

    def test_health_ok(self, client, mock_mongo):
        with patch("hushbox_relay_api.server.get_collection") as mock_gc:
            col = MagicMock()
            col.database.client.admin.command.return_value = {"ok": 1}
            mock_gc.return_value = col
            r = client.get("/health")
        assert r.status_code == 200
        assert r.get_json()["status"] == "ok"


# ─────────────────────────────────────────────────────────────────
# POST /messages
# ─────────────────────────────────────────────────────────────────
class TestSendMessage:

    def test_send_basic(self, client):
        r = client.post("/messages", json={
            "to":      VALID_HASH_A,
            "payload": "enc_blob",
        })
        assert r.status_code == 202
        data = r.get_json()
        assert data["ok"] is True
        assert "id" in data

    def test_send_with_from(self, client):
        r = client.post("/messages", json={
            "to":      VALID_HASH_A,
            "from":    VALID_HASH_B,
            "payload": "payload123",
        })
        assert r.status_code == 202

    def test_send_missing_to(self, client):
        r = client.post("/messages", json={"payload": "x"})
        assert r.status_code == 400

    def test_send_invalid_to_hash(self, client):
        r = client.post("/messages", json={"to": "notatvalidhash", "payload": "x"})
        assert r.status_code == 400

    def test_send_missing_payload(self, client):
        r = client.post("/messages", json={"to": VALID_HASH_A})
        assert r.status_code == 400

    def test_send_payload_too_large(self, client):
        r = client.post("/messages", json={
            "to":      VALID_HASH_A,
            "payload": "x" * (64 * 1024 + 1),
        })
        assert r.status_code == 413

    def test_send_invalid_from_hash(self, client):
        r = client.post("/messages", json={
            "to":      VALID_HASH_A,
            "from":    "bad_hash",
            "payload": "blob",
        })
        assert r.status_code == 400

    def test_send_queue_full(self, client, mock_mongo):
        """Gdy kolejka pełna — 429."""
        with patch("hushbox_relay_api.server.MAX_QUEUE", 2):
            for _ in range(2):
                mock_mongo.insert_one({
                    "msg_id":         str(uuid.uuid4()),
                    "recipient_hash": VALID_HASH_A,
                    "sender_hash":    "",
                    "payload":        "p",
                    "created_at":     datetime.now(timezone.utc),
                })
            r = client.post("/messages", json={
                "to":      VALID_HASH_A,
                "payload": "overflow",
            })
        assert r.status_code == 429


# ─────────────────────────────────────────────────────────────────
# GET /messages/{hash}
# ─────────────────────────────────────────────────────────────────
class TestGetMessages:

    def test_get_empty_queue(self, client):
        r = client.get(f"/messages/{VALID_HASH_A}")
        assert r.status_code == 200
        assert r.get_json()["messages"] == []

    def test_get_returns_sent_message(self, client):
        client.post("/messages", json={"to": VALID_HASH_A, "payload": "hello"})
        r = client.get(f"/messages/{VALID_HASH_A}")
        msgs = r.get_json()["messages"]
        assert len(msgs) == 1
        assert msgs[0]["payload"] == "hello"

    def test_get_multiple_messages(self, client):
        for i in range(3):
            client.post("/messages", json={"to": VALID_HASH_A, "payload": f"m{i}"})
        msgs = client.get(f"/messages/{VALID_HASH_A}").get_json()["messages"]
        assert len(msgs) == 3

    def test_get_since_filters_old(self, client):
        for i in range(3):
            client.post("/messages", json={"to": VALID_HASH_A, "payload": f"p{i}"})
        all_msgs = client.get(f"/messages/{VALID_HASH_A}").get_json()["messages"]
        first_id = all_msgs[0]["id"]

        r2 = client.get(f"/messages/{VALID_HASH_A}?since={first_id}")
        msgs2 = r2.get_json()["messages"]
        assert len(msgs2) == 2
        assert all(m["id"] != first_id for m in msgs2)

    def test_get_invalid_hash(self, client):
        r = client.get("/messages/notavalidhash")
        assert r.status_code == 400

    def test_get_limit(self, client):
        for i in range(10):
            client.post("/messages", json={"to": VALID_HASH_A, "payload": f"p{i}"})
        msgs = client.get(f"/messages/{VALID_HASH_A}?limit=3").get_json()["messages"]
        assert len(msgs) == 3

    def test_messages_isolated_per_recipient(self, client):
        client.post("/messages", json={"to": VALID_HASH_A, "payload": "for_a"})
        client.post("/messages", json={"to": VALID_HASH_B, "payload": "for_b"})

        r_a = client.get(f"/messages/{VALID_HASH_A}").get_json()["messages"]
        r_b = client.get(f"/messages/{VALID_HASH_B}").get_json()["messages"]

        assert r_a[0]["payload"] == "for_a"
        assert r_b[0]["payload"] == "for_b"

    def test_message_has_from_field(self, client):
        client.post("/messages", json={
            "to":      VALID_HASH_A,
            "from":    VALID_HASH_B,
            "payload": "signed_blob",
        })
        msgs = client.get(f"/messages/{VALID_HASH_A}").get_json()["messages"]
        assert msgs[0]["from"] == VALID_HASH_B


# ─────────────────────────────────────────────────────────────────
# DELETE /messages/{hash}/{id}
# ─────────────────────────────────────────────────────────────────
class TestAckMessage:

    def test_ack_removes_message(self, client):
        client.post("/messages", json={"to": VALID_HASH_A, "payload": "x"})
        msgs   = client.get(f"/messages/{VALID_HASH_A}").get_json()["messages"]
        msg_id = msgs[0]["id"]

        r = client.delete(f"/messages/{VALID_HASH_A}/{msg_id}")
        assert r.status_code == 200

        remaining = client.get(f"/messages/{VALID_HASH_A}").get_json()["messages"]
        assert len(remaining) == 0

    def test_ack_not_found(self, client):
        r = client.delete(f"/messages/{VALID_HASH_A}/nonexistent-id")
        assert r.status_code == 404

    def test_ack_invalid_hash(self, client):
        r = client.delete("/messages/badhash/someid")
        assert r.status_code == 400

    def test_ack_wrong_recipient_cannot_delete(self, client):
        """Tylko właściwy odbiorca może usunąć wiadomość."""
        client.post("/messages", json={"to": VALID_HASH_A, "payload": "secret"})
        msgs   = client.get(f"/messages/{VALID_HASH_A}").get_json()["messages"]
        msg_id = msgs[0]["id"]

        # próba usunięcia przez innego odbiorcę
        r = client.delete(f"/messages/{VALID_HASH_B}/{msg_id}")
        assert r.status_code == 404


# ─────────────────────────────────────────────────────────────────
# Stats
# ─────────────────────────────────────────────────────────────────
class TestStats:

    def test_stats_empty(self, client):
        r = client.get("/stats")
        data = r.get_json()
        assert data["total_pending_messages"] == 0

    def test_stats_counts_messages(self, client):
        client.post("/messages", json={"to": VALID_HASH_A, "payload": "p1"})
        client.post("/messages", json={"to": VALID_HASH_A, "payload": "p2"})
        client.post("/messages", json={"to": VALID_HASH_B, "payload": "p3"})

        data = client.get("/stats").get_json()
        assert data["total_pending_messages"] == 3
        assert data["recipients_with_messages"] == 2


# ─────────────────────────────────────────────────────────────────
# Hardening: liveness, walidacja wejścia, limity, rejestr long-poll
# ─────────────────────────────────────────────────────────────────

class TestLivenessEndpoint:

    def test_healthz_returns_ok(self, client):
        r = client.get("/healthz")
        assert r.status_code == 200
        assert r.get_json()["status"] == "ok"

    def test_healthz_does_not_touch_mongo(self, client, monkeypatch):
        """Liveness musi działać nawet gdy baza jest niedostępna."""
        def _boom():
            raise RuntimeError("mongo down")
        monkeypatch.setattr(server, "get_collection", _boom)
        assert client.get("/healthz").status_code == 200

    def test_healthz_exposes_only_status_and_ts(self, client):
        assert set(client.get("/healthz").get_json()) == {"status", "ts"}

    def test_healthz_rejects_post(self, client):
        assert client.post("/healthz").status_code == 405

    def test_health_reports_degraded_when_mongo_down(self, client, monkeypatch):
        """W przeciwieństwie do /healthz, /health sygnalizuje brak bazy."""
        def _boom():
            raise RuntimeError("mongo down")
        monkeypatch.setattr(server, "get_collection", _boom)
        r = client.get("/health")
        assert r.status_code == 503
        assert r.get_json()["mongo"] is False


class TestQueryParamValidation:

    def test_non_numeric_timeout_returns_400_not_500(self, client):
        r = client.get(f"/messages/{VALID_HASH_A}?timeout=abc")
        assert r.status_code == 400
        assert r.get_json()["ok"] is False

    def test_non_numeric_limit_returns_400(self, client):
        assert client.get(f"/messages/{VALID_HASH_A}?limit=x").status_code == 400

    def test_negative_timeout_returns_400(self, client):
        assert client.get(f"/messages/{VALID_HASH_A}?timeout=-5").status_code == 400

    def test_empty_param_falls_back_to_default(self, client):
        assert client.get(f"/messages/{VALID_HASH_A}?timeout=&limit=").status_code == 200

    def test_limit_is_capped(self, client, mock_mongo):
        for _ in range(5):
            client.post("/messages", json={"to": VALID_HASH_A, "payload": "eA=="})
        r = client.get(f"/messages/{VALID_HASH_A}?limit=99999")
        assert r.status_code == 200
        assert len(r.get_json()["messages"]) <= 200

    def test_errors_are_json_not_html(self, client):
        r = client.get(f"/messages/{VALID_HASH_A}?timeout=abc")
        assert r.is_json
        assert "error" in r.get_json()


class TestBodySizeLimit:

    def test_max_content_length_is_configured(self):
        """Bez tego limitu Flask parsuje dowolnie duże ciało do pamięci."""
        assert server.app.config["MAX_CONTENT_LENGTH"] is not None
        assert server.app.config["MAX_CONTENT_LENGTH"] >= server.MAX_PAYLOAD

    def test_oversized_body_is_rejected(self, client):
        huge = "A" * (server.app.config["MAX_CONTENT_LENGTH"] + 1024)
        r = client.post("/messages", json={"to": VALID_HASH_A, "payload": huge})
        assert r.status_code == 413

    def test_payload_over_max_payload_rejected(self, client):
        payload = "A" * (server.MAX_PAYLOAD + 1)
        r = client.post("/messages", json={"to": VALID_HASH_A, "payload": payload})
        assert r.status_code == 413


class TestWaiterRegistry:

    def test_event_removed_when_last_waiter_leaves(self):
        reg = server.WaiterRegistry()
        reg.acquire("abc")
        assert reg.waiting_inboxes() == 1
        reg.release("abc")
        assert reg.waiting_inboxes() == 0, "wyciek pamięci — zdarzenie nie zwolnione"

    def test_refcounting_keeps_event_for_second_waiter(self):
        reg = server.WaiterRegistry()
        e1 = reg.acquire("abc")
        e2 = reg.acquire("abc")
        assert e1 is e2
        reg.release("abc")
        assert reg.waiting_inboxes() == 1
        reg.release("abc")
        assert reg.waiting_inboxes() == 0

    def test_registry_is_bounded(self):
        reg = server.WaiterRegistry(max_waiters=2)
        assert reg.acquire("a") is not None
        assert reg.acquire("b") is not None
        assert reg.acquire("c") is None, "rejestr musi odmówić po przekroczeniu limitu"

    def test_release_unknown_key_is_noop(self):
        reg = server.WaiterRegistry()
        reg.release("nieistnieje")   # nie może rzucić
        assert reg.waiting_inboxes() == 0

    def test_notify_unknown_key_is_noop(self):
        reg = server.WaiterRegistry()
        reg.notify("nieistnieje")

    def test_polling_does_not_leak_events(self, client, mock_mongo):
        """Zapytania o losowe skrzynki nie mogą zostawiać wpisów w pamięci."""
        before = server._waiters.waiting_inboxes()
        for i in range(20):
            h = f"{i:064x}"
            client.get(f"/messages/{h}")
        assert server._waiters.waiting_inboxes() == before

    def test_notify_wakes_waiter(self):
        import threading
        reg = server.WaiterRegistry()
        event = reg.acquire("inbox")
        woken = threading.Event()

        def _wait():
            if event.wait(timeout=5):
                woken.set()

        t = threading.Thread(target=_wait)
        t.start()
        time.sleep(0.1)
        reg.notify("inbox")
        t.join(timeout=5)
        assert woken.is_set()
        reg.release("inbox")


class TestStatsToken:

    def test_stats_open_when_token_not_configured(self, client, monkeypatch):
        monkeypatch.setattr(server, "STATS_TOKEN", "")
        assert client.get("/stats").status_code == 200

    def test_stats_requires_token_when_configured(self, client, monkeypatch):
        monkeypatch.setattr(server, "STATS_TOKEN", "sekret")
        assert client.get("/stats").status_code == 403

    def test_stats_accepts_correct_token(self, client, monkeypatch):
        monkeypatch.setattr(server, "STATS_TOKEN", "sekret")
        r = client.get("/stats", headers={"X-Stats-Token": "sekret"})
        assert r.status_code == 200

    def test_stats_rejects_wrong_token(self, client, monkeypatch):
        monkeypatch.setattr(server, "STATS_TOKEN", "sekret")
        r = client.get("/stats", headers={"X-Stats-Token": "zly"})
        assert r.status_code == 403

    def test_stats_reports_waiting_inboxes(self, client, monkeypatch):
        monkeypatch.setattr(server, "STATS_TOKEN", "")
        assert "waiting_inboxes" in client.get("/stats").get_json()
