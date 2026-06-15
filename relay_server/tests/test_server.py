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

import pytest
import mongomock

# ── patch MongoDB zanim server.py zrobi import ──────────────────
@pytest.fixture(autouse=True)
def mock_mongo(monkeypatch):
    """Podmień get_collection() na mongomock kolekcję."""
    import server
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
    import server
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
        with patch("server.get_collection") as mock_gc:
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
        import server
        with patch("server.MAX_QUEUE", 2):
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
