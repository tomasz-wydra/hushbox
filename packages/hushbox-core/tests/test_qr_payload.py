"""Tests for the versioned QR payload format."""
import base64
import json

import pytest
from nacl.public import PrivateKey

from hushbox_core import (
    ContactCard,
    HushboxError,
    InvalidQrPayload,
    QrPayloadError,
    UnsupportedQrPayload,
    fingerprint_for_pubkey,
    qr_payload,
)


@pytest.fixture
def key():
    return base64.b64encode(bytes(PrivateKey.generate().public_key)).decode()


def _dump(obj) -> str:
    return json.dumps(obj)


# ─────────────────────────────────────────────────────────────────
# Building
# ─────────────────────────────────────────────────────────────────

class TestContactPayload:

    def test_compact_json_with_version_and_type(self, key):
        text = qr_payload.contact_payload(key)
        assert text == '{"v":1,"type":"contact","public_key":"%s"}' % key

    def test_relay_url_is_included_and_trimmed(self, key):
        text = qr_payload.contact_payload(key, "  https://relay.example/  ")
        assert json.loads(text)["relay_url"] == "https://relay.example/"

    def test_empty_relay_url_is_omitted(self, key):
        assert "relay_url" not in json.loads(qr_payload.contact_payload(key, "  "))

    def test_roundtrip(self, key):
        card = qr_payload.parse(qr_payload.contact_payload(key, "http://127.0.0.1:5000"))
        assert card == ContactCard(key, "http://127.0.0.1:5000")
        assert card.fingerprint == fingerprint_for_pubkey(key)

    def test_ascii_only(self, key):
        """Pure ASCII keeps byte mode predictable on every scanner."""
        qr_payload.contact_payload(key, "https://relay.example/").encode("ascii")

    def test_refuses_what_parse_would_refuse(self, key):
        with pytest.raises(InvalidQrPayload):
            qr_payload.contact_payload("not-a-key")
        with pytest.raises(InvalidQrPayload):
            qr_payload.contact_payload(key, "ftp://relay.example")

    def test_typical_size_fits_comfortably(self, key):
        text = qr_payload.contact_payload(key, "https://relay.example-company.pl/")
        assert len(text) < 200


# ─────────────────────────────────────────────────────────────────
# Parsing
# ─────────────────────────────────────────────────────────────────

class TestParse:

    def test_relay_url_optional(self, key):
        card = qr_payload.parse(_dump({"v": 1, "type": "contact", "public_key": key}))
        assert card.relay_url == ""

    def test_unknown_fields_are_ignored(self, key):
        card = qr_payload.parse(_dump(
            {"v": 1, "type": "contact", "public_key": key, "name": "Jan", "x": [1]}))
        assert card.public_key == key

    def test_legacy_payload_without_version_is_rejected(self, key):
        with pytest.raises(InvalidQrPayload, match="nie jest kod QR Hushbox"):
            qr_payload.parse(_dump({"public_key": key}))

    @pytest.mark.parametrize("text", [
        "", "hello", "https://example.com", "[]", "null", "42", '"str"', "{",
        "[" * 10000,
    ])
    def test_not_a_hushbox_code(self, text):
        with pytest.raises(InvalidQrPayload):
            qr_payload.parse(text)

    def test_too_long_is_refused_before_parsing(self, key):
        with pytest.raises(InvalidQrPayload):
            qr_payload.parse(" " * (qr_payload.MAX_PAYLOAD_CHARS + 1))

    def test_non_string_input(self):
        with pytest.raises(InvalidQrPayload):
            qr_payload.parse(b'{"v":1}')

    @pytest.mark.parametrize("v", [0, -1, "1", 1.0, True, None, [1]])
    def test_invalid_version(self, key, v):
        with pytest.raises(InvalidQrPayload, match="wersj"):
            qr_payload.parse(_dump({"v": v, "type": "contact", "public_key": key}))

    @pytest.mark.parametrize("v", [2, 99])
    def test_newer_version_asks_for_update(self, key, v):
        with pytest.raises(UnsupportedQrPayload, match="Zaktualizuj"):
            qr_payload.parse(_dump({"v": v, "type": "contact", "public_key": key}))

    @pytest.mark.parametrize("kind", ["invite", "message"])
    def test_reserved_types_are_not_supported_yet(self, key, kind):
        with pytest.raises(UnsupportedQrPayload, match=kind):
            qr_payload.parse(_dump({"v": 1, "type": kind, "public_key": key}))

    def test_unknown_type(self, key):
        with pytest.raises(UnsupportedQrPayload, match="Nieznany"):
            qr_payload.parse(_dump({"v": 1, "type": "group", "public_key": key}))

    @pytest.mark.parametrize("kind", [None, "", 1, ["contact"]])
    def test_missing_or_bad_type(self, key, kind):
        payload = {"v": 1, "public_key": key}
        if kind is not None:
            payload["type"] = kind
        with pytest.raises(InvalidQrPayload, match="typu"):
            qr_payload.parse(_dump(payload))

    def test_errors_share_a_base(self):
        assert issubclass(InvalidQrPayload, QrPayloadError)
        assert issubclass(UnsupportedQrPayload, QrPayloadError)
        assert issubclass(QrPayloadError, HushboxError)


class TestPublicKeyField:

    @pytest.mark.parametrize("bad", [
        None, "", 123, "not base64 !!!",
        base64.b64encode(b"\0" * 31).decode(),          # wrong length
        base64.b64encode(b"\0" * 33).decode(),
    ])
    def test_invalid_keys(self, bad):
        with pytest.raises(InvalidQrPayload, match="(?i)klucz"):
            qr_payload.parse(_dump({"v": 1, "type": "contact", "public_key": bad}))

    def test_non_canonical_spelling_is_rejected(self, key):
        """Characters outside the alphabet or missing padding are not tolerated."""
        for variant in (key[:10] + "\n" + key[10:], key.rstrip("="), key + "AAAA"):
            with pytest.raises(InvalidQrPayload):
                qr_payload.parse(_dump({"v": 1, "type": "contact", "public_key": variant}))

    def test_non_ascii_key(self):
        with pytest.raises(InvalidQrPayload):
            qr_payload.parse(_dump({"v": 1, "type": "contact", "public_key": "ąę" * 22}))


class TestRelayUrlField:

    @pytest.mark.parametrize("url", [
        "https://relay.example",
        "https://relay.example:8443/path",
        "http://localhost:5000",
        "http://[::1]:5000",
    ])
    def test_valid(self, key, url):
        card = qr_payload.parse(_dump(
            {"v": 1, "type": "contact", "public_key": key, "relay_url": url}))
        assert card.relay_url == url

    @pytest.mark.parametrize("url", [
        "ftp://relay.example",
        "javascript:alert(1)",
        "relay.example",
        "https://",
        "https://user:secret@relay.example",
        "https://user@relay.example",
        "https://relay.example:99999",
        "https://relay.example/a b",
        "https://relay.example/\x00",
        "https://" + "a" * 2100 + ".example",
        123,
        ["https://relay.example"],
    ])
    def test_invalid(self, key, url):
        with pytest.raises(InvalidQrPayload):
            qr_payload.parse(_dump(
                {"v": 1, "type": "contact", "public_key": key, "relay_url": url}))

    def test_empty_or_null_means_none(self, key):
        for url in ("", None):
            card = qr_payload.parse(_dump(
                {"v": 1, "type": "contact", "public_key": key, "relay_url": url}))
            assert card.relay_url == ""
