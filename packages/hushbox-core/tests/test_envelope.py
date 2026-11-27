"""Tests for the v1 message envelope and replay protection."""
import base64
import json
import threading

import pytest
from nacl.public import Box, PrivateKey

from hushbox_core import (
    DecryptedMessage,
    MessageType,
    UnexpectedMessageType,
    UnsupportedMessageType,
    DecryptionError,
    EncryptionManager,
    InvalidCiphertextFormat,
    JsonFileReplayStore,
    MemoryReplayStore,
    MessageExpired,
    ReplayedMessage,
    ReplayStore,
    ReplayStoreError,
    UnsupportedMessageFormat,
    envelope,
)

DAY = 24 * 60 * 60
NOW = 1_800_000_000.0            # fixed "now" for deterministic tests
NOW_MS = int(NOW * 1000)


class FakeClock:
    def __init__(self, t: float = NOW):
        self.t = t

    def __call__(self) -> float:
        return self.t


# ─────────────────────────────────────────────────────────────────
# Fixtures
# ─────────────────────────────────────────────────────────────────

@pytest.fixture
def keys():
    a, b = PrivateKey.generate(), PrivateKey.generate()
    return Box(a, b.public_key), Box(b, a.public_key)   # (alice→bob, bob←alice)


@pytest.fixture
def clock():
    return FakeClock()


@pytest.fixture
def pair(tmp_path, clock):
    """Alice and Bob who know each other, sharing one fake clock."""
    alice = EncryptionManager(data_dir=str(tmp_path / "alice"), clock=clock)
    bob = EncryptionManager(data_dir=str(tmp_path / "bob"), clock=clock)
    alice.add_contact("Bob", bob.export_public_key())
    bob.add_contact("Alice", alice.export_public_key())
    return alice, bob


def _raw(ciphertext: str) -> bytes:
    return base64.b64decode(ciphertext)


def _b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode()


def _inner(content_type=1, body=b"x", header=None, ts=None):
    """Hand-built v2 inner plaintext for forging test envelopes."""
    return ((header or envelope.HEADER) + bytes([content_type]) + b"\x00" * 16
            + (NOW_MS if ts is None else ts).to_bytes(8, "big") + body)


def _forge(box, inner, outer=None):
    return _b64((outer or envelope.HEADER) + bytes(box.encrypt(inner)))


# ─────────────────────────────────────────────────────────────────
# Wire format
# ─────────────────────────────────────────────────────────────────

class TestWireFormat:

    def test_header_is_magic_and_version(self, keys):
        sealed = envelope.seal(keys[0], "hi", clock=FakeClock())
        raw = _raw(sealed.ciphertext)
        assert raw[:4] == b"HBM1"
        assert raw[4] == 2

    def test_roundtrip_carries_id_and_timestamp(self, keys):
        mid = bytes(range(16))
        sealed = envelope.seal(keys[0], "Zażółć gęślą jaźń 🔐",
                               message_id=mid, timestamp_ms=1234567)
        opened = envelope.open_envelope(keys[1], sealed.ciphertext)
        assert opened == DecryptedMessage("Zażółć gęślą jaźń 🔐", mid.hex(), 1234567,
                                          MessageType.TEXT)
        assert sealed.message_id == mid.hex()
        assert sealed.timestamp_ms == 1234567

    def test_empty_body_roundtrips(self, keys):
        sealed = envelope.seal(keys[0], "", clock=FakeClock())
        assert envelope.open_envelope(keys[1], sealed.ciphertext).text == ""

    def test_message_ids_are_random(self, keys):
        ids = {envelope.seal(keys[0], "x").message_id for _ in range(50)}
        assert len(ids) == 50

    def test_timestamp_comes_from_clock_in_ms(self, keys):
        sealed = envelope.seal(keys[0], "x", clock=FakeClock(NOW + 0.1234))
        assert sealed.timestamp_ms == int((NOW + 0.1234) * 1000)

    def test_id_and_timestamp_are_not_visible_on_the_wire(self, keys):
        mid = b"\xAB" * 16
        sealed = envelope.seal(keys[0], "x", message_id=mid, timestamp_ms=NOW_MS)
        raw = _raw(sealed.ciphertext)
        assert mid not in raw
        assert NOW_MS.to_bytes(8, "big") not in raw

    def test_sent_at_is_utc(self):
        msg = DecryptedMessage("x", "00" * 16, 0)
        assert msg.sent_at.isoformat() == "1970-01-01T00:00:00+00:00"

    @pytest.mark.parametrize("bad", [b"", b"\x00" * 15, b"\x00" * 17])
    def test_seal_rejects_bad_message_id(self, keys, bad):
        with pytest.raises(ValueError):
            envelope.seal(keys[0], "x", message_id=bad)

    def test_seal_rejects_negative_timestamp(self, keys):
        with pytest.raises(ValueError):
            envelope.seal(keys[0], "x", timestamp_ms=-1)

    def test_whitespace_and_line_wrapping_are_tolerated(self, keys):
        ct = envelope.seal(keys[0], "mail " * 50).ciphertext
        wrapped = "  " + "\r\n".join(ct[i:i + 64] for i in range(0, len(ct), 64)) + "\n"
        assert envelope.open_envelope(keys[1], wrapped).text == "mail " * 50



# ─────────────────────────────────────────────────────────────────
# Rejected inputs
# ─────────────────────────────────────────────────────────────────

class TestRejectedInputs:

    def test_legacy_bare_box_is_rejected(self, keys):
        """0.4.0 ciphertexts have no header and are no longer accepted."""
        legacy = _b64(bytes(keys[0].encrypt("stary format".encode())))
        with pytest.raises(InvalidCiphertextFormat, match="0.5.0"):
            envelope.open_envelope(keys[1], legacy)

    def test_newer_version_is_reported_as_unsupported(self, keys):
        raw = bytearray(_raw(envelope.seal(keys[0], "x").ciphertext))
        raw[4] = 3
        with pytest.raises(UnsupportedMessageFormat, match="Zaktualizuj"):
            envelope.open_envelope(keys[1], _b64(bytes(raw)))

    def test_v1_envelope_from_0_5_is_rejected(self, keys):
        """v1 (hushbox-core 0.5.0) never shipped in a client; not accepted."""
        v1_header = b"HBM1\x01"
        inner = v1_header + b"\x00" * 16 + NOW_MS.to_bytes(8, "big") + b"x"
        with pytest.raises(UnsupportedMessageFormat, match="starszym"):
            envelope.open_envelope(keys[1], _forge(keys[0], inner, outer=v1_header))

    def test_unsupported_format_is_a_decryption_error(self):
        assert issubclass(UnsupportedMessageFormat, DecryptionError)

    @pytest.mark.parametrize("length", [4, 5, 5 + 24, 5 + 24 + 15])
    def test_truncated_envelope_is_format_error(self, keys, length):
        raw = _raw(envelope.seal(keys[0], "x").ciphertext)[:length]
        with pytest.raises(InvalidCiphertextFormat):
            envelope.open_envelope(keys[1], _b64(raw))

    def test_not_base64(self, keys):
        with pytest.raises(InvalidCiphertextFormat):
            envelope.open_envelope(keys[1], "to nie jest base64 !!!")

    def test_empty(self, keys):
        with pytest.raises(InvalidCiphertextFormat):
            envelope.open_envelope(keys[1], " \n ")

    def test_tampered_body_fails_poly1305(self, keys):
        raw = bytearray(_raw(envelope.seal(keys[0], "x").ciphertext))
        raw[-1] ^= 0x01
        with pytest.raises(DecryptionError):
            envelope.open_envelope(keys[1], _b64(bytes(raw)))

    def test_wrong_sender(self, keys):
        eve = Box(PrivateKey.generate(), PrivateKey.generate().public_key)
        ct = envelope.seal(eve, "x").ciphertext
        with pytest.raises(DecryptionError):
            envelope.open_envelope(keys[1], ct)

    def test_inner_header_must_match_outer(self, keys):
        """A payload sealed under another version cannot be relabelled."""
        inner = _inner(header=b"HBM1\x03")
        with pytest.raises(DecryptionError, match="Nagłówek"):
            envelope.open_envelope(keys[1], _forge(keys[0], inner))

    def test_short_inner_payload(self, keys):
        forged = envelope.HEADER + bytes(keys[0].encrypt(envelope.HEADER + b"\x00" * 10))
        with pytest.raises(DecryptionError):
            envelope.open_envelope(keys[1], _b64(forged))

    def test_non_utf8_body(self, keys):
        with pytest.raises(DecryptionError, match="UTF-8"):
            envelope.open_envelope(keys[1], _forge(keys[0], _inner(body=b"\xff\xfe")))

    def test_no_nacl_exception_leaks(self, keys):
        from nacl.exceptions import CryptoError
        raw = bytearray(_raw(envelope.seal(keys[0], "x").ciphertext))
        raw[10] ^= 0xFF
        try:
            envelope.open_envelope(keys[1], _b64(bytes(raw)))
        except DecryptionError:
            pass
        except CryptoError:
            pytest.fail("CryptoError leaked out of hushbox_core")


# ─────────────────────────────────────────────────────────────────
# Content types
# ─────────────────────────────────────────────────────────────────

class TestContentTypes:

    @pytest.mark.parametrize("t", list(MessageType) + [128, 200, 255])
    def test_type_roundtrips(self, keys, t):
        sealed = envelope.seal(keys[0], "body", type=t)
        opened = envelope.open_envelope(keys[1], sealed.ciphertext)
        assert opened.type == t == sealed.type
        assert opened.text == "body"

    def test_core_types_come_back_as_enum(self, keys):
        opened = envelope.open_envelope(
            keys[1], envelope.seal(keys[0], "x", type=2).ciphertext)
        assert opened.type is MessageType.FILE_DESCRIPTOR

    def test_default_type_is_text(self, keys):
        assert envelope.seal(keys[0], "x").type is MessageType.TEXT

    def test_type_is_inside_the_ciphertext(self, keys):
        a = _raw(envelope.seal(keys[0], "x", type=1, message_id=b"\0" * 16,
                               timestamp_ms=0).ciphertext)
        b = _raw(envelope.seal(keys[0], "x", type=3, message_id=b"\0" * 16,
                               timestamp_ms=0).ciphertext)
        assert a[:5] == b[:5] and len(a) == len(b)

    @pytest.mark.parametrize("bad", [0, 4, 127, 256, -1, True, "1", 1.0])
    def test_seal_rejects_undefined_types(self, keys, bad):
        with pytest.raises(UnsupportedMessageType):
            envelope.seal(keys[0], "x", type=bad)

    @pytest.mark.parametrize("bad", [0, 4, 127])
    def test_unknown_type_on_the_wire_is_unsupported(self, keys, bad):
        with pytest.raises(UnsupportedMessageType, match="Zaktualizuj"):
            envelope.open_envelope(keys[1], _forge(keys[0], _inner(content_type=bad)))

    def test_unsupported_type_is_a_format_and_decryption_error(self):
        assert issubclass(UnsupportedMessageType, UnsupportedMessageFormat)
        assert issubclass(UnexpectedMessageType, DecryptionError)

    def test_allowed_types(self, keys):
        ct = envelope.seal(keys[0], "x", type=MessageType.FILE_PACKAGE).ciphertext
        envelope.open_envelope(keys[1], ct, allowed_types=(MessageType.FILE_PACKAGE,))
        with pytest.raises(UnexpectedMessageType):
            envelope.open_envelope(keys[1], ct, allowed_types=(MessageType.TEXT,))

    def test_overhead_constant(self, keys):
        for n in (0, 1, 999):
            assert len(_raw(envelope.seal(keys[0], "a" * n).ciphertext)) - n \
                == envelope.OVERHEAD == 75


# ─────────────────────────────────────────────────────────────────
# Freshness window
# ─────────────────────────────────────────────────────────────────

class TestFreshness:

    def test_window_boundaries_are_inclusive(self):
        envelope.check_freshness(int((NOW - 30 * DAY) * 1000), now=NOW)
        envelope.check_freshness(int((NOW + 600) * 1000), now=NOW)

    def test_too_old(self):
        with pytest.raises(MessageExpired):
            envelope.check_freshness(int((NOW - 30 * DAY) * 1000) - 1, now=NOW)

    def test_too_far_in_future(self):
        with pytest.raises(MessageExpired, match="przyszłości"):
            envelope.check_freshness(int((NOW + 600) * 1000) + 1, now=NOW)

    def test_custom_window(self):
        envelope.check_freshness(int((NOW - 50) * 1000), now=NOW, max_age=60)
        with pytest.raises(MessageExpired):
            envelope.check_freshness(int((NOW - 61) * 1000), now=NOW, max_age=60)
        with pytest.raises(MessageExpired):
            envelope.check_freshness(int((NOW + 1) * 1000), now=NOW, max_skew=0)

    def test_expired_is_a_decryption_error(self):
        assert issubclass(MessageExpired, DecryptionError)


# ─────────────────────────────────────────────────────────────────
# Replay stores
# ─────────────────────────────────────────────────────────────────

class TestReplayStores:

    @pytest.fixture(params=["memory", "json"])
    def store(self, request, tmp_path):
        if request.param == "memory":
            return MemoryReplayStore()
        return JsonFileReplayStore(tmp_path / "seen.json")

    def test_implements_protocol(self, store):
        assert isinstance(store, ReplayStore)

    def test_add_once(self, store):
        assert not store.contains("s", "m")
        assert store.add("s", "m", 1) is True
        assert store.contains("s", "m")
        assert store.add("s", "m", 1) is False

    def test_namespaced_by_sender(self, store):
        store.add("alice", "m", 1)
        assert not store.contains("bob", "m")
        assert store.add("bob", "m", 1) is True

    def test_prune_by_sender_timestamp(self, store):
        store.add("s", "old", 100)
        store.add("s", "edge", 200)
        store.add("s", "new", 300)
        store.prune(200)
        assert not store.contains("s", "old")
        assert store.contains("s", "edge")
        assert store.contains("s", "new")

    def test_concurrent_add_accepts_exactly_one(self, store):
        results, barrier = [], threading.Barrier(8)

        def worker():
            barrier.wait()
            results.append(store.add("s", "m", 1))

        threads = [threading.Thread(target=worker) for _ in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert results.count(True) == 1

    def test_json_store_persists(self, tmp_path):
        path = tmp_path / "seen.json"
        JsonFileReplayStore(path).add("s", "m", 5)
        reopened = JsonFileReplayStore(path)
        assert reopened.contains("s", "m")
        assert json.loads(path.read_text()) == {"version": 1, "seen": {"s:m": 5}}

    def test_json_store_persists_prune(self, tmp_path):
        path = tmp_path / "seen.json"
        store = JsonFileReplayStore(path)
        store.add("s", "old", 1)
        store.add("s", "new", 10)
        store.prune(5)
        assert not JsonFileReplayStore(path).contains("s", "old")

    @pytest.mark.parametrize("content", [
        "{not json",
        "[]",
        '{"version": 2, "seen": {}}',
        '{"version": 1, "seen": []}',
        '{"version": 1, "seen": {"s:m": "1"}}',
        '{"version": 1, "seen": {"s:m": true}}',
    ])
    def test_corrupted_file_fails_loudly(self, tmp_path, content):
        """An empty store would accept replays, so never start empty silently."""
        path = tmp_path / "seen.json"
        path.write_text(content)
        with pytest.raises(ReplayStoreError):
            JsonFileReplayStore(path)

    def test_failed_write_does_not_record(self, tmp_path, monkeypatch):
        store = JsonFileReplayStore(tmp_path / "seen.json")

        def boom(*_a, **_k):
            raise OSError("disk full")

        monkeypatch.setattr(envelope.keyfile, "write_atomic", boom)
        with pytest.raises(OSError):
            store.add("s", "m", 1)
        assert not store.contains("s", "m")


# ─────────────────────────────────────────────────────────────────
# EncryptionManager integration
# ─────────────────────────────────────────────────────────────────

class TestManagerReplayProtection:

    def test_roundtrip(self, pair):
        alice, bob = pair
        assert bob.decrypt("Alice", alice.encrypt("Bob", "cześć")) == "cześć"

    def test_second_delivery_is_rejected(self, pair):
        alice, bob = pair
        ct = alice.encrypt("Bob", "przelej 1000 zł")
        bob.decrypt("Alice", ct)
        with pytest.raises(ReplayedMessage):
            bob.decrypt("Alice", ct)

    def test_replay_with_reformatted_text_is_rejected(self, pair):
        """Whitespace changes the string, not the message."""
        alice, bob = pair
        ct = alice.encrypt("Bob", "x")
        bob.decrypt("Alice", ct)
        with pytest.raises(ReplayedMessage):
            bob.decrypt("Alice", "\n".join(ct[i:i + 10] for i in range(0, len(ct), 10)))

    def test_replay_rejected_after_restart(self, pair, tmp_path, clock):
        alice, bob = pair
        ct = alice.encrypt("Bob", "x")
        bob.decrypt("Alice", ct)
        bob_again = EncryptionManager(data_dir=str(tmp_path / "bob"), clock=clock)
        with pytest.raises(ReplayedMessage):
            bob_again.decrypt("Alice", ct)

    def test_replay_rejected_after_contact_rename(self, pair):
        alice, bob = pair
        ct = alice.encrypt("Bob", "x")
        bob.decrypt("Alice", ct)
        bob.rename_contact("Alice", "Ala")
        with pytest.raises(ReplayedMessage):
            bob.decrypt("Ala", ct)

    def test_same_text_twice_is_two_messages(self, pair):
        alice, bob = pair
        assert bob.decrypt("Alice", alice.encrypt("Bob", "ok")) == "ok"
        assert bob.decrypt("Alice", alice.encrypt("Bob", "ok")) == "ok"

    def test_decrypt_message_returns_metadata(self, pair):
        alice, bob = pair
        sent = alice.encrypt_message("Bob", "x")
        got = bob.decrypt_message("Alice", sent.ciphertext)
        assert (got.text, got.message_id, got.timestamp_ms) == \
            ("x", sent.message_id, int(NOW * 1000))

    def test_record_false_then_mark_seen(self, pair):
        alice, bob = pair
        ct = alice.encrypt("Bob", "x")
        msg = bob.decrypt_message("Alice", ct, record=False)
        # not recorded yet: a redelivery (e.g. after a crash) still works
        msg = bob.decrypt_message("Alice", ct, record=False)
        bob.mark_seen("Alice", msg)
        with pytest.raises(ReplayedMessage):
            bob.decrypt_message("Alice", ct, record=False)
        with pytest.raises(ReplayedMessage):
            bob.mark_seen("Alice", msg)

    def test_rejected_message_is_not_recorded(self, pair, tmp_path, clock):
        """Failed checks must not consume the ID."""
        alice, bob = pair
        clock.t = NOW + 3600                  # Alice's clock is 1 h ahead
        ct = alice.encrypt("Bob", "x")
        clock.t = NOW
        with pytest.raises(MessageExpired):
            bob.decrypt("Alice", ct)
        clock.t = NOW + 3600                  # Bob's clock catches up
        assert bob.decrypt("Alice", ct) == "x"

    def test_message_older_than_window_is_rejected(self, pair, clock):
        alice, bob = pair
        ct = alice.encrypt("Bob", "x")
        clock.t = NOW + 30 * DAY + 1
        with pytest.raises(MessageExpired):
            bob.decrypt("Alice", ct)

    def test_old_ids_are_pruned_but_stay_rejected(self, pair, clock):
        alice, bob = pair
        ct = alice.encrypt("Bob", "x")
        bob.decrypt("Alice", ct)
        assert len(bob.replay_store) == 1
        clock.t = NOW + 31 * DAY
        bob.decrypt("Alice", alice.encrypt("Bob", "y"))   # triggers prune
        assert len(bob.replay_store) == 1
        with pytest.raises(MessageExpired):
            bob.decrypt("Alice", ct)

    def test_custom_store_and_window(self, tmp_path, clock):
        store = MemoryReplayStore()
        alice = EncryptionManager(data_dir=str(tmp_path / "a"), clock=clock)
        bob = EncryptionManager(data_dir=str(tmp_path / "b"), clock=clock,
                                replay_store=store, max_message_age=60)
        alice.add_contact("Bob", bob.export_public_key())
        bob.add_contact("Alice", alice.export_public_key())
        ct = alice.encrypt("Bob", "x")
        bob.decrypt("Alice", ct)
        assert len(store) == 1
        assert not (tmp_path / "b" / "seen_messages.json").exists()
        clock.t = NOW + 61
        with pytest.raises(MessageExpired):
            bob.decrypt("Alice", ct)

    @pytest.mark.parametrize("kwargs", [{"max_message_age": 0},
                                        {"max_clock_skew": -1}])
    def test_invalid_window_rejected(self, tmp_path, kwargs):
        with pytest.raises(ValueError):
            EncryptionManager(data_dir=str(tmp_path), **kwargs)

    def test_legacy_message_rejected_by_manager(self, pair):
        alice, bob = pair
        box = Box(alice.private_key, bob.public_key)
        legacy = _b64(bytes(box.encrypt(b"legacy")))
        with pytest.raises(InvalidCiphertextFormat):
            bob.decrypt("Alice", legacy)

    def test_corrupted_default_store_fails_on_startup(self, tmp_path):
        (tmp_path / "seen_messages.json").write_text("garbage")
        with pytest.raises(ReplayStoreError):
            EncryptionManager(data_dir=str(tmp_path))


class TestManagerContentTypes:

    def test_decrypt_accepts_only_text(self, pair):
        alice, bob = pair
        ct = alice.encrypt("Bob", "{}", type=MessageType.FILE_DESCRIPTOR)
        with pytest.raises(UnexpectedMessageType):
            bob.decrypt("Alice", ct)
        # refused before recording: the same envelope is still receivable
        msg = bob.decrypt_message("Alice", ct)
        assert msg.type is MessageType.FILE_DESCRIPTOR

    def test_decrypt_message_types_filter(self, pair):
        alice, bob = pair
        ct = alice.encrypt("Bob", "x", type=200)
        with pytest.raises(UnexpectedMessageType):
            bob.decrypt_message("Alice", ct, types=(MessageType.TEXT,))
        assert bob.decrypt_message("Alice", ct, types=(200,)).type == 200

    def test_package_is_not_a_message(self, pair):
        alice, bob = pair
        ct = alice.encrypt("Bob", "pkg", type=MessageType.FILE_PACKAGE)
        with pytest.raises(UnexpectedMessageType):
            bob.decrypt_message("Alice", ct)
        with pytest.raises(UnexpectedMessageType):
            bob.decrypt_message("Alice", ct, types=(MessageType.FILE_PACKAGE,))
        assert len(bob.replay_store) == 0

    def test_open_package_has_no_replay_or_window(self, pair, clock):
        alice, bob = pair
        ct = alice.encrypt("Bob", "pkg", type=MessageType.FILE_PACKAGE)
        assert bob.open_package("Alice", ct) == "pkg"
        clock.t = NOW + 365 * DAY
        assert bob.open_package("Alice", ct) == "pkg"
        assert len(bob.replay_store) == 0

    def test_open_package_refuses_messages(self, pair):
        alice, bob = pair
        with pytest.raises(UnexpectedMessageType):
            bob.open_package("Alice", alice.encrypt("Bob", "text"))

    def test_encrypt_message_reports_type(self, pair):
        alice, _ = pair
        assert alice.encrypt_message("Bob", "x", type=130).type == 130
