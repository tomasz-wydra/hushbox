"""Tests for the Ed25519 signing key derived from the X25519 identity."""
import base64

import pytest
from nacl.public import PrivateKey
from nacl.signing import SigningKey

from hushbox_core import EncryptionManager, HushboxError, SignatureError, signing


@pytest.fixture
def sk():
    return PrivateKey.generate()


# ─────────────────────────────────────────────────────────────────
# Derivation
# ─────────────────────────────────────────────────────────────────

class TestDerivation:

    def test_deterministic(self, sk):
        assert bytes(signing.derive_signing_key(sk)) == bytes(signing.derive_signing_key(bytes(sk)))

    def test_differs_per_identity(self, sk):
        other = PrivateKey.generate()
        assert bytes(signing.derive_signing_key(sk)) != bytes(signing.derive_signing_key(other))

    def test_not_the_x25519_key_itself(self, sk):
        derived = signing.derive_signing_key(sk)
        assert bytes(derived) != bytes(sk)
        assert bytes(derived.verify_key) != bytes(sk.public_key)

    def test_known_answer(self):
        """Pins the derivation: changing it would change every signing key."""
        derived = signing.derive_signing_key(bytes(range(32)))
        assert signing.encode_verify_key(derived.verify_key) == KNOWN_VERIFY_KEY

    def test_matches_an_independent_blake2b(self, sk):
        """Other clients can reimplement it with any standard BLAKE2b."""
        import hashlib
        seed = hashlib.blake2b(b"signing-key/v1", digest_size=32, key=bytes(sk),
                               person=b"hushbox:ed25519:").digest()
        assert bytes(signing.derive_signing_key(sk)) == bytes(SigningKey(seed))

    def test_rejects_wrong_length(self):
        with pytest.raises(ValueError):
            signing.derive_signing_key(b"\0" * 31)


# v1 derivation for the X25519 key bytes 0x00..0x1f, pinned on purpose.
KNOWN_VERIFY_KEY = "jg5yMAWIfKyZa3F4HT2Oh1tUfhbD82TB3JXN1ydSIrQ="


# ─────────────────────────────────────────────────────────────────
# Sign / verify
# ─────────────────────────────────────────────────────────────────

class TestSignVerify:

    def test_roundtrip(self, sk):
        key = signing.derive_signing_key(sk)
        sig = signing.sign(key, "org-cert", b"payload")
        assert len(sig) == signing.SIGNATURE_SIZE
        signing.verify(key.verify_key, "org-cert", b"payload", sig)
        signing.verify(signing.encode_verify_key(key.verify_key), "org-cert", b"payload", sig)

    def test_wrong_message(self, sk):
        key = signing.derive_signing_key(sk)
        sig = signing.sign(key, "org-cert", b"payload")
        with pytest.raises(SignatureError):
            signing.verify(key.verify_key, "org-cert", b"payloaD", sig)

    def test_context_binds_the_signature(self, sk):
        """A signature for one purpose is never valid for another."""
        key = signing.derive_signing_key(sk)
        sig = signing.sign(key, "org-cert", b"payload")
        with pytest.raises(SignatureError):
            signing.verify(key.verify_key, "group-header", b"payload", sig)

    def test_context_and_message_cannot_be_shifted(self, sk):
        """Length prefix: ("ab", "c…") and ("abc", "…") sign different bytes."""
        key = signing.derive_signing_key(sk)
        sig = signing.sign(key, "ab", b"cX")
        with pytest.raises(SignatureError):
            signing.verify(key.verify_key, "abc", b"X", sig)

    def test_not_a_plain_ed25519_signature(self, sk):
        """Signatures are domain-separated from raw Ed25519 over the message."""
        key = signing.derive_signing_key(sk)
        raw = key.sign(b"payload").signature
        with pytest.raises(SignatureError):
            signing.verify(key.verify_key, "org-cert", b"payload", raw)

    def test_wrong_key(self, sk):
        sig = signing.sign(signing.derive_signing_key(sk), "c", b"m")
        other = signing.derive_signing_key(PrivateKey.generate())
        with pytest.raises(SignatureError):
            signing.verify(other.verify_key, "c", b"m", sig)

    @pytest.mark.parametrize("bad", [b"", b"\0" * 63, b"\0" * 65, "x" * 64, None])
    def test_malformed_signature(self, sk, bad):
        key = signing.derive_signing_key(sk)
        with pytest.raises(SignatureError):
            signing.verify(key.verify_key, "c", b"m", bad)

    def test_tampered_signature(self, sk):
        key = signing.derive_signing_key(sk)
        sig = bytearray(signing.sign(key, "c", b"m"))
        sig[0] ^= 1
        with pytest.raises(SignatureError):
            signing.verify(key.verify_key, "c", b"m", bytes(sig))

    @pytest.mark.parametrize("ctx", ["", "A", "with space", "ą", "x" * 65, None, b"c"])
    def test_invalid_context(self, sk, ctx):
        key = signing.derive_signing_key(sk)
        with pytest.raises(ValueError):
            signing.sign(key, ctx, b"m")

    def test_message_must_be_bytes(self, sk):
        with pytest.raises(TypeError):
            signing.sign(signing.derive_signing_key(sk), "c", "text")

    def test_empty_message(self, sk):
        key = signing.derive_signing_key(sk)
        signing.verify(key.verify_key, "c", b"", signing.sign(key, "c", b""))


class TestVerifyKeyEncoding:

    def test_roundtrip(self, sk):
        vk = signing.derive_signing_key(sk).verify_key
        assert signing.decode_verify_key(signing.encode_verify_key(vk)) == vk

    @pytest.mark.parametrize("bad", [
        "", "not base64!", base64.b64encode(b"\0" * 31).decode(), None, 5,
    ])
    def test_invalid(self, bad):
        with pytest.raises(SignatureError):
            signing.decode_verify_key(bad)

    def test_non_canonical(self, sk):
        b64 = signing.encode_verify_key(signing.derive_signing_key(sk).verify_key)
        for variant in (b64.rstrip("="), b64[:5] + "\n" + b64[5:]):
            with pytest.raises(SignatureError):
                signing.decode_verify_key(variant)

    def test_error_is_a_hushbox_error(self):
        assert issubclass(SignatureError, HushboxError)


# ─────────────────────────────────────────────────────────────────
# EncryptionManager
# ─────────────────────────────────────────────────────────────────

class TestManager:

    def test_manager_signs_with_derived_key(self, tmp_path):
        mgr = EncryptionManager(str(tmp_path))
        sig = mgr.sign("org-cert", b"x")
        signing.verify(mgr.export_signing_public_key(), "org-cert", b"x", sig)
        assert bytes(mgr.signing_key) == bytes(signing.derive_signing_key(mgr.private_key))

    def test_signing_key_is_stable_across_restarts(self, tmp_path):
        first = EncryptionManager(str(tmp_path)).export_signing_public_key()
        assert EncryptionManager(str(tmp_path)).export_signing_public_key() == first

    def test_stable_with_passphrase_and_after_migration(self, tmp_path):
        mgr = EncryptionManager(str(tmp_path))
        before = mgr.export_signing_public_key()
        mgr.set_passphrase("pw")
        assert EncryptionManager(str(tmp_path), passphrase="pw").export_signing_public_key() == before

    def test_nothing_new_on_disk(self, tmp_path):
        EncryptionManager(str(tmp_path))
        assert sorted(p.name for p in tmp_path.iterdir()) == ["my_private_key.bin"]

    def test_signing_and_encryption_keys_differ(self, tmp_path):
        mgr = EncryptionManager(str(tmp_path))
        assert mgr.export_signing_public_key() != mgr.export_public_key()

    def test_signing_key_is_a_real_ed25519_key(self, tmp_path):
        assert isinstance(EncryptionManager(str(tmp_path)).signing_key, SigningKey)
