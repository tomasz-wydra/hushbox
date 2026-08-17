"""
Testy jednostkowe dla EncryptionManager.

Uruchomienie:
    pytest tests/ -v
"""
import pytest
import tempfile
import os
from pathlib import Path
from nacl.public import PrivateKey
from nacl.encoding import Base64Encoder

from hushbox_core import (
    EncryptionManager,
    ContactInfo,
    DecryptionError,
    FingerprintMismatch,
    InvalidCiphertextFormat,
    InvalidPassphrase,
    KeyConflictError,
    PassphraseRequired,
    fingerprint_for_pubkey,
    keyfile,
)


# ─────────────────────────────────────────────────────────────────
# Fixtures
# ─────────────────────────────────────────────────────────────────

@pytest.fixture
def tmp_dir(tmp_path):
    """Tymczasowy katalog dla każdego testu."""
    return str(tmp_path)


@pytest.fixture
def manager(tmp_dir):
    """EncryptionManager z czystym tymczasowym katalogiem."""
    return EncryptionManager(data_dir=tmp_dir)


@pytest.fixture
def alice(tmp_path):
    return EncryptionManager(data_dir=str(tmp_path / "alice"))


@pytest.fixture
def bob(tmp_path):
    return EncryptionManager(data_dir=str(tmp_path / "bob"))


# ─────────────────────────────────────────────────────────────────
# Klucze własne
# ─────────────────────────────────────────────────────────────────

class TestKeyManagement:

    def test_generates_private_key_on_first_run(self, tmp_dir):
        key_path = Path(tmp_dir) / "my_private_key.bin"
        assert not key_path.exists()
        EncryptionManager(data_dir=tmp_dir)
        assert key_path.exists()

    def test_loads_existing_private_key(self, tmp_dir):
        mgr1 = EncryptionManager(data_dir=tmp_dir)
        key1 = mgr1.export_public_key()
        mgr2 = EncryptionManager(data_dir=tmp_dir)
        key2 = mgr2.export_public_key()
        assert key1 == key2, "Ta sama instancja powinna mieć ten sam klucz po ponownym ładowaniu."

    def test_export_public_key_returns_base64_string(self, manager):
        pub = manager.export_public_key()
        assert isinstance(pub, str)
        assert len(pub) > 0
        # Sprawdzamy, że to prawidłowy base64 klucz (32 bajty)
        raw = bytes.fromhex(
            PrivateKey.generate().public_key.encode(encoder=Base64Encoder).decode()  # tylko format
            and pub  # używamy pub
            and bytes.__new__(bytes)  # dummy, poniżej prawdziwy test
        ) if False else None
        decoded = PublicKey_from_b64(pub)
        assert decoded is not None

    def test_different_instances_have_different_keys(self, tmp_path):
        mgr1 = EncryptionManager(data_dir=str(tmp_path / "a"))
        mgr2 = EncryptionManager(data_dir=str(tmp_path / "b"))
        assert mgr1.export_public_key() != mgr2.export_public_key()


def PublicKey_from_b64(b64: str):
    """Helper: parsuj klucz publiczny base64, zwróć obiekt lub rzuć."""
    from nacl.public import PublicKey
    from nacl.encoding import Base64Encoder
    return PublicKey(b64.encode(), encoder=Base64Encoder)


# ─────────────────────────────────────────────────────────────────
# Kontakty
# ─────────────────────────────────────────────────────────────────

class TestContacts:

    def test_add_contact(self, manager, bob):
        manager.add_contact("Bob", bob.export_public_key())
        assert manager.has_contact("Bob")

    def test_add_contact_persists(self, tmp_dir, bob):
        mgr1 = EncryptionManager(data_dir=tmp_dir)
        mgr1.add_contact("Bob", bob.export_public_key())
        mgr2 = EncryptionManager(data_dir=tmp_dir)
        assert mgr2.has_contact("Bob")

    def test_add_contact_invalid_key_raises(self, manager):
        with pytest.raises(Exception):
            manager.add_contact("Bob", "to-nie-jest-klucz-base64!!!")

    def test_add_contact_empty_name_raises(self, manager, bob):
        with pytest.raises(ValueError):
            manager.add_contact("", bob.export_public_key())

    def test_add_contact_whitespace_name_raises(self, manager, bob):
        with pytest.raises(ValueError):
            manager.add_contact("   ", bob.export_public_key())

    def test_remove_contact(self, manager, bob):
        manager.add_contact("Bob", bob.export_public_key())
        manager.remove_contact("Bob")
        assert not manager.has_contact("Bob")

    def test_remove_nonexistent_contact_raises(self, manager):
        with pytest.raises(KeyError):
            manager.remove_contact("NieIstnieje")

    def test_rename_contact(self, manager, bob):
        manager.add_contact("Bob", bob.export_public_key())
        manager.rename_contact("Bob", "Robert")
        assert manager.has_contact("Robert")
        assert not manager.has_contact("Bob")

    def test_rename_contact_preserves_key(self, manager, bob):
        key = bob.export_public_key()
        manager.add_contact("Bob", key)
        manager.rename_contact("Bob", "Robert")
        assert manager.contact_keys["Robert"] == key

    def test_rename_nonexistent_raises(self, manager):
        with pytest.raises(KeyError):
            manager.rename_contact("NieIstnieje", "Cokolwiek")

    def test_rename_to_empty_raises(self, manager, bob):
        manager.add_contact("Bob", bob.export_public_key())
        with pytest.raises(ValueError):
            manager.rename_contact("Bob", "")

    def test_list_contacts_sorted(self, manager, bob, alice):
        manager.add_contact("Zenek", bob.export_public_key())
        manager.add_contact("Anna",  alice.export_public_key())
        assert manager.list_contacts() == ["Anna", "Zenek"]

    def test_list_contacts_empty(self, manager):
        assert manager.list_contacts() == []

    def test_readding_same_key_is_idempotent(self, manager, bob):
        """Ponowne dodanie tego samego klucza to nie zmiana klucza."""
        key = bob.export_public_key()
        manager.add_contact("Bob", key)
        manager.add_contact("Bob", key, relay_url="https://relay.example")
        assert manager.contact_keys["Bob"] == key
        assert manager.get_contact("Bob").relay_url == "https://relay.example"

    def test_silent_key_substitution_is_rejected(self, manager, bob, alice):
        """TOFU: podmiana klucza istniejącego kontaktu wymaga zgody."""
        manager.add_contact("Bob", bob.export_public_key())
        with pytest.raises(KeyConflictError):
            manager.add_contact("Bob", alice.export_public_key())
        # klucz musi pozostać nietknięty
        assert manager.contact_keys["Bob"] == bob.export_public_key()

    def test_key_conflict_carries_both_fingerprints(self, manager, bob, alice):
        manager.add_contact("Bob", bob.export_public_key())
        with pytest.raises(KeyConflictError) as exc:
            manager.add_contact("Bob", alice.export_public_key())
        assert exc.value.old_fingerprint == fingerprint_for_pubkey(bob.export_public_key())
        assert exc.value.new_fingerprint == fingerprint_for_pubkey(alice.export_public_key())

    def test_update_existing_contact_key_with_consent(self, manager, bob, alice):
        manager.add_contact("Bob", bob.export_public_key())
        new_key = alice.export_public_key()
        manager.add_contact("Bob", new_key, allow_key_change=True)
        assert manager.contact_keys["Bob"] == new_key


# ─────────────────────────────────────────────────────────────────
# Szyfrowanie / Deszyfrowanie
# ─────────────────────────────────────────────────────────────────

class TestEncryption:

    def test_encrypt_returns_string(self, alice, bob):
        alice.add_contact("Bob", bob.export_public_key())
        result = alice.encrypt("Bob", "Cześć!")
        assert isinstance(result, str)
        assert len(result) > 0

    def test_encrypt_decrypt_roundtrip(self, alice, bob):
        """Alice szyfruje dla Boba, Bob odszyfrowuje od Alice."""
        alice.add_contact("Bob", bob.export_public_key())
        bob.add_contact("Alice", alice.export_public_key())

        plaintext = "Tajna wiadomość 123 !@#"
        cipher = alice.encrypt("Bob", plaintext)
        result = bob.decrypt("Alice", cipher)
        assert result == plaintext

    def test_encrypt_decrypt_unicode(self, alice, bob):
        alice.add_contact("Bob", bob.export_public_key())
        bob.add_contact("Alice", alice.export_public_key())
        plaintext = "Zażółć gęślą jaźń 🔐"
        cipher = alice.encrypt("Bob", plaintext)
        assert bob.decrypt("Alice", cipher) == plaintext

    def test_encrypt_decrypt_long_message(self, alice, bob):
        alice.add_contact("Bob", bob.export_public_key())
        bob.add_contact("Alice", alice.export_public_key())
        plaintext = "A" * 10_000
        cipher = alice.encrypt("Bob", plaintext)
        assert bob.decrypt("Alice", cipher) == plaintext

    def test_different_encryptions_of_same_plaintext(self, alice, bob):
        """NaCl Box używa losowego nonce - każde szyfrowanie jest inne."""
        alice.add_contact("Bob", bob.export_public_key())
        plaintext = "test"
        c1 = alice.encrypt("Bob", plaintext)
        c2 = alice.encrypt("Bob", plaintext)
        assert c1 != c2

    def test_decrypt_with_whitespace_ciphertext(self, alice, bob):
        """Deszyfrowanie powinno tolerować białe znaki wokół ciphertext."""
        alice.add_contact("Bob", bob.export_public_key())
        bob.add_contact("Alice", alice.export_public_key())
        plaintext = "hello"
        cipher = alice.encrypt("Bob", plaintext)
        assert bob.decrypt("Alice", f"  {cipher}  ") == plaintext

    def test_encrypt_unknown_contact_raises(self, alice):
        with pytest.raises(KeyError):
            alice.encrypt("NieIstnieje", "test")

    def test_decrypt_unknown_contact_raises(self, alice):
        with pytest.raises(KeyError):
            alice.decrypt("NieIstnieje", "dummycipher")

    def test_decrypt_wrong_sender_raises(self, alice, bob, tmp_path):
        """Odszyfrowanie kluczem złego nadawcy powinno rzucić wyjątek."""
        alice.add_contact("Bob", bob.export_public_key())
        bob.add_contact("Alice", alice.export_public_key())
        eve = EncryptionManager(data_dir=str(tmp_path / "eve"))
        bob.add_contact("Eve", eve.export_public_key())

        cipher = alice.encrypt("Bob", "tajne")
        with pytest.raises(Exception):
            bob.decrypt("Eve", cipher)   # Eve nie jest nadawcą

    def test_tampered_ciphertext_raises(self, alice, bob):
        alice.add_contact("Bob", bob.export_public_key())
        bob.add_contact("Alice", alice.export_public_key())
        cipher = alice.encrypt("Bob", "test")
        tampered = cipher[:-4] + "XXXX"
        with pytest.raises(Exception):
            bob.decrypt("Alice", tampered)


# ─────────────────────────────────────────────────────────────────
# Ochrona klucza prywatnego hasłem (Argon2id)
# ─────────────────────────────────────────────────────────────────

class TestPrivateKeyAtRest:

    def test_legacy_plaintext_key_still_loads(self, tmp_dir):
        """Instalacje przed Argon2id muszą działać bez migracji."""
        mgr1 = EncryptionManager(data_dir=tmp_dir)
        assert not mgr1.is_key_encrypted()
        pub = mgr1.export_public_key()
        assert EncryptionManager(data_dir=tmp_dir).export_public_key() == pub

    def test_key_file_has_owner_only_permissions(self, tmp_dir):
        EncryptionManager(data_dir=tmp_dir)
        path = Path(tmp_dir) / "my_private_key.bin"
        assert (path.stat().st_mode & 0o777) == 0o600

    def test_new_key_is_sealed_when_passphrase_given(self, tmp_dir):
        mgr = EncryptionManager(data_dir=tmp_dir, passphrase="correct horse battery")
        assert mgr.is_key_encrypted()
        raw = (Path(tmp_dir) / "my_private_key.bin").read_bytes()
        assert raw.startswith(keyfile.MAGIC)
        # surowy klucz nie może być obecny w pliku
        assert bytes(mgr.private_key) not in raw

    def test_sealed_key_roundtrip(self, tmp_dir):
        mgr1 = EncryptionManager(data_dir=tmp_dir, passphrase="hunter2hunter2")
        pub = mgr1.export_public_key()
        mgr2 = EncryptionManager(data_dir=tmp_dir, passphrase="hunter2hunter2")
        assert mgr2.export_public_key() == pub

    def test_wrong_passphrase_raises(self, tmp_dir):
        EncryptionManager(data_dir=tmp_dir, passphrase="prawidlowe-haslo")
        with pytest.raises(InvalidPassphrase):
            EncryptionManager(data_dir=tmp_dir, passphrase="zle-haslo")

    def test_missing_passphrase_raises(self, tmp_dir):
        EncryptionManager(data_dir=tmp_dir, passphrase="prawidlowe-haslo")
        with pytest.raises(PassphraseRequired):
            EncryptionManager(data_dir=tmp_dir)

    def test_path_is_encrypted_without_passphrase(self, tmp_dir):
        path = Path(tmp_dir) / "my_private_key.bin"
        assert not keyfile.path_is_encrypted(path)   # plik nie istnieje
        EncryptionManager(data_dir=tmp_dir, passphrase="x" * 12)
        assert keyfile.path_is_encrypted(path)

    def test_migrate_legacy_key_to_passphrase(self, tmp_dir):
        """set_passphrase() migruje istniejący plik legacy bez utraty tożsamości."""
        mgr = EncryptionManager(data_dir=tmp_dir)
        pub = mgr.export_public_key()
        mgr.set_passphrase("nowe-dlugie-haslo")
        assert mgr.is_key_encrypted()
        reopened = EncryptionManager(data_dir=tmp_dir, passphrase="nowe-dlugie-haslo")
        assert reopened.export_public_key() == pub

    def test_change_passphrase(self, tmp_dir):
        mgr = EncryptionManager(data_dir=tmp_dir, passphrase="stare-haslo")
        pub = mgr.export_public_key()
        mgr.set_passphrase("zupelnie-nowe-haslo")
        with pytest.raises(InvalidPassphrase):
            EncryptionManager(data_dir=tmp_dir, passphrase="stare-haslo")
        assert EncryptionManager(
            data_dir=tmp_dir, passphrase="zupelnie-nowe-haslo"
        ).export_public_key() == pub

    def test_remove_passphrase(self, tmp_dir):
        mgr = EncryptionManager(data_dir=tmp_dir, passphrase="haslo-do-usuniecia")
        pub = mgr.export_public_key()
        mgr.remove_passphrase()
        assert not mgr.is_key_encrypted()
        assert EncryptionManager(data_dir=tmp_dir).export_public_key() == pub

    def test_empty_passphrase_rejected(self, tmp_dir):
        mgr = EncryptionManager(data_dir=tmp_dir)
        with pytest.raises(ValueError):
            mgr.set_passphrase("")

    def test_truncated_sealed_file_raises(self, tmp_dir):
        EncryptionManager(data_dir=tmp_dir, passphrase="haslo-testowe")
        path = Path(tmp_dir) / "my_private_key.bin"
        path.write_bytes(path.read_bytes()[:20])
        with pytest.raises(Exception):
            EncryptionManager(data_dir=tmp_dir, passphrase="haslo-testowe")

    def test_kdf_params_are_read_from_header(self, tmp_dir):
        """Parametry KDF z nagłówka, nie z hardkodu — pozwala je podnosić."""
        from nacl.pwhash import argon2id
        raw = bytes(PrivateKey.generate())
        sealed = keyfile.seal(
            raw, "haslo",
            opslimit=argon2id.OPSLIMIT_INTERACTIVE,
            memlimit=argon2id.MEMLIMIT_INTERACTIVE,
        )
        assert keyfile.unseal(sealed, "haslo") == raw


# ─────────────────────────────────────────────────────────────────
# Fingerprint / TOFU
# ─────────────────────────────────────────────────────────────────

class TestFingerprintVerification:

    def test_fingerprint_is_stable(self, bob):
        key = bob.export_public_key()
        assert fingerprint_for_pubkey(key) == fingerprint_for_pubkey(key)

    def test_fingerprint_differs_per_key(self, alice, bob):
        assert fingerprint_for_pubkey(alice.export_public_key()) != \
               fingerprint_for_pubkey(bob.export_public_key())

    def test_fingerprint_is_over_raw_bytes_not_base64(self, bob):
        """Fingerprint liczymy nad materiałem klucza, pubkey_hash nad base64."""
        import hashlib
        from nacl.public import PublicKey
        key_b64 = bob.export_public_key()
        raw = bytes(PublicKey(key_b64.encode(), encoder=Base64Encoder))
        expected = hashlib.sha256(raw).hexdigest().lower()
        info = ContactInfo(public_key=key_b64)
        assert "".join(info.fingerprint.split()).lower() == expected
        # a to jest inna wartość — identyfikator skrzynki na relayu
        assert info.pubkey_hash != expected

    def test_new_contact_is_unverified(self, manager, bob):
        manager.add_contact("Bob", bob.export_public_key())
        assert manager.is_verified("Bob") is False

    def test_verify_contact_with_correct_fingerprint(self, manager, bob):
        manager.add_contact("Bob", bob.export_public_key())
        manager.verify_contact("Bob", manager.fingerprint("Bob"))
        assert manager.is_verified("Bob") is True

    def test_verify_accepts_user_typed_formatting(self, manager, bob):
        """Użytkownik wkleja fingerprint bez spacji / małymi literami."""
        manager.add_contact("Bob", bob.export_public_key())
        messy = manager.fingerprint("Bob").replace(" ", "").lower()
        manager.verify_contact("Bob", messy)
        assert manager.is_verified("Bob") is True

    def test_verify_contact_with_wrong_fingerprint_raises(self, manager, bob, alice):
        manager.add_contact("Bob", bob.export_public_key())
        with pytest.raises(FingerprintMismatch):
            manager.verify_contact("Bob", fingerprint_for_pubkey(alice.export_public_key()))
        assert manager.is_verified("Bob") is False

    def test_verify_empty_fingerprint_raises(self, manager, bob):
        manager.add_contact("Bob", bob.export_public_key())
        with pytest.raises(ValueError):
            manager.verify_contact("Bob", "   ")

    def test_verification_persists(self, tmp_dir, bob):
        mgr1 = EncryptionManager(data_dir=tmp_dir)
        mgr1.add_contact("Bob", bob.export_public_key())
        mgr1.verify_contact("Bob", mgr1.fingerprint("Bob"))
        assert EncryptionManager(data_dir=tmp_dir).is_verified("Bob") is True

    def test_key_change_resets_verification(self, manager, bob, alice):
        """Weryfikacja dotyczy klucza — po jego zmianie musi wygasnąć."""
        manager.add_contact("Bob", bob.export_public_key())
        manager.verify_contact("Bob", manager.fingerprint("Bob"))
        manager.add_contact("Bob", alice.export_public_key(), allow_key_change=True)
        assert manager.is_verified("Bob") is False

    def test_relay_url_update_keeps_verification(self, manager, bob):
        manager.add_contact("Bob", bob.export_public_key())
        manager.verify_contact("Bob", manager.fingerprint("Bob"))
        manager.add_contact("Bob", bob.export_public_key(), relay_url="https://r.example")
        assert manager.is_verified("Bob") is True

    def test_unverify_contact(self, manager, bob):
        manager.add_contact("Bob", bob.export_public_key())
        manager.verify_contact("Bob", manager.fingerprint("Bob"))
        manager.unverify_contact("Bob")
        assert manager.is_verified("Bob") is False

    def test_legacy_contacts_json_defaults_to_unverified(self, tmp_dir, bob):
        """Kontakty zapisane przed TOFU nie mogą udawać zweryfikowanych."""
        import json
        path = Path(tmp_dir) / "contact_keys.json"
        path.write_text(json.dumps({"Bob": {"public_key": bob.export_public_key()}}))
        assert EncryptionManager(data_dir=tmp_dir).is_verified("Bob") is False

    def test_legacy_plain_string_contact_format(self, tmp_dir, bob):
        import json
        path = Path(tmp_dir) / "contact_keys.json"
        path.write_text(json.dumps({"Bob": bob.export_public_key()}))
        mgr = EncryptionManager(data_dir=tmp_dir)
        assert mgr.has_contact("Bob")
        assert mgr.is_verified("Bob") is False

    def test_my_fingerprint_matches_contact_view(self, alice, bob):
        """Fingerprint u mnie i u rozmówcy musi być identyczny."""
        bob.add_contact("Alice", alice.export_public_key())
        assert bob.fingerprint("Alice") == alice.my_fingerprint()


# ─────────────────────────────────────────────────────────────────
# Obsługa błędów deszyfrowania
# ─────────────────────────────────────────────────────────────────

class TestDecryptionErrors:

    def test_tampered_ciphertext_raises_decryption_error(self, alice, bob):
        alice.add_contact("Bob", bob.export_public_key())
        bob.add_contact("Alice", alice.export_public_key())
        cipher = alice.encrypt("Bob", "test")
        tampered = cipher[:-6] + ("A" if cipher[-6] != "A" else "B") + cipher[-5:]
        with pytest.raises(DecryptionError):
            bob.decrypt("Alice", tampered)

    def test_wrong_sender_raises_decryption_error(self, alice, bob, tmp_path):
        alice.add_contact("Bob", bob.export_public_key())
        bob.add_contact("Alice", alice.export_public_key())
        eve = EncryptionManager(data_dir=str(tmp_path / "eve2"))
        bob.add_contact("Eve", eve.export_public_key())
        cipher = alice.encrypt("Bob", "tajne")
        with pytest.raises(DecryptionError):
            bob.decrypt("Eve", cipher)

    def test_invalid_base64_raises_format_error(self, alice, bob):
        bob.add_contact("Alice", alice.export_public_key())
        with pytest.raises(InvalidCiphertextFormat):
            bob.decrypt("Alice", "to zdecydowanie nie jest base64 !!!###")

    def test_empty_ciphertext_raises_format_error(self, alice, bob):
        bob.add_contact("Alice", alice.export_public_key())
        with pytest.raises(InvalidCiphertextFormat):
            bob.decrypt("Alice", "    ")

    def test_format_error_is_subclass_of_decryption_error(self):
        """UI łapie jeden typ — DecryptionError — i to wystarcza."""
        assert issubclass(InvalidCiphertextFormat, DecryptionError)

    def test_no_nacl_exception_leaks_to_caller(self, alice, bob):
        """Żaden wyjątek PyNaCl nie może wyciec poza hushbox_core."""
        from nacl.exceptions import CryptoError
        alice.add_contact("Bob", bob.export_public_key())
        bob.add_contact("Alice", alice.export_public_key())
        cipher = alice.encrypt("Bob", "x")
        broken = cipher[:-6] + ("A" if cipher[-6] != "A" else "B") + cipher[-5:]
        try:
            bob.decrypt("Alice", broken)
        except DecryptionError:
            pass
        except CryptoError:
            pytest.fail("CryptoError z PyNaCl wyciekł do wywołującego.")

    def test_line_wrapped_ciphertext_decrypts(self, alice, bob):
        """Klienci pocztowi zawijają base64 — musimy to tolerować."""
        alice.add_contact("Bob", bob.export_public_key())
        bob.add_contact("Alice", alice.export_public_key())
        plaintext = "wiadomosc przez email " * 20
        cipher = alice.encrypt("Bob", plaintext)
        wrapped = "\n".join(cipher[i:i + 64] for i in range(0, len(cipher), 64))
        assert bob.decrypt("Alice", wrapped) == plaintext
