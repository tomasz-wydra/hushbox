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

from hushbox_core import EncryptionManager, ContactInfo


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

    def test_update_existing_contact_key(self, manager, bob, alice):
        manager.add_contact("Bob", bob.export_public_key())
        new_key = alice.export_public_key()
        manager.add_contact("Bob", new_key)
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
