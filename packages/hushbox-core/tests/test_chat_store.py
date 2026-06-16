"""
Testy jednostkowe dla ChatStore.
"""
import pytest
from pathlib import Path

from hushbox_core import ChatStore, Message


@pytest.fixture
def store(tmp_path):
    return ChatStore(data_dir=str(tmp_path))


class TestMessage:
    def test_to_dict_from_dict_roundtrip(self):
        msg = Message(direction="out", plaintext="Cześć", ciphertext="abc123", timestamp="12:00:00")
        assert Message.from_dict(msg.to_dict()) == msg

    def test_default_timestamp_is_set(self):
        msg = Message(direction="in", plaintext="hi", ciphertext="xyz")
        assert msg.timestamp  # nie pusty


class TestChatStore:

    def test_load_empty_returns_empty_list(self, store):
        assert store.load("Anna") == []

    def test_add_and_load_message(self, store):
        msg = Message(direction="out", plaintext="Hej", ciphertext="abc")
        store.add_message("Anna", msg)
        loaded = store.load("Anna")
        assert len(loaded) == 1
        assert loaded[0].plaintext == "Hej"

    def test_messages_persist_across_instances(self, tmp_path):
        store1 = ChatStore(data_dir=str(tmp_path))
        msg = Message(direction="in", plaintext="Hello", ciphertext="xyz", timestamp="10:00:00")
        store1.add_message("Bob", msg)

        store2 = ChatStore(data_dir=str(tmp_path))
        loaded = store2.load("Bob")
        assert len(loaded) == 1
        assert loaded[0] == msg

    def test_multiple_messages_order(self, store):
        for i in range(5):
            store.add_message("Bob", Message(direction="out", plaintext=f"msg{i}", ciphertext=f"c{i}"))
        loaded = store.load("Bob")
        assert len(loaded) == 5
        assert [m.plaintext for m in loaded] == [f"msg{i}" for i in range(5)]

    def test_clear_history(self, store):
        store.add_message("Anna", Message(direction="out", plaintext="test", ciphertext="abc"))
        store.clear_history("Anna")
        assert store.load("Anna") == []

    def test_clear_history_removes_file(self, tmp_path):
        store = ChatStore(data_dir=str(tmp_path))
        store.add_message("Anna", Message(direction="out", plaintext="test", ciphertext="abc"))
        store.clear_history("Anna")
        assert not store._path("Anna").exists()

    def test_delete_contact_history(self, store):
        store.add_message("Anna", Message(direction="out", plaintext="test", ciphertext="abc"))
        store.delete_contact_history("Anna")
        assert store.load("Anna") == []

    def test_separate_histories_per_contact(self, store):
        store.add_message("Anna", Message(direction="out", plaintext="do Anny", ciphertext="a"))
        store.add_message("Bob",  Message(direction="in",  plaintext="od Boba",  ciphertext="b"))
        assert store.load("Anna")[0].plaintext == "do Anny"
        assert store.load("Bob")[0].plaintext  == "od Boba"

    def test_contact_name_with_special_chars(self, store):
        """Nazwy kontaktów ze spacjami i polskimi znakami powinny działać."""
        store.add_message("Żaneta Łęczyca", Message(direction="out", plaintext="hi", ciphertext="c"))
        loaded = store.load("Żaneta Łęczyca")
        assert len(loaded) == 1
