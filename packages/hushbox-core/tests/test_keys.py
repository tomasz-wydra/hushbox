"""Public key spelling and the relay mailbox id (hushbox_core.keys)."""
import base64
import hashlib

import pytest
from nacl.public import PrivateKey

from hushbox_core import keys, pubkey_to_hash


@pytest.fixture
def pk():
    return base64.b64encode(bytes(PrivateKey.generate().public_key)).decode()


def test_canonical_key_is_returned_unchanged(pk):
    assert keys.canonical_public_key(pk) == pk
    assert keys.is_canonical_public_key(pk)


@pytest.mark.parametrize("spell", [
    lambda k: k + "\n", lambda k: "\t" + k, lambda k: k[:10] + " " + k[10:] + "\r\n",
])
def test_whitespace_is_removed_but_not_canonical(pk, spell):
    assert keys.canonical_public_key(spell(pk)) == pk
    assert not keys.is_canonical_public_key(spell(pk))


@pytest.mark.parametrize("bad", [
    "", "abc", "A" * 43, "A" * 44 + "==",
    base64.b64encode(b"\0" * 31).decode(), base64.b64encode(b"\0" * 33).decode(),
    None, 123, b"x" * 44,
])
def test_invalid_input_is_rejected(bad):
    with pytest.raises(ValueError):
        keys.canonical_public_key(bad)
    assert not keys.is_canonical_public_key(bad)


def test_junk_characters_are_rejected_for_new_input(pk):
    with pytest.raises(ValueError):
        keys.canonical_public_key(pk[:5] + "!" + pk[5:])


def test_mailbox_id_is_sha256_of_the_canonical_text(pk):
    assert keys.mailbox_id(pk) == hashlib.sha256(pk.encode()).hexdigest()
    assert pubkey_to_hash(pk) == keys.mailbox_id(pk)


def test_mailbox_id_is_the_same_for_every_decodable_spelling(pk):
    """Matches the key a Box would use (nacl's lenient decoding), so contacts
    stored by earlier versions with stray characters reach the right mailbox."""
    for spelled in (pk + "\n", " " + pk, pk[:5] + "!" + pk[5:]):
        assert keys.mailbox_id(spelled) == keys.mailbox_id(pk)
        assert keys.repair_public_key(spelled) == pk


@pytest.mark.parametrize("bad", ["", "abc", None])
def test_mailbox_id_of_a_non_key_raises(bad):
    with pytest.raises(ValueError):
        keys.mailbox_id(bad)


def test_repair_leaves_undecodable_values_alone():
    assert keys.repair_public_key("nie-klucz") == "nie-klucz"
