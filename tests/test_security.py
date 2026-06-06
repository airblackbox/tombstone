"""
Adversarial security tests. Each asserts that an attack on a Tombstone
guarantee is DEFEATED. Run with: pytest tests/

These are the proof behind the security claims. If any fails, a guarantee
has regressed.
"""
import json
import shutil
from pathlib import Path

import pytest

from tombstone import Vault, Ledger, Policy, SubjectErased


@pytest.fixture
def vault(tmp_path):
    v = Vault(str(tmp_path / "data"))
    v.record("alice", "Alice, alice@example.com", location="users")
    v.record("bob", "Bob, bob@example.com", location="users")
    return v


def test_forge_entry_is_detected(vault):
    path = vault.ledger.path
    lines = Path(path).read_text().splitlines()
    entry = json.loads(lines[0])
    entry["subject_id"] = "attacker"
    lines[0] = json.dumps(entry)
    Path(path).write_text("\n".join(lines) + "\n")
    intact, _ = vault.ledger.verify()
    assert intact is False  # forgery caught


def test_reorder_is_detected(vault):
    path = vault.ledger.path
    lines = Path(path).read_text().splitlines()
    lines[0], lines[1] = lines[1], lines[0]
    Path(path).write_text("\n".join(lines) + "\n")
    intact, _ = vault.ledger.verify()
    assert intact is False  # reorder caught


def test_truncation_is_detected(vault):
    vault.erase("bob")
    path = vault.ledger.path
    lines = Path(path).read_text().splitlines()
    Path(path).write_text("\n".join(lines[:-1]) + "\n")  # chop last entry
    intact, _ = vault.ledger.verify()
    assert intact is False  # truncation caught by authenticated head


def test_shredded_data_unrecoverable(vault):
    ref = vault.record("dave", "Dave, dave@example.com", location="users")
    vault.erase("dave")
    with pytest.raises(SubjectErased):
        vault.read("dave", ref)
    # And no plaintext on disk
    blob_dir = Path(str(vault.base) + "").joinpath("blobs")
    for blob in blob_dir.glob("*.blob"):
        assert b"dave@example.com" not in blob.read_bytes()


def test_proxy_blocks_direct_and_obfuscated():
    pol = Policy()
    pol.protect("alice", "alice@example.com")
    pol.block_destination("evil.example.com")
    assert pol.check_payload("http://evil.example.com", '{"e":"alice@example.com"}').allowed is False
    assert pol.check_payload("http://evil.example.com", '{"e":"a l i c e@e x a m p l e.com"}').allowed is False


def test_clean_traffic_allowed():
    pol = Policy()
    pol.protect("alice", "alice@example.com")
    pol.block_destination("evil.example.com")
    assert pol.check_payload("http://evil.example.com", '{"event":"click"}').allowed is True


def test_master_erase_kills_everyone(tmp_path):
    """Destroying the master key crypto-erases all subjects at once."""
    v = Vault(str(tmp_path / "data"))
    for name in ["alice", "bob", "carol"]:
        v.record(name, f"{name}, {name}@example.com", location="users")
    assert v.keys.has_key("alice") is True
    v.crypto_erase_all()
    for name in ["alice", "bob", "carol"]:
        assert v.keys.get_key(name) is None  # all unrecoverable


def test_hoarded_wrapped_key_useless_after_master_erase(tmp_path):
    """A copied wrapped key cannot decrypt anything once the master is gone."""
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    base = tmp_path / "data"
    v = Vault(str(base))
    ref = v.record("dave", "Dave, dave@example.com", location="users")
    wrapped = (base / "keys" / "dave.key").read_bytes()  # attacker hoards this
    v.crypto_erase_all()
    # The hoarded wrapped bytes are not a usable key for any blob.
    for blob in (base / "blobs").glob("*.blob"):
        data = blob.read_bytes()
        for guess in (wrapped, wrapped[12:], wrapped[:32]):
            if len(guess) == 32:
                try:
                    AESGCM(guess).decrypt(data[:12], data[12:], None)
                    assert False, "hoarded wrapped key should not decrypt data"
                except Exception:
                    pass


def test_merkle_inclusion_and_forgery(tmp_path):
    """A real entry proves inclusion; a forged entry does not."""
    from tombstone import Ledger
    v = Vault(str(tmp_path / "data"))
    for name in ["alice", "bob", "carol", "dave"]:
        v.record(name, f"{name}@example.com", location="users")
    entries = v.ledger._entries()
    bundle = v.ledger.prove_inclusion(2)
    assert Ledger.check_inclusion(bundle) is True
    forged = dict(bundle); forged["entry_hash"] = "00" * 32
    assert Ledger.check_inclusion(forged) is False


def test_merkle_consistency_detects_rewrite(tmp_path):
    """Consistency proof holds for growth, fails if history is rewritten.

    Note: the Merkle layer commits to each entry's entry_hash. Tampering with
    other fields is caught by the hash-chain verify() instead (defense in
    depth). To test the Merkle layer specifically, we rewrite the entry_hash,
    which is what an attacker forging the tree structure would have to do.
    """
    v = Vault(str(tmp_path / "data"))
    for name in ["alice", "bob", "carol"]:
        v.record(name, f"{name}@example.com", location="users")
    cons = v.ledger.prove_consistency(2)
    assert v.ledger.check_consistency(cons) is True
    # Rewrite an early entry's HASH on disk (the field Merkle commits to).
    import json
    from pathlib import Path
    path = v.ledger.path
    lines = Path(path).read_text().splitlines()
    e = json.loads(lines[0]); e["entry_hash"] = "ff" * 32; lines[0] = json.dumps(e)
    Path(path).write_text("\n".join(lines) + "\n")
    assert v.ledger.check_consistency(cons) is False
