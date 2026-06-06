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
