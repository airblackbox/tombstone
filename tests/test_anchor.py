"""External anchoring: a rewritten history is caught against an anchor, and
the Rekor client speaks the real hashedrekord API shape (tested against a
fake that stores and returns entries exactly as rekor.sigstore.dev does)."""
import base64
import hashlib
import json
from pathlib import Path

import pytest

from tombstone import Vault, Ledger, LocalAnchor, RekorAnchor, AnchorError
from tombstone.anchor import statement_bytes


class FakeRekor:
    """In-memory stand-in for rekor.sigstore.dev's /api/v1/log/entries."""

    def __init__(self):
        self.entries = {}
        self.calls = []

    def __call__(self, method, url, body):
        self.calls.append((method, url))
        if method == "POST" and url.endswith("/api/v1/log/entries"):
            entry = json.loads(body)
            assert entry["kind"] == "hashedrekord"
            assert entry["spec"]["data"]["hash"]["algorithm"] == "sha256"
            uuid = hashlib.sha256(body).hexdigest()
            record = {
                "body": base64.b64encode(json.dumps(entry).encode()).decode(),
                "integratedTime": 1700000000,
                "logID": "c0d23d6ad406973f9559f3ba2d1ca01f84147d8ffc5b8445c224f98b9591801d",
                "logIndex": 100 + len(self.entries),
                "verification": {"signedEntryTimestamp": "MEUC..."},
            }
            self.entries[uuid] = record
            return 201, json.dumps({uuid: record}).encode()
        if method == "GET" and "/api/v1/log/entries/" in url:
            uuid = url.rsplit("/", 1)[1]
            if uuid not in self.entries:
                return 404, b'{"code":404,"message":"entry not found"}'
            return 200, json.dumps({uuid: self.entries[uuid]}).encode()
        return 500, b"unexpected"


def _ledger_with(tmp_path, n=4):
    ledger = Ledger(str(tmp_path / "l.jsonl"))
    for i in range(n):
        ledger.append("s", "record", f"c{i}")
    return ledger


def _rewrite_entry(ledger, index, field, value):
    lines = ledger.path.read_text().splitlines()
    e = json.loads(lines[index]); e[field] = value; lines[index] = json.dumps(e)
    ledger.path.write_text("\n".join(lines) + "\n")


# ---- local anchor -----------------------------------------------------------

def test_local_anchor_roundtrip_and_growth(tmp_path):
    ledger = _ledger_with(tmp_path)
    anchor = LocalAnchor(str(tmp_path / "anchors"))
    receipt = ledger.anchor(anchor)
    assert receipt["size"] == 4
    assert receipt["anchor"]["independent"] is False
    ledger.append("s", "record", "later")           # growth is fine
    ok, msg = ledger.check_anchor(receipt, anchor)
    assert ok, msg


def test_anchor_catches_rewritten_history_even_if_rechained(tmp_path):
    """An operator with the HMAC secret rewrites entry 1 and re-chains
    everything after it, so verify() passes. The anchor still catches it."""
    ledger = _ledger_with(tmp_path)
    anchor = LocalAnchor(str(tmp_path / "anchors"))
    receipt = ledger.anchor(anchor)

    # Rebuild the log from scratch with one entry changed and valid hashes.
    entries = ledger._entries()
    entries[1]["data_commitment"] = "attacker-changed-this"
    forged = Ledger(str(tmp_path / "forged.jsonl"))
    for e in entries:
        forged.append(e["subject_id"], e["event_type"], e["data_commitment"])
    assert forged.verify()[0] is True                # the local chain is fooled

    ok, msg = forged.check_anchor(receipt, anchor)
    assert ok is False
    assert "rewritten" in msg


def test_check_anchor_rejects_receipt_larger_than_log(tmp_path):
    ledger = _ledger_with(tmp_path)
    anchor = LocalAnchor(str(tmp_path / "anchors"))
    receipt = ledger.anchor(anchor)
    receipt["size"] = 99
    ok, msg = ledger.check_anchor(receipt, anchor)
    assert ok is False and "99" in msg


# ---- rekor anchor -----------------------------------------------------------

def test_rekor_anchor_publishes_and_verifies(tmp_path):
    fake = FakeRekor()
    anchor = RekorAnchor(key_path=str(tmp_path / "k.pem"), transport=fake)
    ledger = _ledger_with(tmp_path)
    receipt = ledger.anchor(anchor)

    a = receipt["anchor"]
    assert a["provider"] == "rekor" and a["independent"] is True
    assert a["log_index"] == 100
    assert a["lookup"].endswith("logIndex=100")
    assert a["statement_sha256"] == hashlib.sha256(
        statement_bytes(receipt["size"], receipt["root"])).hexdigest()

    ok, msg = ledger.check_anchor(receipt, anchor)
    assert ok, msg
    assert "log index 100" in msg
    assert [m for m, _ in fake.calls] == ["POST", "GET"]


def test_rekor_key_is_private_and_reused(tmp_path):
    key = tmp_path / "k.pem"
    a1 = RekorAnchor(key_path=str(key), transport=FakeRekor())
    assert oct(key.stat().st_mode)[-3:] == "600"
    a2 = RekorAnchor(key_path=str(key), transport=FakeRekor())
    assert a1.public_key_pem() == a2.public_key_pem()


def test_rekor_detects_tampered_entry_on_lookup(tmp_path):
    fake = FakeRekor()
    anchor = RekorAnchor(key_path=str(tmp_path / "k.pem"), transport=fake)
    ledger = _ledger_with(tmp_path)
    receipt = ledger.anchor(anchor)
    # Someone swaps the published entry for one committing to a different root.
    uuid = receipt["anchor"]["uuid"]
    body = json.loads(base64.b64decode(fake.entries[uuid]["body"]))
    body["spec"]["data"]["hash"]["value"] = "00" * 32
    fake.entries[uuid]["body"] = base64.b64encode(json.dumps(body).encode()).decode()
    ok, msg = ledger.check_anchor(receipt, anchor)
    assert ok is False and "different statement" in msg


def test_rekor_refusal_raises_anchor_error(tmp_path):
    def refusing(method, url, body):
        return 400, b'{"code":400,"message":"bad entry"}'
    anchor = RekorAnchor(key_path=str(tmp_path / "k.pem"), transport=refusing)
    ledger = _ledger_with(tmp_path)
    with pytest.raises(AnchorError):
        ledger.anchor(anchor)


# ---- erasure certificate ----------------------------------------------------

def test_erasure_certificate_with_anchor(tmp_path):
    v = Vault(str(tmp_path / "data"))
    ref = v.record("jose", "Jose Rios, jose@example.com", location="users")
    v.record("ana", "Ana, ana@example.com", location="users")
    v.erase("jose")

    fake = FakeRekor()
    anchor = RekorAnchor(key_path=str(tmp_path / "k.pem"), transport=fake)
    cert = v.erasure_certificate("jose", anchor=anchor)

    assert cert["erased"] is True
    assert cert["proof"]["key_present"] is False
    assert Ledger.check_inclusion(cert["inclusion"]) is True    # no log needed
    assert cert["anchor"]["anchor"]["log_index"] == 100
    # The certificate itself never carries the person's data.
    assert "jose@example.com" not in json.dumps(cert)

    ok, msg = v.check_erasure_certificate(cert, anchor)
    assert ok, msg

    # More activity later does not invalidate the certificate.
    v.record("ana", "Ana again", location="users")
    ok, msg = v.check_erasure_certificate(cert, anchor)
    assert ok, msg


def test_erasure_certificate_requires_an_erase_event(tmp_path):
    v = Vault(str(tmp_path / "data"))
    v.record("jose", "Jose Rios", location="users")
    with pytest.raises(ValueError):
        v.erasure_certificate("jose")


def test_erasure_certificate_fails_if_history_rewritten(tmp_path):
    v = Vault(str(tmp_path / "data"))
    v.record("jose", "Jose Rios", location="users")
    v.erase("jose")
    cert = v.erasure_certificate("jose")
    _rewrite_entry(v.ledger, 0, "subject_id", "attacker")
    ok, msg = v.check_erasure_certificate(cert)
    assert ok is False
