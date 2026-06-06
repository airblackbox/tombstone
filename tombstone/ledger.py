"""
ledger.py

The tamper-evident ledger. This is an append-only log where each entry
is chained to the one before it with a hash, so if anyone alters an old
entry, every entry after it breaks and verification fails.

The critical privacy rule: PERSONAL DATA NEVER GOES IN THE LEDGER.
The ledger only stores a *commitment* (a SHA-256 hash) to the data, plus
metadata like which subject and what kind of event. The actual personal
data lives elsewhere, encrypted. This is what lets the ledger stay
permanent and tamper-evident while still honoring "delete me": we can
erase the data (by destroying its key) without ever touching the log.

Each entry links to the previous via prev_hash, forming a chain. The
entry_hash of entry N is computed over its own contents AND the
prev_hash, so the chain is only valid if every link is intact.
"""

import json
import hashlib
import time
from pathlib import Path


def _hash(data: bytes) -> str:
    """SHA-256 of some bytes, as a hex string. Our commitment primitive."""
    return hashlib.sha256(data).hexdigest()


class Ledger:
    """An append-only, hash-chained log stored as one JSON-lines file."""

    # The very first entry links to this fixed value (the "genesis" link).
    GENESIS = "0" * 64

    def __init__(self, path: str = "tombstone_ledger.jsonl"):
        self.path = Path(path)
        if not self.path.exists():
            self.path.write_text("")
        # Tamper-proof HEAD: defends against truncation. The head records the
        # chain's length and tip hash, authenticated with HMAC under a secret
        # key. An attacker who chops entries off the log cannot produce a
        # matching head without the secret, so verify() catches the missing
        # entries. The secret lives beside the ledger; in production it would
        # live in a KMS/HSM, separate from the log itself.
        self.head_path = Path(str(self.path) + ".head")
        self._secret_path = Path(str(self.path) + ".headkey")
        if not self._secret_path.exists():
            import secrets as _secrets
            self._secret_path.write_bytes(_secrets.token_bytes(32))
        self._head_secret = self._secret_path.read_bytes()

    def _entries(self) -> list[dict]:
        """Read all entries from disk, in order."""
        lines = self.path.read_text().splitlines()
        return [json.loads(line) for line in lines if line.strip()]

    def _last_hash(self) -> str:
        """The entry_hash of the most recent entry, or GENESIS if empty."""
        entries = self._entries()
        if not entries:
            return self.GENESIS
        return entries[-1]["entry_hash"]

    def _sign_head(self, length: int, tip: str) -> str:
        """HMAC over (length, tip). Only someone with the secret can forge it."""
        import hmac
        msg = f"{length}:{tip}".encode()
        return hmac.new(self._head_secret, msg, hashlib.sha256).hexdigest()

    def _write_head(self, length: int, tip: str) -> None:
        """Persist the authenticated head: how many entries and the tip hash."""
        head = {"length": length, "tip": tip, "mac": self._sign_head(length, tip)}
        self.head_path.write_text(json.dumps(head))

    def _read_head(self) -> dict | None:
        if not self.head_path.exists():
            return None
        try:
            return json.loads(self.head_path.read_text())
        except (ValueError, OSError):
            return None

    def append(self, subject_id: str, event_type: str, data_commitment: str) -> dict:
        """
        Add a new entry to the chain.

        subject_id:      who this event is about
        event_type:      e.g. "record" (data stored) or "erase" (key destroyed)
        data_commitment: a SHA-256 hash of the encrypted data, NOT the data.
                         For an erase event there is no data, so we commit to
                         a fixed marker instead.

        Returns the entry that was written.
        """
        prev_hash = self._last_hash()
        # The body is everything the entry asserts. We hash the body PLUS the
        # previous hash to chain it. Sorting keys makes the hash deterministic.
        body = {
            "index": len(self._entries()),
            "timestamp": time.time(),
            "subject_id": subject_id,
            "event_type": event_type,
            "data_commitment": data_commitment,
            "prev_hash": prev_hash,
        }
        body_bytes = json.dumps(body, sort_keys=True).encode()
        entry = dict(body)
        entry["entry_hash"] = _hash(body_bytes)

        # Append as one JSON line.
        with open(self.path, "a") as f:
            f.write(json.dumps(entry) + "\n")
        # Update the authenticated head so truncation becomes detectable.
        self._write_head(entry["index"] + 1, entry["entry_hash"])
        return entry

    def verify(self) -> tuple[bool, str]:
        """
        Walk the whole chain and confirm nothing has been tampered with.

        Returns (True, "...") if the chain is intact, or (False, reason)
        pointing at the first broken link.
        """
        entries = self._entries()
        prev_hash = self.GENESIS
        for i, entry in enumerate(entries):
            # 1. The entry must point at the previous entry's hash.
            if entry["prev_hash"] != prev_hash:
                return False, f"entry {i}: prev_hash does not match the chain"
            # 2. Recompute this entry's hash from its body and compare.
            body = {
                "index": entry["index"],
                "timestamp": entry["timestamp"],
                "subject_id": entry["subject_id"],
                "event_type": entry["event_type"],
                "data_commitment": entry["data_commitment"],
                "prev_hash": entry["prev_hash"],
            }
            body_bytes = json.dumps(body, sort_keys=True).encode()
            if _hash(body_bytes) != entry["entry_hash"]:
                return False, f"entry {i}: contents were altered (hash mismatch)"
            prev_hash = entry["entry_hash"]

        # Truncation defense: compare the actual log against the authenticated
        # head. If entries were chopped off, the recorded length/tip will not
        # match, and the attacker cannot have forged a new head without the
        # secret key.
        head = self._read_head()
        if head is not None:
            expected_mac = self._sign_head(head.get("length"), head.get("tip"))
            if head.get("mac") != expected_mac:
                return False, "head record is forged or corrupted (bad MAC)"
            if head.get("length") != len(entries):
                return False, (
                    f"truncation detected: head says {head.get('length')} entries, "
                    f"log has {len(entries)}"
                )
            actual_tip = entries[-1]["entry_hash"] if entries else self.GENESIS
            if head.get("tip") != actual_tip:
                return False, "tip mismatch: log tip does not match authenticated head"

        return True, f"chain intact ({len(entries)} entries verified)"

    def events_for(self, subject_id: str) -> list[dict]:
        """All ledger entries about one subject (useful for proving erasure)."""
        return [e for e in self._entries() if e["subject_id"] == subject_id]

    # ---- Merkle proofs (v0.6): inclusion and consistency ----

    def _leaves(self) -> list[bytes]:
        """Each entry's hash, as a Merkle leaf, in log order."""
        from .merkle import hash_leaf
        return [hash_leaf(e["entry_hash"].encode()) for e in self._entries()]

    def merkle_root(self) -> str:
        """The current Merkle root over all entries, as hex."""
        from .merkle import merkle_root
        return merkle_root(self._leaves()).hex()

    def prove_inclusion(self, index: int) -> dict:
        """
        Prove the entry at `index` is in the log, with a compact (~log2 n)
        audit path. Returns everything a verifier needs, NOT the whole log.
        """
        from .merkle import inclusion_proof
        leaves = self._leaves()
        entries = self._entries()
        proof = inclusion_proof(leaves, index)
        return {
            "index": index,
            "size": len(leaves),
            "entry_hash": entries[index]["entry_hash"],
            "proof": [h.hex() for h in proof],
            "root": self.merkle_root(),
        }

    @staticmethod
    def check_inclusion(bundle: dict) -> bool:
        """
        Verify an inclusion bundle from prove_inclusion() WITHOUT the log.
        Anyone holding only the root can confirm a single entry is included.
        """
        from .merkle import hash_leaf, verify_inclusion
        leaf = hash_leaf(bundle["entry_hash"].encode())
        proof = [bytes.fromhex(h) for h in bundle["proof"]]
        root = bytes.fromhex(bundle["root"])
        return verify_inclusion(leaf, bundle["index"], bundle["size"], proof, root)

    def prove_consistency(self, old_size: int) -> dict:
        """Prove the log only grew since it had `old_size` entries."""
        from .merkle import consistency_proof, merkle_root
        leaves = self._leaves()
        old_root = merkle_root(leaves[:old_size]).hex()
        proof = consistency_proof(leaves, old_size)
        return {
            "old_size": old_size,
            "old_root": old_root,
            "proof": [h.hex() for h in proof],
        }

    def check_consistency(self, bundle: dict) -> bool:
        """Verify a consistency bundle against the current log."""
        from .merkle import verify_consistency
        leaves = self._leaves()
        old_root = bytes.fromhex(bundle["old_root"])
        proof = [bytes.fromhex(h) for h in bundle["proof"]]
        return verify_consistency(old_root, bundle["old_size"], leaves, proof)
