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
        return True, f"chain intact ({len(entries)} entries verified)"

    def events_for(self, subject_id: str) -> list[dict]:
        """All ledger entries about one subject (useful for proving erasure)."""
        return [e for e in self._entries() if e["subject_id"] == subject_id]
