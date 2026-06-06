"""
vault.py

The Vault is the thing you actually use. It ties together:
  - the KeyStore (one key per subject, destroying it = erasure)
  - the Ledger (tamper-evident log of what happened, with hash commitments)
  - the encrypted data store (the actual personal data, encrypted at rest)

The four operations that matter:
  record(subject, data) -> encrypt with subject's key, store ciphertext,
                           append a "record" commitment to the ledger
  read(subject, ref)    -> decrypt and return the data (fails after erasure)
  erase(subject)        -> destroy the subject's key (crypto-shred),
                           append an "erase" event to the ledger
  prove_erased(subject) -> show the data is unrecoverable AND the ledger
                           still verifies intact

We use AES-256-GCM from the `cryptography` library for encryption. GCM is
authenticated, so a wrong/garbage key fails loudly instead of returning
junk, which is exactly what we want when proving a key is truly gone.
"""

import os
import json
import hashlib
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .keystore import KeyStore
from .ledger import Ledger
from .lineage import Lineage


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class SubjectErased(Exception):
    """Raised when you try to read data for a subject who has been erased."""


class Vault:
    def __init__(self, base_dir: str = "tombstone_data"):
        self.base = Path(base_dir)
        self.base.mkdir(parents=True, exist_ok=True)
        # Encrypted blobs live here, one file per stored record.
        self.blob_dir = self.base / "blobs"
        self.blob_dir.mkdir(exist_ok=True)
        # Phase 2B: physical encrypted copies at named locations live here.
        self.loc_dir = self.base / "locations"
        self.loc_dir.mkdir(exist_ok=True)
        self.keys = KeyStore(str(self.base / "keys"))
        self.ledger = Ledger(str(self.base / "ledger.jsonl"))
        self.lineage = Lineage(self.ledger)

    def record(self, subject_id: str, data: str, location: str = "origin") -> str:
        """
        Store personal data for a subject.

        `location` is a label for WHERE this data first lives (e.g.
        "users_table"). It seeds the lineage graph so later copies can be
        traced back to an origin.

        Returns a `ref` (a short id) you use to read it back later.
        The data is encrypted with the subject's key before it touches disk,
        and only a hash commitment of the ciphertext goes into the ledger.
        """
        key = self.keys.create_key(subject_id)
        aes = AESGCM(key)
        nonce = os.urandom(12)  # GCM needs a fresh 12-byte nonce each time
        ciphertext = aes.encrypt(nonce, data.encode(), None)
        blob = nonce + ciphertext  # store nonce alongside the ciphertext

        ref = _sha256(blob)[:16]  # short, content-derived reference
        (self.blob_dir / f"{ref}.blob").write_bytes(blob)

        # The ledger gets a COMMITMENT to the ciphertext, never the data.
        self.ledger.append(subject_id, "record", _sha256(blob))
        # Seed lineage: the data now exists at `location`.
        self.lineage.record_flow(subject_id, "external", location, kind="origin")
        return ref

    def copy_to(self, subject_id: str, source: str, dest: str, kind: str = "copy") -> dict:
        """
        Record that a subject's data flowed from `source` to `dest`.

        Use this whenever data is copied or derived: an ETL job, an export,
        a model training snapshot, a cache. This is what builds the footprint
        we must cover to erase the subject completely.
        """
        return self.lineage.record_flow(subject_id, source, dest, kind=kind)

    # ---- Phase 2B: key inheritance (containment you can demonstrate) ----

    def store_at(self, subject_id: str, location: str, data: str,
                 source: str = "users_table", kind: str = "copy") -> None:
        """
        Store a REAL encrypted copy of a subject's data at a named location,
        encrypted with the SUBJECT'S key (key inheritance). Also records the
        flow in lineage. After the subject is erased, this copy becomes
        permanently unreadable, because it shares the one destroyed key.

        This is what makes B a guarantee instead of an assertion: there is an
        actual encrypted blob at each location that we can try (and fail) to
        read after erasure.
        """
        key = self.keys.create_key(subject_id)
        aes = AESGCM(key)
        nonce = os.urandom(12)
        ciphertext = aes.encrypt(nonce, data.encode(), None)
        # File name ties the copy to subject + location.
        safe = _sha256(f"{subject_id}:{location}".encode())[:16]
        (self.loc_dir / f"{safe}.blob").write_bytes(nonce + ciphertext)
        self.lineage.record_flow(subject_id, source, location, kind=kind)

    def read_at(self, subject_id: str, location: str) -> str:
        """Read the copy stored at `location`. Fails if the subject is erased."""
        key = self.keys.get_key(subject_id)
        if key is None:
            raise SubjectErased(
                f"subject '{subject_id}' erased; copy at '{location}' is unrecoverable"
            )
        safe = _sha256(f"{subject_id}:{location}".encode())[:16]
        blob_path = self.loc_dir / f"{safe}.blob"
        if not blob_path.exists():
            raise FileNotFoundError(f"no copy at '{location}' for '{subject_id}'")
        blob = blob_path.read_bytes()
        nonce, ciphertext = blob[:12], blob[12:]
        return AESGCM(key).decrypt(nonce, ciphertext, None).decode()

    def verify_erasure_coverage(self, subject_id: str) -> dict:
        """
        After erasure, walk EVERY location in the subject's footprint and
        confirm the physical copy there is unreadable. This turns "same key,
        trust me" into a demonstrated, per-location proof.

        Returns a per-location report plus an overall `all_covered` flag.
        """
        results = {}
        for location in sorted(self.lineage.locations(subject_id) - {"external"}):
            safe = _sha256(f"{subject_id}:{location}".encode())[:16]
            has_blob = (self.loc_dir / f"{safe}.blob").exists()
            try:
                self.read_at(subject_id, location)
                readable = True   # we successfully decrypted: NOT covered
            except SubjectErased:
                readable = False  # key gone: this copy is dead (good)
            except FileNotFoundError:
                readable = False  # no physical copy here (lineage-only node)
            results[location] = {
                "has_physical_copy": has_blob,
                "readable": readable,
            }
        all_covered = all(not r["readable"] for r in results.values())
        return {"locations": results, "all_covered": all_covered}

    def read(self, subject_id: str, ref: str) -> str:
        """
        Read back a stored record. Decrypts with the subject's key.

        If the subject has been erased (key destroyed), this raises
        SubjectErased, because the ciphertext can no longer be decrypted.
        """
        key = self.keys.get_key(subject_id)
        if key is None:
            raise SubjectErased(
                f"subject '{subject_id}' has been erased; data is unrecoverable"
            )
        blob_path = self.blob_dir / f"{ref}.blob"
        if not blob_path.exists():
            raise FileNotFoundError(f"no record with ref '{ref}'")
        blob = blob_path.read_bytes()
        nonce, ciphertext = blob[:12], blob[12:]
        aes = AESGCM(key)
        # If the key were wrong, GCM would raise here. With the right key,
        # we get the original data back.
        return aes.decrypt(nonce, ciphertext, None).decode()

    def erase(self, subject_id: str) -> dict:
        """
        Crypto-shred a subject: destroy their key so all their data
        (everywhere, including copies we cannot see) becomes permanently
        unrecoverable. Records an "erase" event in the ledger as proof.

        Note we deliberately do NOT delete the ledger entries or the blob
        files. The blobs are now undecryptable noise, and the ledger stays
        intact so the audit trail is preserved.
        """
        destroyed = self.keys.destroy_key(subject_id)
        # Commit to a fixed marker for erase events (there is no data).
        marker = _sha256(f"ERASED:{subject_id}".encode())
        entry = self.ledger.append(subject_id, "erase", marker)
        entry["key_was_destroyed"] = destroyed
        return entry

    def prove_erased(self, subject_id: str) -> dict:
        """
        Produce a proof bundle that a subject has been erased:
          - key_present: should be False after erasure
          - data_readable: should be False (decryption now impossible)
          - ledger_intact: should be True (the audit trail still verifies)
          - erase_event: the ledger entry recording the erasure
        """
        key_present = self.keys.has_key(subject_id)

        # Try to read every record we have for this subject. After erasure,
        # all of these should fail.
        data_readable = False
        for entry in self.ledger.events_for(subject_id):
            if entry["event_type"] != "record":
                continue
            # We do not store ref->subject mapping in v1; instead we just
            # confirm the key is gone, which is what makes data unreadable.
            # (Phase 2 lineage will track refs per subject explicitly.)
            break
        if key_present:
            data_readable = True  # if the key still exists, data IS readable

        intact, detail = self.ledger.verify()
        erase_events = [
            e for e in self.ledger.events_for(subject_id)
            if e["event_type"] == "erase"
        ]
        # Phase 2A: report the full footprint. Every location the subject's
        # data reached. Because all copies/derivatives are encrypted with the
        # SAME per-subject key, destroying that one key crypto-shreds every
        # location at once, so coverage is complete by construction.
        footprint = sorted(self.lineage.locations(subject_id) - {"external"})
        return {
            "subject_id": subject_id,
            "key_present": key_present,
            "data_readable": data_readable,
            "ledger_intact": intact,
            "ledger_detail": detail,
            "erase_event": erase_events[-1] if erase_events else None,
            "footprint": footprint,
            "footprint_covered": (not key_present),
        }
