"""
keystore.py

The heart of Tombstone. In crypto-shredding, the KEY is the data.

Every data subject (person) gets their own unique encryption key. Their
personal data is stored encrypted with that key. To "erase" the person,
we destroy their key. Once the key is gone, the encrypted data is just
noise forever, even if copies of the ciphertext still exist in backups,
logs, or derived tables we never knew about.

That is the trick that makes erasure provable AND compatible with an
append-only, tamper-evident log: we never delete the log, we destroy
the key.

For v1 the keys live in a local directory, one file per subject. That
is the honest, simple version. Swapping this for a cloud KMS later does
not change anything else in the system.
"""

import os
import secrets
from pathlib import Path


class KeyStore:
    """Stores one symmetric key per data subject, on the local disk."""

    def __init__(self, key_dir: str = ".tombstone_keys"):
        # Where the per-subject keys live. One file per subject.
        self.key_dir = Path(key_dir)
        self.key_dir.mkdir(parents=True, exist_ok=True)

    def _key_path(self, subject_id: str) -> Path:
        # A subject's key lives at <key_dir>/<subject_id>.key
        # We keep the filename simple and predictable.
        safe = "".join(c for c in subject_id if c.isalnum() or c in "-_")
        return self.key_dir / f"{safe}.key"

    def create_key(self, subject_id: str) -> bytes:
        """Make a new random key for a subject, or return the existing one."""
        path = self._key_path(subject_id)
        if path.exists():
            return path.read_bytes()
        # 32 random bytes = a 256-bit key. secrets is the right tool here.
        key = secrets.token_bytes(32)
        path.write_bytes(key)
        return key

    def get_key(self, subject_id: str) -> bytes | None:
        """Return a subject's key, or None if it has been destroyed."""
        path = self._key_path(subject_id)
        if not path.exists():
            return None
        return path.read_bytes()

    def destroy_key(self, subject_id: str) -> bool:
        """
        Crypto-shred: destroy the subject's key so their data can never
        be decrypted again. Returns True if a key was destroyed, False if
        there was nothing to destroy.

        We overwrite the file with random bytes before deleting it, so the
        old key cannot be recovered from the raw disk by simple means.
        """
        path = self._key_path(subject_id)
        if not path.exists():
            return False
        size = path.stat().st_size
        # Overwrite the key material, then remove the file.
        with open(path, "wb") as f:
            f.write(secrets.token_bytes(size))
            f.flush()
            os.fsync(f.fileno())
        path.unlink()
        return True

    def has_key(self, subject_id: str) -> bool:
        """True if the subject still has a key (i.e. has not been erased)."""
        return self._key_path(subject_id).exists()
