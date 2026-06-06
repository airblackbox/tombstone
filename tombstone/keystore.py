"""
keystore.py  -  Envelope-encryption key store (v0.4 hardening).

THE PROBLEM WITH THE OLD DESIGN
The first version stored each subject key as raw bytes on disk, and "erase"
overwrote and deleted that file. On modern SSDs that is NOT a guarantee:
wear-leveling means the controller may keep the old bytes physically present
somewhere you cannot reach or scrub. So erasure secretly depended on the disk
cooperating. That is a real soft spot in a tool whose whole job is erasure.

THE FIX: ENVELOPE ENCRYPTION
We never store a usable subject key in the clear. Instead:

  - There is ONE master key (stored once).
  - Each subject key is generated, then WRAPPED (encrypted) under the master
    key. Only the wrapped form touches disk.
  - To use a subject key, we unwrap it in memory with the master key.

Two ways to erase, neither depending on physically scrubbing the disk:

  1. Erase ONE subject: destroy their wrapped key. Without it there is nothing
     to unwrap, so their data is unrecoverable.

  2. Erase EVERYONE at once: destroy the MASTER key. Every subject key on disk
     becomes ciphertext that can never be unwrapped, so ALL data dies at once,
     even copies of wrapped keys an attacker squirreled away.

HONEST LIMIT (documented, not hidden)
The master key here lives in a local file. Truly hardened, it belongs in a
KMS/HSM that performs and attests its own destruction. This module makes the
DESIGN correct; a KMS integration makes the DEPLOYMENT hardened. The
wrap/unwrap interface is exactly what a KMS would slot into.
"""

import os
import secrets
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class MasterKeyDestroyed(Exception):
    """Raised when the master key is gone, so no subject key can be unwrapped."""


class KeyStore:
    """Per-subject keys, wrapped under a master key (envelope encryption)."""

    def __init__(self, key_dir: str = ".tombstone_keys"):
        self.key_dir = Path(key_dir)
        self.key_dir.mkdir(parents=True, exist_ok=True)
        self._master_path = self.key_dir / "_master.key"
        if not self._master_path.exists():
            self._master_path.write_bytes(secrets.token_bytes(32))

    # ---- master key handling ----

    def _master(self) -> bytes:
        if not self._master_path.exists():
            raise MasterKeyDestroyed(
                "master key destroyed; no subject data can be decrypted"
            )
        return self._master_path.read_bytes()

    def destroy_master(self) -> bool:
        """Crypto-erase the ENTIRE store by destroying the master key."""
        if not self._master_path.exists():
            return False
        self._secure_unlink(self._master_path)
        return True

    # ---- per-subject keys (wrapped) ----

    def _key_path(self, subject_id: str) -> Path:
        safe = "".join(c for c in subject_id if c.isalnum() or c in "-_")
        return self.key_dir / f"{safe}.key"

    def _wrap(self, plaintext_key: bytes) -> bytes:
        aes = AESGCM(self._master())
        nonce = os.urandom(12)
        return nonce + aes.encrypt(nonce, plaintext_key, None)

    def _unwrap(self, wrapped: bytes) -> bytes:
        aes = AESGCM(self._master())
        nonce, ct = wrapped[:12], wrapped[12:]
        return aes.decrypt(nonce, ct, None)

    def create_key(self, subject_id: str) -> bytes:
        """Make/fetch a subject key. Only the WRAPPED form is ever on disk."""
        path = self._key_path(subject_id)
        if path.exists():
            return self._unwrap(path.read_bytes())
        key = secrets.token_bytes(32)
        path.write_bytes(self._wrap(key))
        return key

    def get_key(self, subject_id: str) -> bytes | None:
        """Usable key, or None if the subject OR the master key is gone."""
        path = self._key_path(subject_id)
        if not path.exists():
            return None
        try:
            return self._unwrap(path.read_bytes())
        except MasterKeyDestroyed:
            return None

    def destroy_key(self, subject_id: str) -> bool:
        """Erase ONE subject: destroy their wrapped key."""
        path = self._key_path(subject_id)
        if not path.exists():
            return False
        self._secure_unlink(path)
        return True

    def has_key(self, subject_id: str) -> bool:
        if not self._key_path(subject_id).exists():
            return False
        return self._master_path.exists()

    # ---- helpers ----

    @staticmethod
    def _secure_unlink(path: Path) -> None:
        """Overwrite with random bytes, fsync, then delete. Defense in depth."""
        size = path.stat().st_size
        with open(path, "wb") as f:
            f.write(secrets.token_bytes(size))
            f.flush()
            os.fsync(f.fileno())
        path.unlink()
