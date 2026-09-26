"""
anchor.py  -  external anchoring: make the ledger independently verifiable.

THE PROBLEM
A hash chain plus an HMAC head is tamper-EVIDENT, but the HMAC secret lives
with whoever holds the ledger. If that party rewrites history and re-signs, the
chain verifies cleanly. "We checked our own log" is not proof to anyone else.

THE FIX
Periodically hand the ledger's Merkle root to an OUTSIDE party that records it
in a public, append-only transparency log and gives back a receipt. Later,
anyone can confirm that the ledger's first N entries still hash to the root
that was published at that moment. Rewriting anything before an anchor now
requires rewriting the public log, which the operator cannot do.

    receipt = ledger.anchor(RekorAnchor())         # publish the current root
    ok, msg = ledger.check_anchor(receipt, anchor)  # prove nothing was rewritten

Two anchors ship:

  RekorAnchor  - Sigstore's Rekor transparency log (rekor.sigstore.dev). Free,
                 public, append-only, run by the OpenSSF. The root is signed
                 with a local ECDSA P-256 key and submitted as a `hashedrekord`
                 entry. The receipt carries the log index, so anyone can look
                 it up at https://search.sigstore.dev/?logIndex=<n>.
  LocalAnchor  - writes receipts to a directory. Useful for tests and offline
                 development. It is NOT independent: it proves nothing to a
                 third party, and says so in every receipt it writes.

Honest scope: anchoring proves the log was not rewritten AFTER the anchor was
published. Entries added after the last anchor are protected only by the
local chain until the next anchor. Anchor as often as your evidence needs.
"""

import base64
import hashlib
import json
import time
import urllib.error
import urllib.request
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

ANCHOR_STATEMENT_VERSION = "tombstone-anchor-v1"
REKOR_PUBLIC_URL = "https://rekor.sigstore.dev"


def statement_bytes(size: int, root_hex: str) -> bytes:
    """The exact bytes that get signed and published: version, size, root."""
    return f"{ANCHOR_STATEMENT_VERSION}\n{size}\n{root_hex}\n".encode()


class AnchorError(Exception):
    """The external service refused or could not be reached."""


# ---------------------------------------------------------------------------
# Local (non-independent) anchor: for tests and offline work.
# ---------------------------------------------------------------------------

class LocalAnchor:
    """Writes receipts to a folder. Not independent; clearly labelled as such."""

    name = "local"

    def __init__(self, receipt_dir: str = ".tombstone_anchors"):
        self.dir = Path(receipt_dir)
        self.dir.mkdir(parents=True, exist_ok=True)

    def publish(self, size: int, root_hex: str) -> dict:
        stmt = statement_bytes(size, root_hex)
        rid = hashlib.sha256(stmt).hexdigest()[:24]
        receipt = {
            "provider": self.name,
            "independent": False,
            "note": "local anchor: proves nothing to a third party; use RekorAnchor for that",
            "id": rid,
            "statement_sha256": hashlib.sha256(stmt).hexdigest(),
            "anchored_at": time.time(),
        }
        (self.dir / f"{rid}.json").write_text(json.dumps(receipt))
        return receipt

    def verify(self, size: int, root_hex: str, receipt: dict) -> tuple[bool, str]:
        path = self.dir / f"{receipt.get('id')}.json"
        if not path.exists():
            return False, "local anchor receipt not found"
        stored = json.loads(path.read_text())
        if stored.get("statement_sha256") != hashlib.sha256(statement_bytes(size, root_hex)).hexdigest():
            return False, "local anchor receipt does not match this size/root"
        return True, "local anchor matches (not independent)"


# ---------------------------------------------------------------------------
# Rekor (Sigstore) anchor: public, append-only, independently verifiable.
# ---------------------------------------------------------------------------

def _default_transport(method: str, url: str, body: bytes | None) -> tuple[int, bytes]:
    req = urllib.request.Request(url, data=body, method=method)
    req.add_header("Accept", "application/json")
    if body is not None:
        req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return resp.status, resp.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()
    except urllib.error.URLError as e:
        raise AnchorError(f"could not reach {url}: {e.reason}") from e


class RekorAnchor:
    """Anchor ledger roots in Sigstore's Rekor transparency log.

    A local ECDSA P-256 key signs each statement. Only the PUBLIC key goes to
    Rekor. The private key is stored PEM-encoded at `key_path` (created on
    first use, mode 0600). `transport` can be swapped for testing.
    """

    name = "rekor"

    def __init__(self, url: str = REKOR_PUBLIC_URL, key_path: str = ".tombstone_anchor_key.pem",
                 transport=None):
        self.url = url.rstrip("/")
        self.key_path = Path(key_path)
        self._transport = transport or _default_transport
        self._key = self._load_or_create_key()

    # ---- keys ----

    def _load_or_create_key(self):
        if self.key_path.exists():
            return serialization.load_pem_private_key(self.key_path.read_bytes(), password=None)
        key = ec.generate_private_key(ec.SECP256R1())
        pem = key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        self.key_path.touch(mode=0o600)
        self.key_path.write_bytes(pem)
        return key

    def public_key_pem(self) -> bytes:
        return self._key.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        )

    # ---- publish / verify ----

    def publish(self, size: int, root_hex: str) -> dict:
        stmt = statement_bytes(size, root_hex)
        digest = hashlib.sha256(stmt).hexdigest()
        sig = self._key.sign(stmt, ec.ECDSA(hashes.SHA256()))
        entry = {
            "apiVersion": "0.0.1",
            "kind": "hashedrekord",
            "spec": {
                "data": {"hash": {"algorithm": "sha256", "value": digest}},
                "signature": {
                    "content": base64.b64encode(sig).decode(),
                    "publicKey": {"content": base64.b64encode(self.public_key_pem()).decode()},
                },
            },
        }
        status, body = self._transport("POST", f"{self.url}/api/v1/log/entries",
                                       json.dumps(entry).encode())
        if status not in (200, 201):
            raise AnchorError(f"rekor refused the entry (HTTP {status}): {body[:300]!r}")
        try:
            uuid, info = next(iter(json.loads(body).items()))
        except (ValueError, StopIteration, AttributeError) as e:
            raise AnchorError(f"rekor returned an unexpected body: {body[:300]!r}") from e
        return {
            "provider": self.name,
            "independent": True,
            "url": self.url,
            "uuid": uuid,
            "log_index": info.get("logIndex"),
            "log_id": info.get("logID"),
            "integrated_time": info.get("integratedTime"),
            "statement_sha256": digest,
            "signature_b64": base64.b64encode(sig).decode(),
            "public_key_pem": self.public_key_pem().decode(),
            "lookup": f"https://search.sigstore.dev/?logIndex={info.get('logIndex')}",
        }

    def verify(self, size: int, root_hex: str, receipt: dict) -> tuple[bool, str]:
        """Fetch the entry back from Rekor and confirm it commits to this
        size and root under the public key in the receipt."""
        stmt = statement_bytes(size, root_hex)
        digest = hashlib.sha256(stmt).hexdigest()
        if receipt.get("statement_sha256") != digest:
            return False, "receipt statement does not match this size/root"

        status, body = self._transport("GET", f"{self.url}/api/v1/log/entries/{receipt.get('uuid')}", None)
        if status != 200:
            return False, f"rekor lookup failed (HTTP {status})"
        try:
            _, info = next(iter(json.loads(body).items()))
            spec = json.loads(base64.b64decode(info["body"]))["spec"]
            logged_digest = spec["data"]["hash"]["value"]
            logged_sig = base64.b64decode(spec["signature"]["content"])
            logged_pub = base64.b64decode(spec["signature"]["publicKey"]["content"])
        except (ValueError, KeyError, StopIteration, TypeError) as e:
            return False, f"rekor entry could not be decoded: {e}"

        if logged_digest != digest:
            return False, "rekor entry commits to a different statement"
        try:
            pub = serialization.load_pem_public_key(logged_pub)
            pub.verify(logged_sig, stmt, ec.ECDSA(hashes.SHA256()))
        except Exception:
            return False, "signature in the rekor entry does not verify over this statement"
        return True, f"anchored in rekor at log index {info.get('logIndex')}"
