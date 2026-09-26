"""
demo_certificate.py  -  erase a person from an AI data pipeline and hand over
a certificate an auditor can check without trusting you.

Run:  python demo/demo_certificate.py
      TOMBSTONE_REKOR=1 python demo/demo_certificate.py   # anchor for real in Sigstore Rekor

By default the anchor is local (fast, offline, proves nothing to outsiders).
With TOMBSTONE_REKOR=1 the ledger root is published to rekor.sigstore.dev, a
public append-only log, and the certificate carries the log index anyone can
look up.
"""

import json
import os
import shutil
from pathlib import Path

from tombstone import Vault, Ledger, LocalAnchor, RekorAnchor, SubjectErased


def line():
    print("-" * 64)


def main():
    if Path("tombstone_data").exists():
        shutil.rmtree("tombstone_data")
    vault = Vault("tombstone_data")

    line()
    print("STEP 1  A person's data spreads through the pipeline")
    line()
    ref = vault.record("jose-rios", "Jose Rios, jose@example.com", location="users_table")
    vault.store_at("jose-rios", "marketing_export", "jose@example.com")
    vault.store_at("jose-rios", "vector_store", "Jose Rios profile embedding source")
    vault.copy_to("jose-rios", "vector_store", "ml_training_set", kind="derive")
    print("  footprint:", sorted(vault.lineage.locations("jose-rios") - {"external"}))
    print(f"  readable now? {vault.read('jose-rios', ref)!r}")

    line()
    print("STEP 2  Erase: destroy the one key every copy shares")
    line()
    vault.erase("jose-rios")
    for loc in ("marketing_export", "vector_store"):
        try:
            vault.read_at("jose-rios", loc)
            print(f"  {loc}: STILL READABLE (bug)")
        except SubjectErased:
            print(f"  {loc}: unrecoverable")

    line()
    print("STEP 3  Issue the erasure certificate")
    line()
    if os.environ.get("TOMBSTONE_REKOR") == "1":
        anchor = RekorAnchor(key_path="tombstone_data/anchor_key.pem")
        print("  anchoring in Sigstore Rekor (public transparency log)...")
    else:
        anchor = LocalAnchor("tombstone_data/anchors")
        print("  anchoring locally (set TOMBSTONE_REKOR=1 for a public anchor)")
    cert = vault.erasure_certificate("jose-rios", anchor=anchor)
    Path("tombstone_data/certificate.json").write_text(json.dumps(cert, indent=2))
    print(f"  erased            = {cert['erased']}")
    print(f"  erase entry index = {cert['inclusion']['index']} of {cert['inclusion']['size']}")
    print(f"  inclusion proof   = {len(cert['inclusion']['proof'])} hashes (no need to share the rest of the log)")
    print(f"  anchor            = {cert['anchor']['anchor']['provider']}"
          + (f", {cert['anchor']['anchor']['lookup']}" if 'lookup' in cert['anchor']['anchor'] else ""))
    print(f"  personal data in certificate? {'jose@example.com' in json.dumps(cert)}   (want False)")
    print("  written to tombstone_data/certificate.json")

    line()
    print("STEP 4  An auditor checks it")
    line()
    print("  inclusion proof alone (no log needed):", Ledger.check_inclusion(cert["inclusion"]))
    ok, msg = vault.check_erasure_certificate(cert, anchor)
    print(f"  full check: {ok}  ({msg})")

    line()
    print("STEP 5  Someone rewrites history to hide the erasure")
    line()
    lines = vault.ledger.path.read_text().splitlines()
    e = json.loads(lines[0]); e["subject_id"] = "someone-else"; lines[0] = json.dumps(e)
    vault.ledger.path.write_text("\n".join(lines) + "\n")
    ok, msg = vault.check_erasure_certificate(cert, anchor)
    print(f"  certificate check: {ok}  ({msg})")

    line()
    print("  Erasure across every copy, a certificate with no personal data in it,")
    print("  and a rewrite of history gets caught. That is a tombstone.")
    line()


if __name__ == "__main__":
    main()
