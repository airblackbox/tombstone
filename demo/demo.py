"""
demo.py  -  The whole Tombstone thesis in five steps.

Run it:  python demo.py

It shows the one thing nobody else demonstrates cleanly:
you can have a permanent, tamper-evident audit log AND honor "delete me"
at the same time, because erasure destroys the KEY, not the log.
"""

import shutil
from pathlib import Path
from tombstone import Vault, SubjectErased


def line():
    print("-" * 64)


def main():
    # Start clean each run so the demo is repeatable.
    if Path("tombstone_data").exists():
        shutil.rmtree("tombstone_data")

    vault = Vault()
    subject = "jose-rios"

    line()
    print("STEP 1  Store some personal data for a subject")
    line()
    ref = vault.record(subject, "Jose Rios, jose@example.com, hired 2026-05-01")
    print(f"  stored a record for '{subject}', ref = {ref}")
    print("  the data on disk is ENCRYPTED; the ledger holds only a hash of it")

    line()
    print("STEP 2  Prove the audit log is tamper-evident")
    line()
    intact, detail = vault.ledger.verify()
    print(f"  ledger verify -> intact={intact}  ({detail})")

    line()
    print("STEP 3  Read the data back (proves it was really stored)")
    line()
    print(f"  read -> {vault.read(subject, ref)!r}")

    line()
    print("STEP 4  Erase the subject (destroy their key = crypto-shred)")
    line()
    event = vault.erase(subject)
    print(f"  key destroyed = {event['key_was_destroyed']}")
    print(f"  ledger recorded an 'erase' event at index {event['index']}")

    line()
    print("STEP 5  Prove erasure: data is GONE, but the log still verifies")
    line()
    # 5a: reading now fails because the key is gone
    try:
        vault.read(subject, ref)
        print("  read -> UNEXPECTED: data still readable (this would be a bug)")
    except SubjectErased as e:
        print(f"  read -> blocked: {e}")
    # 5b: the proof bundle
    proof = vault.prove_erased(subject)
    print(f"  key_present   = {proof['key_present']}    (want False)")
    print(f"  data_readable = {proof['data_readable']}    (want False)")
    print(f"  ledger_intact = {proof['ledger_intact']}     (want True)")
    print(f"  ledger_detail = {proof['ledger_detail']}")

    line()
    ok = (
        proof["key_present"] is False
        and proof["data_readable"] is False
        and proof["ledger_intact"] is True
    )
    print(f"  THESIS PROVEN: {ok}")
    print("  The person is unrecoverable. The audit trail is still intact.")
    line()


if __name__ == "__main__":
    main()
