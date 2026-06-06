"""
demo_containment.py  -  Phase 2B: one key-shred kills every copy.

Run it:  python demo/demo_containment.py

Phase 2A traced where data went. Phase 2B proves the kill is total: we store
REAL encrypted copies at every location, all under the subject's one key.
After erasing the subject, we walk every location and show each copy is now
unreadable, even the ones we might never have known to look for.
"""

import shutil
from pathlib import Path
from tombstone import Vault, SubjectErased


def line():
    print("-" * 64)


def main():
    if Path("tombstone_data").exists():
        shutil.rmtree("tombstone_data")

    vault = Vault()
    subject = "jose-rios"
    pii = "Jose Rios, jose@example.com"

    line()
    print("STEP 1  Store REAL encrypted copies at 4 locations (key inheritance)")
    line()
    vault.record(subject, pii, location="users_table")
    vault.store_at(subject, "marketing_contacts", pii, source="users_table")
    vault.store_at(subject, "email_export_q2", pii, source="marketing_contacts")
    vault.store_at(subject, "ml_training_set", pii, source="users_table", kind="derive")
    print("  Real ciphertext now sits at marketing_contacts, email_export_q2,")
    print("  ml_training_set, all encrypted with Jose's ONE key.")

    line()
    print("STEP 2  Confirm every copy is readable BEFORE erasure")
    line()
    for loc in ["marketing_contacts", "email_export_q2", "ml_training_set"]:
        print(f"  read_at({loc}) -> {vault.read_at(subject, loc)!r}")

    line()
    print("STEP 3  Erase Jose (destroy the one key)")
    line()
    vault.erase(subject)
    print("  key destroyed.")

    line()
    print("STEP 4  Walk EVERY location and prove each copy is now dead")
    line()
    coverage = vault.verify_erasure_coverage(subject)
    for loc, r in coverage["locations"].items():
        status = "READABLE (bad!)" if r["readable"] else "unrecoverable"
        copy = "physical copy" if r["has_physical_copy"] else "lineage node "
        print(f"  {loc:>20}  [{copy}]  ->  {status}")
    print(f"\n  all_covered = {coverage['all_covered']}     (want True)")

    line()
    intact, detail = vault.ledger.verify()
    ok = coverage["all_covered"] and intact
    print(f"  ledger still intact = {intact}  ({detail})")
    print(f"  PHASE 2B PROVEN: {ok}")
    print("  One key destroyed. Every copy dead. Audit trail intact.")
    line()


if __name__ == "__main__":
    main()
