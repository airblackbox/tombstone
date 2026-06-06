"""
demo_lineage.py  -  Phase 2A: the Meta problem, in miniature.

Run it:  python demo/demo_lineage.py

Phase 1 erased data in one place. This shows the real problem: data SPRAWLS.
Jose's record gets copied into marketing, derived into an analytics rollup,
exported to a CSV, snapshotted into an ML training set. Then he asks to be
deleted. We trace everywhere his data went, erase him, and prove every
location is covered, all while the audit log stays intact.
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

    line()
    print("STEP 1  Store Jose's data, then let it SPRAWL like real systems do")
    line()
    vault.record(subject, "Jose Rios, jose@example.com", location="users_table")
    # Data gets copied and derived across the company, the way it really does:
    vault.copy_to(subject, "users_table", "marketing_contacts", kind="copy")
    vault.copy_to(subject, "users_table", "analytics_rollup", kind="derive")
    vault.copy_to(subject, "marketing_contacts", "email_export_q2", kind="copy")
    vault.copy_to(subject, "analytics_rollup", "ml_training_set", kind="derive")
    print("  Jose's data now lives in 5 places via copies and derivations.")

    line()
    print("STEP 2  Show the lineage graph (where the data flowed)")
    line()
    for edge in vault.lineage.graph(subject):
        print(f"  {edge['from']:>20}  --{edge['kind']}-->  {edge['to']}")

    line()
    print("STEP 3  Enumerate the FULL FOOTPRINT (everywhere to cover)")
    line()
    footprint = sorted(vault.lineage.locations(subject) - {"external"})
    print(f"  {len(footprint)} locations: {footprint}")
    print("  This is the list Meta could not produce. We can.")

    line()
    print("STEP 4  Trace downstream from one entry point")
    line()
    reach = sorted(vault.lineage.trace(subject, "users_table") - {"users_table"})
    print(f"  Data entering at 'users_table' can reach: {reach}")

    line()
    print("STEP 5  Erase Jose, and prove coverage of the WHOLE footprint")
    line()
    vault.erase(subject)
    proof = vault.prove_erased(subject)
    print(f"  key_present       = {proof['key_present']}    (want False)")
    print(f"  ledger_intact     = {proof['ledger_intact']}     (want True)")
    print(f"  footprint         = {proof['footprint']}")
    print(f"  footprint_covered = {proof['footprint_covered']}     (want True)")
    print()
    print("  Why coverage is complete: every copy and derivative was encrypted")
    print("  with Jose's ONE key. Destroying it crypto-shreds all 5 locations")
    print("  at once, even ones we might have failed to list.")

    line()
    ok = (
        proof["key_present"] is False
        and proof["ledger_intact"] is True
        and proof["footprint_covered"] is True
        and len(proof["footprint"]) == 5
    )
    print(f"  PHASE 2A PROVEN: {ok}")
    print("  We traced the sprawl, erased it everywhere, kept the audit trail.")
    line()


if __name__ == "__main__":
    main()
