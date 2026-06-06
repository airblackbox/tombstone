"""
demo_merkle.py  -  Merkle proofs: prove one thing without revealing everything.

Run it:  python demo/demo_merkle.py

A hash chain proves the whole log is intact, but to prove ONE entry you had to
hand over the whole log. A Merkle tree proves a single entry's inclusion with
about log2(n) hashes, and proves the log only ever grew. This is how real
transparency logs work.
"""

import shutil
from pathlib import Path
from tombstone import Vault, Ledger


def line():
    print("-" * 64)


def main():
    if Path("tombstone_data").exists():
        shutil.rmtree("tombstone_data")
    v = Vault()

    line()
    print("STEP 1  Build a log: several people, several events")
    line()
    for name in ["alice", "bob", "carol", "dave", "erin"]:
        v.record(name, f"{name}, {name}@example.com", location="users")
    v.erase("carol")  # the event we will prove, privately
    entries = v.ledger._entries()
    print(f"  log has {len(entries)} entries; root = {v.ledger.merkle_root()[:24]}...")

    line()
    print("STEP 2  Prove ONE entry (carol's erasure) is in the log")
    line()
    # find carol's erase entry index
    idx = next(i for i, e in enumerate(entries)
               if e["subject_id"] == "carol" and e["event_type"] == "erase")
    bundle = v.ledger.prove_inclusion(idx)
    print(f"  proving entry #{idx} (carol erase)")
    print(f"  proof size: {len(bundle['proof'])} hashes (vs {len(entries)} full entries)")
    print(f"  verifies with ONLY the root + proof: {Ledger.check_inclusion(bundle)}")
    print("  note: the verifier never saw the other people's events.")

    line()
    print("STEP 3  Attacker forges inclusion for an event that never happened")
    line()
    forged = dict(bundle)
    forged["entry_hash"] = "deadbeef" * 8  # an entry that is not in the log
    print(f"  forged claim verifies? {Ledger.check_inclusion(forged)}   (want False)")

    line()
    print("STEP 4  Prove the log only GREW (append-only over time)")
    line()
    old_size = 3
    cons = v.ledger.prove_consistency(old_size)
    print(f"  consistency from size {old_size} -> {len(entries)}: "
          f"{v.ledger.check_consistency(cons)}   (want True)")

    line()
    ok = (Ledger.check_inclusion(bundle)
          and not Ledger.check_inclusion(forged)
          and v.ledger.check_consistency(cons))
    print(f"  MERKLE PROOFS PROVEN: {ok}")
    print("  Prove one entry without revealing the rest. Forgeries rejected.")
    line()
    shutil.rmtree("tombstone_data", ignore_errors=True)


if __name__ == "__main__":
    main()
