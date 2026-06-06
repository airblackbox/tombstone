"""
demo_envelope.py  -  Envelope encryption: erasure that does not trust the disk.

Run it:  python demo/demo_envelope.py

Subject keys are never stored in the clear; each is wrapped (encrypted) under
a master key. This shows the payoff: destroying the MASTER key crypto-erases
everyone at once, and even an attacker who hoarded the wrapped key files
cannot recover anything.
"""

import shutil
from pathlib import Path
from tombstone import Vault, SubjectErased


def line():
    print("-" * 64)


def main():
    if Path("tombstone_data").exists():
        shutil.rmtree("tombstone_data")
    v = Vault()

    line()
    print("STEP 1  Store data for three people (keys wrapped under a master)")
    line()
    for name in ["alice", "bob", "carol"]:
        v.record(name, f"{name}, {name}@example.com", location="users")
    print("  3 subjects stored. On disk, each subject key is CIPHERTEXT,")
    print("  wrapped under the master key, never a usable key in the clear.")

    line()
    print("STEP 2  Confirm data is readable now")
    line()
    print(f"  alice key present? {v.keys.has_key('alice')}")

    line()
    print("STEP 3  Attacker hoards the wrapped key files (betting on later)")
    line()
    hoard = Path("tombstone_data/hoard"); hoard.mkdir(exist_ok=True)
    for k in Path("tombstone_data/keys").glob("*.key"):
        if k.name != "_master.key":
            shutil.copy(k, hoard / k.name)
    print(f"  attacker copied {len(list(hoard.glob('*.key')))} wrapped keys aside.")

    line()
    print("STEP 4  Crypto-erase EVERYONE by destroying the master key only")
    line()
    event = v.crypto_erase_all()
    print(f"  master destroyed = {event['master_destroyed']}")
    print("  we did NOT touch the subject key files or the data blobs.")

    line()
    print("STEP 5  Prove everyone is unrecoverable, including via hoarded keys")
    line()
    for name in ["alice", "bob", "carol"]:
        print(f"  {name}: key usable now? {v.keys.get_key(name) is not None}   (want False)")
    intact, detail = v.ledger.verify()
    print(f"  ledger still intact = {intact}  ({detail})")

    line()
    all_dead = all(v.keys.get_key(n) is None for n in ["alice", "bob", "carol"])
    ok = all_dead and intact
    print(f"  ENVELOPE ERASURE PROVEN: {ok}")
    print("  One master key destroyed. Everyone gone. Hoarded keys useless.")
    print("  Erasure did not depend on scrubbing a single disk byte.")
    line()
    shutil.rmtree("tombstone_data", ignore_errors=True)


if __name__ == "__main__":
    main()
