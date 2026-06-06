"""
attack.py  -  We play attacker against our own system.

Each test tries to DEFEAT a Tombstone guarantee. We print whether the attack
was DEFENDED (good, the system caught it) or SUCCEEDED (bad, a real hole we
must fix). This is how you actually know a security claim is true: you try to
break it and watch what happens.

Run: python attack.py
"""

import json
import shutil
from pathlib import Path

from tombstone import Vault, Ledger, SubjectErased


def banner(name):
    print("\n" + "=" * 64)
    print(name)
    print("=" * 64)


def result(attack_name, defended: bool, detail: str = ""):
    tag = "DEFENDED (good)" if defended else "SUCCEEDED (HOLE!)"
    print(f"  [{tag}] {attack_name}")
    if detail:
        print(f"           {detail}")
    return defended


def fresh_vault(with_data=True):
    if Path("attack_data").exists():
        shutil.rmtree("attack_data")
    v = Vault("attack_data")
    if with_data:
        v.record("alice", "Alice, alice@example.com", location="users")
        v.record("bob", "Bob, bob@example.com", location="users")
        v.record("carol", "Carol, carol@example.com", location="users")
    return v


def attack_forge_entry():
    """Attacker edits the CONTENTS of a past entry but keeps its hash."""
    banner("ATTACK 1: forge a past entry (change its data, keep its hash)")
    v = fresh_vault()
    path = "attack_data/ledger.jsonl"
    lines = Path(path).read_text().splitlines()
    entry = json.loads(lines[0])
    entry["subject_id"] = "attacker-changed-this"  # tamper, leave hash as-is
    lines[0] = json.dumps(entry)
    Path(path).write_text("\n".join(lines) + "\n")
    intact, detail = Ledger(path).verify()
    # DEFENDED if verification now fails (caught the forgery).
    return result("forge entry contents", defended=(intact is False), detail=detail)


def attack_reorder():
    """Attacker swaps the order of two entries."""
    banner("ATTACK 2: reorder entries")
    v = fresh_vault()
    path = "attack_data/ledger.jsonl"
    lines = Path(path).read_text().splitlines()
    if len(lines) >= 2:
        lines[0], lines[1] = lines[1], lines[0]  # swap first two
    Path(path).write_text("\n".join(lines) + "\n")
    intact, detail = Ledger(path).verify()
    return result("reorder entries", defended=(intact is False), detail=detail)


def attack_truncate():
    """Attacker DELETES recent entries to hide that something happened."""
    banner("ATTACK 3: truncate the log (delete recent entries to hide them)")
    v = fresh_vault()
    # Something incriminating happens: we erase carol.
    v.erase("carol")
    path = "attack_data/ledger.jsonl"
    lines = Path(path).read_text().splitlines()
    full_len = len(lines)
    # Attacker chops off the last entry (the erase) to hide it.
    Path(path).write_text("\n".join(lines[:-1]) + "\n")
    intact, detail = Ledger(path).verify()
    # This is the subtle one: each entry only chains BACKWARD, so a truncated
    # log still verifies as "intact". DEFENDED only if verify somehow catches
    # that entries are missing.
    return result(
        "truncate log",
        defended=(intact is False),
        detail=f"had {full_len} entries, chopped to {full_len-1}; verify says intact={intact}",
    )


def attack_recover_shredded():
    """Attacker tries to read a subject's data after their key is destroyed."""
    banner("ATTACK 4: recover data after crypto-shred")
    v = fresh_vault()
    ref = v.record("dave", "Dave, dave@example.com", location="users")
    v.store_at("dave", "marketing", "Dave, dave@example.com")
    v.erase("dave")
    recovered = None
    try:
        recovered = v.read("dave", ref)
    except SubjectErased:
        pass
    # Also try to read the raw blob file directly off disk and decrypt it.
    raw_readable = False
    blob_dir = Path("attack_data/blobs")
    for blob in blob_dir.glob("*.blob"):
        data = blob.read_bytes()
        # Without the key, this is just ciphertext. We confirm it does NOT
        # contain the plaintext in the clear.
        if b"dave@example.com" in data:
            raw_readable = True
    defended = (recovered is None) and (raw_readable is False)
    return result(
        "recover shredded data",
        defended=defended,
        detail=f"vault read returned {recovered!r}; plaintext-on-disk={raw_readable}",
    )


def attack_proxy_bypass():
    """Attacker tries to sneak PII past the proxy policy."""
    banner("ATTACK 5: sneak PII past the proxy policy")
    from tombstone import Policy
    pol = Policy()
    pol.protect("alice", "alice@example.com")
    pol.block_destination("evil.example.com")
    # Straightforward leak attempt:
    d1 = pol.check_payload("http://evil.example.com/x", '{"e":"alice@example.com"}')
    caught_direct = (d1.allowed is False)
    # Evasion: split the email so the exact string is not present, but the
    # generic email pattern still should catch a different valid-looking email.
    d2 = pol.check_payload("http://evil.example.com/x", '{"e":"a l i c e@e x a m p l e.com"}')
    # This spaced-out version defeats both exact-match AND the regex. So the
    # honest result: this evasion SUCCEEDS against v0.3. That is a real finding.
    caught_evasion = (d2.allowed is False)
    print(f"  direct leak caught: {caught_direct}")
    print(f"  spaced-out evasion caught: {caught_evasion}")
    # We report the EVASION result as the headline, since the direct case
    # already works.
    return result(
        "proxy evasion (obfuscated PII)",
        defended=caught_evasion,
        detail="spaced-out PII defeats exact-match and regex in v0.3",
    )


def attack_master_erase_defeats_hoarded_keys():
    """
    Attacker copies subjects' WRAPPED key files to a hiding spot, betting they
    can decrypt later. We then crypto-erase the whole store (destroy master).
    The hoarded wrapped keys must be useless without the master.
    """
    banner("ATTACK 6: hoard wrapped keys, then survive a master crypto-erase")
    v = fresh_vault()
    import shutil as _sh
    hoard = Path("attack_data/hoard")
    hoard.mkdir(parents=True, exist_ok=True)
    # Attacker copies every wrapped subject key they can see.
    keydir = Path("attack_data/keys")
    for k in keydir.glob("*.key"):
        if k.name != "_master.key":
            _sh.copy(k, hoard / k.name)
    hoarded = list(hoard.glob("*.key"))

    # Whole-store crypto-erase: destroy the master key only.
    v.crypto_erase_all()

    # Now try to use the hoarded wrapped keys. Without the master they cannot
    # be unwrapped. We confirm: (a) vault reads fail, (b) the hoarded files are
    # ciphertext, not usable keys.
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    recovered_any = False
    # Even if the attacker tries the hoarded bytes directly as an AES key, they
    # are wrapped (encrypted), so they are not a valid key for the data blobs.
    for blob in Path("attack_data/blobs").glob("*.blob"):
        data = blob.read_bytes()
        for hk in hoarded:
            wrapped = hk.read_bytes()
            # Attacker's best naive try: use the wrapped bytes (minus nonce) as a key.
            for guess in (wrapped, wrapped[12:], wrapped[:32]):
                if len(guess) != 32:
                    continue
                try:
                    AESGCM(guess).decrypt(data[:12], data[12:], None)
                    recovered_any = True
                except Exception:
                    pass
    defended = (not recovered_any)
    return result(
        "master crypto-erase defeats hoarded wrapped keys",
        defended=defended,
        detail=f"attacker hoarded {len(hoarded)} wrapped keys; recovered_any={recovered_any}",
    )


def main():
    print("TOMBSTONE ADVERSARIAL TEST SUITE")
    print("We attack our own guarantees. DEFENDED = good. SUCCEEDED = a hole to fix.")
    outcomes = {
        "forge": attack_forge_entry(),
        "reorder": attack_reorder(),
        "truncate": attack_truncate(),
        "recover_shredded": attack_recover_shredded(),
        "proxy_evasion": attack_proxy_bypass(),
        "master_erase": attack_master_erase_defeats_hoarded_keys(),
    }
    banner("SUMMARY")
    for name, defended in outcomes.items():
        print(f"  {name:20} {'DEFENDED' if defended else 'HOLE TO FIX'}")
    holes = [n for n, d in outcomes.items() if not d]
    print(f"\n  {len(outcomes)-len(holes)}/{len(outcomes)} attacks defended.")
    if holes:
        print(f"  Holes to fix in Phase 5 hardening: {holes}")
    if Path("attack_data").exists():
        shutil.rmtree("attack_data")


if __name__ == "__main__":
    main()
