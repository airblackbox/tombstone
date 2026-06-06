"""
merkle.py  -  A Merkle tree with inclusion and consistency proofs.

This is the data structure real transparency logs (e.g. Certificate
Transparency) use. It gives two powerful properties our hash chain alone
could not:

  INCLUSION PROOF: prove "entry X is in this log" with about log2(n) hashes,
  without revealing the rest of the log. For a million entries that is ~20
  hashes instead of a million records. Useful for privacy: prove an erasure
  is recorded without dumping everyone else's events.

  CONSISTENCY PROOF: prove the log only ever GREW between two points (no entry
  was swapped, removed, or rewritten). This is how you prove an append-only
  log stayed append-only over time.

We follow the RFC 6962 (Certificate Transparency) hashing rules:
  - leaf hash  = SHA256(0x00 || data)
  - node hash  = SHA256(0x01 || left || right)
The 0x00/0x01 prefixes prevent "second preimage" attacks where a leaf could be
forged to look like an internal node.
"""

import hashlib


def _sha(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()


def hash_leaf(data: bytes) -> bytes:
    """Leaf hash with the 0x00 domain-separation prefix (RFC 6962)."""
    return _sha(b"\x00" + data)


def hash_node(left: bytes, right: bytes) -> bytes:
    """Internal node hash with the 0x01 prefix (RFC 6962)."""
    return _sha(b"\x01" + left + right)


def merkle_root(leaves: list[bytes]) -> bytes:
    """
    Compute the Merkle root of a list of already-hashed leaves.

    Uses the RFC 6962 rule for odd counts: a lone node is promoted up a level
    (it is NOT duplicated, which is a known weakness in some other schemes).
    """
    if not leaves:
        return _sha(b"")  # empty tree
    level = list(leaves)
    while len(level) > 1:
        nxt = []
        for i in range(0, len(level), 2):
            if i + 1 < len(level):
                nxt.append(hash_node(level[i], level[i + 1]))
            else:
                nxt.append(level[i])  # promote the lone node
        level = nxt
    return level[0]


def inclusion_proof(leaves: list[bytes], index: int) -> list[bytes]:
    """
    Build the audit path proving the leaf at `index` is in the tree.

    Returns the list of sibling hashes needed to recompute the root from the
    target leaf. Verifier uses verify_inclusion() with this path.
    """
    if not (0 <= index < len(leaves)):
        raise IndexError("leaf index out of range")
    proof = []
    level = list(leaves)
    idx = index
    while len(level) > 1:
        nxt = []
        for i in range(0, len(level), 2):
            if i + 1 < len(level):
                left, right = level[i], level[i + 1]
                nxt.append(hash_node(left, right))
                if i == idx or i + 1 == idx:
                    # record the SIBLING of our target on this level
                    sibling = right if i == idx else left
                    proof.append(sibling)
            else:
                nxt.append(level[i])  # lone node promoted; no sibling recorded
        idx //= 2
        level = nxt
    return proof


def verify_inclusion(leaf: bytes, index: int, size: int,
                     proof: list[bytes], root: bytes) -> bool:
    """
    Verify that `leaf` really sits at `index` in a tree of `size` leaves with
    the given `root`, using `proof` (the sibling path). Recomputes the root
    and compares. Returns True only if it matches exactly.
    """
    if not (0 <= index < size):
        return False
    computed = leaf
    idx, sz = index, size
    p = 0
    while sz > 1:
        # number of nodes on this level is sz; pair them up
        last_index_on_level = sz - 1
        if idx == last_index_on_level and sz % 2 == 1:
            # our node was the lone promoted node: no sibling at this level
            idx //= 2
            sz = (sz + 1) // 2
            continue
        if p >= len(proof):
            return False
        sibling = proof[p]
        p += 1
        if idx % 2 == 0:
            computed = hash_node(computed, sibling)
        else:
            computed = hash_node(sibling, computed)
        idx //= 2
        sz = (sz + 1) // 2
    return computed == root and p == len(proof)


def consistency_proof(leaves: list[bytes], old_size: int) -> list[bytes]:
    """
    Prove that a log of `old_size` leaves is a prefix of the current log
    (i.e. the log only appended, never rewrote the first old_size entries).

    Simplified, honest implementation: we expose the hashes a verifier needs
    to recompute BOTH the old root (from the first old_size leaves) and the
    new root (from all leaves), proving the old set is an unchanged prefix.
    For clarity over cleverness we return the two roots plus the new size;
    verify_consistency recomputes and checks the prefix relationship.

    (A full RFC 6962 consistency proof returns a minimal hash subset. This
    version is correct and demonstrable; the minimal-subset optimization is a
    later refinement, noted honestly.)
    """
    if not (0 < old_size <= len(leaves)):
        raise ValueError("old_size out of range")
    old_root = merkle_root(leaves[:old_size])
    new_root = merkle_root(leaves)
    return [old_root, new_root]


def verify_consistency(old_root: bytes, old_size: int,
                       new_leaves: list[bytes], proof: list[bytes]) -> bool:
    """
    Verify the log grew consistently: the first `old_size` of `new_leaves`
    must still hash to `old_root`, and the full set must hash to the claimed
    new root in the proof. This catches any rewrite of historical entries.
    """
    if old_size <= 0 or old_size > len(new_leaves):
        return False
    if len(proof) != 2:
        return False
    claimed_old_root, claimed_new_root = proof
    if claimed_old_root != old_root:
        return False
    # The old prefix must be unchanged...
    if merkle_root(new_leaves[:old_size]) != old_root:
        return False
    # ...and the claimed new root must match the actual full tree.
    if merkle_root(new_leaves) != claimed_new_root:
        return False
    return True
