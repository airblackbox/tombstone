"""Trajectory commitment, vendored AIR contract (Path A).

Byte-identical copy of air_blackbox.trajectory / the Go pkg/trajectory: same
TRAJ-STEP-v1 canonical encoding, same domain-separated Merkle construction,
same (depth, step_id) ordering. Pinned to the shared vector in
tests/testdata/canonical_vector.json, so a trajectory root committed here (where
ActionGuard captures agent actions) equals the root the Go gateway anchors to
Rekor.

Vendored rather than imported so Tombstone stays pip-installable standalone;
the vector test fails loudly if this ever drifts from the contract. If the
duplication becomes painful, extract a shared air-trajectory micro-package.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Dict, List

CANONICAL_STEP_VERSION = "TRAJ-STEP-v1"


@dataclass
class Step:
    step_id: str
    kind: str
    input_hash: str = ""
    output_hash: str = ""
    gate_verdict: str = "n/a"
    timestamp: str = ""  # RFC3339 UTC
    parent_ids: List[str] = field(default_factory=list)

    def canonical(self) -> bytes:
        """Language-neutral, newline-delimited encoding. Must match Go exactly."""
        for v in [self.step_id, self.kind, self.input_hash, self.output_hash,
                  self.gate_verdict, self.timestamp, *self.parent_ids]:
            if "\n" in v:
                raise ValueError(f"trajectory: field contains newline: {v!r}")
        parents = ",".join(sorted(self.parent_ids))
        fields = [
            CANONICAL_STEP_VERSION, self.step_id, parents, self.kind,
            self.input_hash, self.output_hash, self.gate_verdict, self.timestamp,
        ]
        return "\n".join(fields).encode("utf-8")


def _leaf(data: bytes) -> bytes:
    h = hashlib.sha256()
    h.update(b"\x00")
    h.update(data)
    return h.digest()


def _node(left: bytes, right: bytes) -> bytes:
    h = hashlib.sha256()
    h.update(b"\x01")
    h.update(left)
    h.update(right)
    return h.digest()


def _merkle_root(leaves: List[bytes]) -> bytes:
    if not leaves:
        raise ValueError("trajectory: no leaves")
    level = list(leaves)
    while len(level) > 1:
        nxt = []
        for i in range(0, len(level), 2):
            if i + 1 < len(level):
                nxt.append(_node(level[i], level[i + 1]))
            else:
                nxt.append(level[i])  # promote lone node (RFC 6962)
        level = nxt
    return level[0]


def _canonical_order(steps: Dict[str, Step]) -> List[str]:
    """Sort step IDs by (causal depth, step_id). Depth = longest path from a
    root. Raises on unknown parent or cycle. Identical rule to the Go side."""
    depth: Dict[str, int] = {}
    visiting: Dict[str, bool] = {}

    def resolve(sid: str) -> int:
        if sid in depth:
            return depth[sid]
        if sid not in steps:
            raise ValueError(f"trajectory: step {sid!r} references unknown parent")
        if visiting.get(sid):
            raise ValueError(f"trajectory: cycle detected at step {sid!r}")
        visiting[sid] = True
        mx = -1
        for p in steps[sid].parent_ids:
            mx = max(mx, resolve(p))
        visiting[sid] = False
        depth[sid] = mx + 1
        return depth[sid]

    for sid in steps:
        resolve(sid)
    return sorted(steps.keys(), key=lambda s: (depth[s], s))


def commit_root(steps: List[Step]) -> str:
    """Compute the hex Merkle step root for a trajectory's steps."""
    by_id: Dict[str, Step] = {}
    for s in steps:
        if not s.step_id:
            raise ValueError("trajectory: step_id required")
        if s.step_id in by_id:
            raise ValueError(f"trajectory: duplicate step_id {s.step_id!r}")
        by_id[s.step_id] = s
    if not by_id:
        raise ValueError("trajectory: no steps to commit")
    order = _canonical_order(by_id)
    leaves = [_leaf(by_id[sid].canonical()) for sid in order]
    return _merkle_root(leaves).hex()


def leaf_hex(step: Step) -> str:
    """Hex leaf hash of a single step (for vector checks)."""
    return _leaf(step.canonical()).hex()
