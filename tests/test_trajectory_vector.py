"""Tombstone's vendored encoder must reproduce the shared cross-language vector.
If this passes here and in the gateway repo, Tombstone (Python capture) and the
Go anchoring stack commit byte-identical roots."""
import json
import os

from tombstone.trajectory import Step, commit_root, leaf_hex

VECTOR = os.path.join(os.path.dirname(__file__), "testdata", "canonical_vector.json")


def test_vendored_encoder_matches_contract():
    with open(VECTOR) as f:
        vec = json.load(f)
    steps = [
        Step(step_id=s["step_id"], kind=s["kind"],
             input_hash=s.get("input_hash", ""), output_hash=s.get("output_hash", ""),
             gate_verdict=s.get("gate_verdict", "n/a"), timestamp=s.get("timestamp", ""),
             parent_ids=s.get("parent_ids") or [])
        for s in vec["steps"]
    ]
    for s, expected in zip(steps, vec["leaf_hashes"]):
        assert leaf_hex(s) == expected, f"leaf mismatch at {s.step_id}"
    assert commit_root(steps) == vec["expected_root"]
