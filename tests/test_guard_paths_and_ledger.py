"""Regression tests for the code review fixes:

- protected paths match by real location, not by substring
- destructive verbs are inferred from whole words in a tool name
- the ledger survives concurrent appends
- a deleted head file cannot hide a truncation
"""
import json
import os
import threading
from pathlib import Path

import pytest

from tombstone.action_guard import ActionGuard, ActionBlocked
from tombstone.easy import Tombstone, _infer_action
from tombstone.ledger import Ledger


# ---- protected paths -------------------------------------------------------

def test_relative_and_parent_paths_cannot_bypass_protection(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "data").mkdir()
    target = tmp_path / "data" / "f.txt"

    tb = Tombstone(protect=["./data"], budget=50)

    def delete_file(path):
        os.remove(path)
        return "deleted"

    guarded = tb.guard(delete_file)
    spellings = [
        "./data/f.txt",
        "data/f.txt",
        str(target),
        f"../{tmp_path.name}/data/f.txt",
        "./data/../data/f.txt",
    ]
    for spelling in spellings:
        target.write_text("x")
        with pytest.raises(ActionBlocked):
            guarded(spelling)
        assert target.exists(), f"{spelling!r} bypassed the guard"


def test_sibling_with_same_prefix_is_not_protected(tmp_path):
    guard = ActionGuard()
    guard.protect_path(str(tmp_path / "data"))
    # "/x/data" must not also protect "/x/database".
    assert guard.check_action("delete", str(tmp_path / "database")).allowed is True
    assert guard.check_action("delete", str(tmp_path / "data")).allowed is False
    assert guard.check_action("delete", str(tmp_path / "data" / "sub" / "f")).allowed is False


def test_non_path_targets_still_match_exactly():
    guard = ActionGuard()
    guard.protect_path("prod_users_table")
    assert guard.check_action("drop", "prod_users_table").allowed is False
    assert guard.check_action("drop", "staging_users_table").allowed is True


# ---- verb inference --------------------------------------------------------

@pytest.mark.parametrize("name", [
    "transform_data", "perform_search", "format_report", "confirm_order",
    "dropdown_pick", "alarm_set", "warm_cache", "informant_lookup",
])
def test_harmless_tool_names_are_not_destructive(name):
    assert _infer_action(name) == "call"


@pytest.mark.parametrize("name,verb", [
    ("delete_file", "delete"), ("drop_table", "drop"), ("rm_dir", "rm"),
    ("remove_dir", "remove"), ("overwrite_config", "overwrite"), ("PurgeCache", "purge"),
])
def test_destructive_tool_names_are_detected(name, verb):
    assert _infer_action(name) == verb


# ---- ledger ----------------------------------------------------------------

def test_concurrent_appends_keep_the_chain_intact(tmp_path):
    ledger = Ledger(str(tmp_path / "l.jsonl"))

    def writer(n):
        for i in range(25):
            ledger.append("t", "record", f"{n}-{i}")

    threads = [threading.Thread(target=writer, args=(n,)) for n in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    ok, msg = ledger.verify()
    assert ok, msg
    assert len(ledger._entries()) == 100
    # Indexes are dense and unique: no two writers claimed the same slot.
    assert [e["index"] for e in ledger._entries()] == list(range(100))


def test_reopened_ledger_continues_the_chain(tmp_path):
    path = str(tmp_path / "l.jsonl")
    Ledger(path).append("t", "record", "a")
    Ledger(path).append("t", "record", "b")
    ok, msg = Ledger(path).verify()
    assert ok, msg
    assert len(Ledger(path)._entries()) == 2


def test_deleting_head_does_not_hide_truncation(tmp_path):
    path = tmp_path / "l.jsonl"
    ledger = Ledger(str(path))
    for i in range(3):
        ledger.append("t", "record", f"c{i}")

    lines = path.read_text().splitlines()
    path.write_text("\n".join(lines[:-1]) + "\n")   # chop the last entry
    os.remove(str(path) + ".head")                  # ...and hide the evidence

    ok, msg = Ledger(str(path)).verify()
    assert ok is False
    assert "head record missing" in msg


def test_empty_ledger_without_head_still_verifies(tmp_path):
    ok, _ = Ledger(str(tmp_path / "l.jsonl")).verify()
    assert ok is True
