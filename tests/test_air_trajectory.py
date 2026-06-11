"""ActionGuard -> trajectory bridge: faithful verdicts and a committed root."""
import pytest

from tombstone.action_guard import ActionGuard, ActionBlocked
from tombstone.integrations.air_trajectory import (
    TrajectoryRecorder, verdict_from_decision, guarded_step,
)


def test_verdict_permit():
    g = ActionGuard()
    assert verdict_from_decision(g.check_action("read", "/tmp/x")) == "permit"


def test_verdict_require_approval_on_protected_destructive():
    g = ActionGuard()
    g.protect_path("/prod/db")
    d = g.check_action("delete", "/prod/db")
    assert d.allowed is False
    assert verdict_from_decision(d) == "require_approval"


def test_verdict_forbid_on_loop():
    g = ActionGuard(loop_threshold=3)
    for _ in range(2):
        g.check_action("call", "same")
    d = g.check_action("call", "same")  # third in a row trips the loop guard
    assert d.allowed is False
    assert verdict_from_decision(d) == "forbid"


def test_recorder_commits_stable_root():
    g = ActionGuard()
    g.protect_path("/prod/db")
    rec = TrajectoryRecorder("run-1", root_goal="clean up the database")
    rec.record_llm("plan the cleanup", "I will delete /prod/db", timestamp="2026-06-10T00:00:00Z")
    rec.record_action("read", "/tmp/scratch", g.check_action("read", "/tmp/scratch"),
                      result="ok", timestamp="2026-06-10T00:00:01Z")
    rec.record_action("delete", "/prod/db", g.check_action("delete", "/prod/db"),
                      timestamp="2026-06-10T00:00:02Z")
    summary = rec.commit(outcome="blocked")
    assert summary["step_count"] == 3
    assert summary["outcome"] == "blocked"
    assert len(summary["step_root"]) == 64  # sha256 hex
    # Deterministic: committing the same steps again yields the same root.
    assert rec.commit(outcome="blocked")["step_root"] == summary["step_root"]


def test_guarded_step_enforces_and_records():
    g = ActionGuard()
    g.protect_path("/prod")
    rec = TrajectoryRecorder("run-2")

    @guarded_step(g, rec, "delete")
    def delete_file(path):
        return f"deleted {path}"

    # Permitted path runs and records a permit step.
    assert delete_file("/tmp/ok") == "deleted /tmp/ok"
    # Protected path is blocked, records a require_approval step, and raises.
    with pytest.raises(ActionBlocked):
        delete_file("/prod/secrets")

    summary = rec.commit()
    assert summary["step_count"] == 2  # both the allowed and the blocked attempt
