"""ActionGuard -> AIR trajectory bridge (Phase 2, Path A).

ActionGuard already decides whether an agent may act and seals the decision to
its ledger. This bridge additionally records each decision as an AIR trajectory
Step carrying the gate verdict, and commits the run to a single Merkle root.
That root is what the Go gateway anchors with ML-DSA-65 + Rekor, so the proof
boundary covers the world-affecting action, not just the LLM call that proposed
it.

See docs/SPEC-trajectory-chain.md in the gateway repo. The verdict mapping is
faithful to ActionGuard's three real outcomes:

  allowed                              -> permit
  blocked, needs human sign-off        -> require_approval
  blocked, budget/loop/other           -> forbid
"""
from __future__ import annotations

import hashlib
from typing import List, Optional

from tombstone.trajectory import Step, commit_root


def _sha(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def verdict_from_decision(decision) -> str:
    """Map an ActionGuard Decision to a trajectory gate verdict.

    A destructive action on a protected target is a human-sign-off case, which
    is semantically require_approval rather than a hard forbid; everything else
    that is blocked (step budget, loop) is a forbid.
    """
    if getattr(decision, "allowed", False):
        return "permit"
    reason = (getattr(decision, "reason", "") or "").lower()
    if "sign-off" in reason or "approval" in reason or "sign off" in reason:
        return "require_approval"
    return "forbid"


class TrajectoryRecorder:
    """Accumulates the steps of one agent run and commits them to a root.

    Steps auto-chain linearly (each new step's parent is the previous one)
    unless explicit parent_ids are given, which is how branches are expressed.
    """

    def __init__(self, trajectory_id: str, root_goal: str = ""):
        self.trajectory_id = trajectory_id
        self.root_goal_hash = _sha(root_goal) if root_goal else ""
        self._steps: List[Step] = []
        self._last_id: Optional[str] = None
        self._n = 0

    def _next_id(self, prefix: str) -> str:
        self._n += 1
        return f"{prefix}{self._n}"

    def _add(self, step: Step) -> str:
        self._steps.append(step)
        self._last_id = step.step_id
        return step.step_id

    def _parents(self, parent_ids: Optional[List[str]]) -> List[str]:
        if parent_ids is not None:
            return parent_ids
        return [self._last_id] if self._last_id is not None else []

    def record_llm(self, prompt: str, completion: str, *, step_id: str = "",
                   parent_ids: Optional[List[str]] = None, timestamp: str = "") -> str:
        sid = step_id or self._next_id("s")
        return self._add(Step(
            step_id=sid, kind="llm_call", input_hash=_sha(prompt),
            output_hash=_sha(completion), gate_verdict="n/a",
            timestamp=timestamp, parent_ids=self._parents(parent_ids),
        ))

    def record_action(self, action_type: str, target: str, decision, *,
                      kind: str = "action", result: Optional[str] = None,
                      step_id: str = "", parent_ids: Optional[List[str]] = None,
                      timestamp: str = "") -> str:
        """Record a guarded action with the verdict ActionGuard returned.

        A blocked action has no output, so its output_hash is empty; a permitted
        action hashes its result if one is supplied.
        """
        sid = step_id or self._next_id("s")
        verdict = verdict_from_decision(decision)
        out = _sha(result) if (result is not None and getattr(decision, "allowed", False)) else ""
        return self._add(Step(
            step_id=sid, kind=kind, input_hash=_sha(f"{action_type}:{target}"),
            output_hash=out, gate_verdict=verdict, timestamp=timestamp,
            parent_ids=self._parents(parent_ids),
        ))

    def commit(self, outcome: str = "completed") -> dict:
        """Commit the run to a trajectory summary, including the Merkle root.

        The returned dict is exactly what the Go anchor bridge consumes.
        """
        return {
            "trajectory_id": self.trajectory_id,
            "root_goal_hash": self.root_goal_hash,
            "step_root": commit_root(self._steps),
            "step_count": len(self._steps),
            "outcome": outcome,
        }


def guarded_step(guard, recorder: TrajectoryRecorder, action_type: str,
                 *, target_from=None):
    """Decorator: enforce via ActionGuard AND record the decision as a step.

    Mirrors ActionGuard.guarded but also writes a trajectory step for every
    attempt, permitted or blocked, so the trajectory reflects what the agent
    tried, not only what it succeeded at.
    """
    import functools
    from tombstone.action_guard import ActionBlocked

    def decorator(fn):
        @functools.wraps(fn)
        def wrapper(*args, **kwargs):
            target = str(target_from(*args, **kwargs)) if target_from else (
                str(args[0]) if args else "")
            decision = guard.check_action(action_type, target)
            if not decision.allowed:
                recorder.record_action(action_type, target, decision, kind="action")
                raise ActionBlocked(decision)
            result = fn(*args, **kwargs)
            recorder.record_action(action_type, target, decision, kind="action",
                                   result=str(result))
            return result
        return wrapper
    return decorator
