"""
action_guard.py  -  Tombstone's intercept-and-prove spine, pointed at AGENT ACTIONS.

The proxy/policy layer asks: "is this DATA allowed to flow to this destination?"
This layer asks a different question: "is this agent allowed to DO this?" and it
asks BEFORE an irreversible action (delete, overwrite, drop, spend) actually runs.

Same spine as the rest of Tombstone: every decision is sealed to the
tamper-evident ledger, so there is a signed receipt of what the agent tried to
do and whether it was stopped. Observe-only tools record the disaster after it
happens. This stops it first, then proves it.

Honest scope: this is a policy gate the agent must consult before acting. It
only protects actions that are actually routed through it. It is not a kernel
hook and cannot stop code that bypasses the guard. The value is the pattern:
check before the irreversible step, and seal a receipt either way.
"""

import hashlib
from .policy import Decision  # reuse the project's allow/block result type


# Verbs treated as irreversible / high blast radius by default.
DESTRUCTIVE_ACTIONS = {
    "delete", "drop", "rm", "destroy", "overwrite", "truncate", "wipe", "purge",
}


class ActionGuard:
    """Gate that an agent calls before performing an action.

    guard.check_action("delete", "/path/to/docs") -> Decision(allowed, reason)
    """

    def __init__(self, ledger=None, step_budget=None, loop_threshold=5):
        self.ledger = ledger                  # tamper-evident ledger (optional but recommended)
        self.step_budget = step_budget        # max total actions before we call it a runaway
        self.loop_threshold = loop_threshold  # identical actions IN A ROW before we call it a loop
        self._protected_paths: set[str] = set()
        self._steps = 0
        self._last_sig: str | None = None
        self._consecutive = 0

    def protect_path(self, *paths: str) -> None:
        """Mark targets that must never be destroyed without human sign-off."""
        self._protected_paths.update(p for p in paths if p)

    def check_action(self, action_type: str, target: str = "", **context) -> Decision:
        self._steps += 1
        atype = action_type.lower().strip()
        sig = f"{atype}:{target}"

        # 1. Runaway budget: too many actions overall.
        if self.step_budget is not None and self._steps > self.step_budget:
            return self._record(
                False, action_type, target,
                f"step budget exceeded ({self._steps} > {self.step_budget}): possible runaway",
            )

        # 2. Loop detection: same action+target repeated consecutively.
        if sig == self._last_sig:
            self._consecutive += 1
        else:
            self._consecutive = 1
            self._last_sig = sig
        if self._consecutive >= self.loop_threshold:
            return self._record(
                False, action_type, target,
                f"loop detected: '{sig}' repeated {self._consecutive}x in a row",
            )

        # 3. Destructive action against a protected target.
        if atype in DESTRUCTIVE_ACTIONS and self._target_is_protected(target):
            return self._record(
                False, action_type, target,
                f"destructive '{action_type}' on protected target requires human sign-off",
            )

        return self._record(True, action_type, target, "action permitted")

    def _target_is_protected(self, target: str) -> bool:
        return any(p in target for p in self._protected_paths)

    def _record(self, allowed: bool, action_type: str, target: str, reason: str) -> Decision:
        decision = Decision(allowed, reason, matched=[f"{action_type}:{target}"] if target else [])
        if self.ledger is not None:
            # Commit to a hash of the decision, never the raw target, so the
            # ledger stays a commitment log and not a data leak.
            commit = hashlib.sha256(
                f"{allowed}|{action_type}|{target}|{reason}".encode()
            ).hexdigest()
            event = "action_allowed" if allowed else "action_blocked"
            self.ledger.append("agent", event, commit)
        return decision
