"""
action_guard.py  -  Tombstone's intercept-and-prove spine, pointed at AGENT ACTIONS.

The proxy/policy layer asks: "is this DATA allowed to flow to this destination?"
This layer asks a different question: "is this agent allowed to DO this?" and it
asks BEFORE an irreversible action (delete, overwrite, drop, spend) actually runs.

Two ways to use it:

  1. Advisory: call guard.check_action(...) yourself and honor the Decision.
  2. Enforced: wrap a real function with guard.guarded(...). The wrapper checks
     the guard first and RAISES ActionBlocked if denied, so the underlying
     function never runs. This is how you give an agent a tool it cannot misuse:
     hand it the guarded tool, not the raw capability.

Either way, every decision is sealed to the tamper-evident ledger, so there is
a signed receipt of what the agent tried to do and whether it was stopped.

Honest scope: enforcement covers actions the agent takes THROUGH guarded tools.
If you also hand the agent the raw, unguarded capability (a bare os.remove), it
can bypass the guard. The deployment rule is therefore simple: give the agent
only guarded tools for anything risky. Tombstone is the wrapper you put around
every dangerous tool, not a kernel hook.
"""

import functools
import hashlib

from .policy import Decision  # reuse the project's allow/block result type


# Verbs treated as irreversible / high blast radius by default.
DESTRUCTIVE_ACTIONS = {
    "delete", "drop", "rm", "destroy", "overwrite", "truncate", "wipe", "purge",
}


class ActionBlocked(Exception):
    """Raised when a guarded action is denied. The wrapped function never runs."""

    def __init__(self, decision: "Decision"):
        self.decision = decision
        super().__init__(decision.reason)


class ActionGuard:
    """Gate that an agent calls before performing an action.

    guard.check_action("delete", "/path/to/docs") -> Decision(allowed, reason)
    guard.guarded("delete")(real_delete_fn)        -> a tool that enforces it
    """

    def __init__(self, ledger=None, step_budget=None, loop_threshold=5):
        self.ledger = ledger
        self.step_budget = step_budget
        self.loop_threshold = loop_threshold
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

        if self.step_budget is not None and self._steps > self.step_budget:
            return self._record(
                False, action_type, target,
                f"step budget exceeded ({self._steps} > {self.step_budget}): possible runaway",
            )

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

        if atype in DESTRUCTIVE_ACTIONS and self._target_is_protected(target):
            return self._record(
                False, action_type, target,
                f"destructive '{action_type}' on protected target requires human sign-off",
            )

        return self._record(True, action_type, target, "action permitted")

    def guarded(self, action_type: str, target_from=None):
        """Wrap a real callable so it MUST pass the guard before it runs.

        If the guard denies the action, the wrapped function is never called and
        ActionBlocked is raised. target_from optionally extracts the target to
        judge from the call args; by default the first positional arg is used.
        """
        def decorator(fn):
            @functools.wraps(fn)
            def wrapper(*args, **kwargs):
                if target_from is not None:
                    target = str(target_from(*args, **kwargs))
                else:
                    target = str(args[0]) if args else ""
                decision = self.check_action(action_type, target)
                if not decision.allowed:
                    raise ActionBlocked(decision)
                return fn(*args, **kwargs)
            return wrapper
        return decorator

    def _target_is_protected(self, target: str) -> bool:
        return any(p in target for p in self._protected_paths)

    def _record(self, allowed: bool, action_type: str, target: str, reason: str) -> Decision:
        decision = Decision(allowed, reason, matched=[f"{action_type}:{target}"] if target else [])
        if self.ledger is not None:
            commit = hashlib.sha256(
                f"{allowed}|{action_type}|{target}|{reason}".encode()
            ).hexdigest()
            event = "action_allowed" if allowed else "action_blocked"
            self.ledger.append("agent", event, commit)
        return decision
