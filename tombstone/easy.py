"""
tombstone.easy  -  add Tombstone to any agent in two lines.

    from tombstone.easy import Tombstone

    tb = Tombstone(protect=["./data"], budget=50)   # a ledger + guard, ready
    tools = tb.guard_all(tools)                      # wrap your tools

Now your agent cannot:
  - run away: after `budget` tool calls it is stopped (a cost ceiling),
  - loop:     the same call repeated `loop` times in a row is stopped,
  - destroy protected data: a delete/drop/overwrite on a protected path is stopped.

Every decision, allowed or blocked, is sealed to a tamper-evident ledger.
Check it any time with tb.verify().

Works with plain Python functions (any framework that calls tools as functions:
CrewAI, AutoGen, a raw OpenAI or Anthropic tool loop) and with LangChain tools.
"""

import functools
import os
import tempfile
from typing import Callable

from .ledger import Ledger
from .action_guard import ActionGuard, ActionBlocked, DESTRUCTIVE_ACTIONS


def _default_target(*args, **kwargs) -> str:
    """Best-effort extraction of the target the guard should judge.

    Frameworks call tools with keyword args from a schema, so check kwargs
    first, then positional args.
    """
    if kwargs:
        return str(next(iter(kwargs.values())))
    if args:
        return str(args[0])
    return ""


def _infer_action(name: str) -> str:
    """Pick the guard's action verb from a tool name.

    If the name looks destructive (delete_file, drop_table, remove_dir), use
    that verb so protected-path enforcement kicks in. Otherwise 'call', which
    still counts toward the runaway budget and the loop detector.
    """
    low = (name or "").lower()
    for verb in DESTRUCTIVE_ACTIONS:
        if verb in low:
            return verb
    return "call"


def _is_langchain_tool(obj) -> bool:
    return (hasattr(obj, "func") and hasattr(obj, "name")
            and callable(getattr(obj, "func", None)))


class Tombstone:
    """One object that holds a ledger + guard and wraps your tools."""

    def __init__(self, protect=(), budget=50, loop=5, ledger_path=None, on_block="raise"):
        if on_block not in ("raise", "return"):
            raise ValueError("on_block must be 'raise' or 'return'")
        if ledger_path is None:
            ledger_path = os.path.join(tempfile.mkdtemp(prefix="tombstone_"), "ledger.jsonl")
        self.ledger = Ledger(ledger_path)
        self.ledger_path = str(self.ledger.path)
        self._guard = ActionGuard(ledger=self.ledger, step_budget=budget, loop_threshold=loop)
        self.on_block = on_block

        paths = [protect] if isinstance(protect, str) else list(protect)
        for p in paths:
            # Register both the given form and the absolute form so a relative
            # or absolute call argument both match the protected target.
            self._guard.protect_path(p, os.path.abspath(p))

    def guard(self, fn: Callable, action: str = None) -> Callable:
        """Wrap one tool (a plain function or a LangChain tool). Returns the
        guarded version to hand your agent instead of the raw one."""
        if _is_langchain_tool(fn):
            from .integrations.langchain import guarded_tool
            act = action or _infer_action(getattr(fn, "name", "") or getattr(fn.func, "__name__", ""))
            return guarded_tool(
                self._guard, act, fn.func, name=fn.name,
                description=getattr(fn, "description", None), on_block=self.on_block,
            )

        act = action or _infer_action(getattr(fn, "__name__", "call"))
        inner = self._guard.guarded(act, target_from=_default_target)(fn)

        @functools.wraps(fn)
        def runner(*args, **kwargs):
            try:
                return inner(*args, **kwargs)
            except ActionBlocked as exc:
                if self.on_block == "return":
                    return f"BLOCKED by Tombstone: {exc}"
                raise
        return runner

    def guard_all(self, tools):
        """Wrap a whole list of tools at once."""
        return [self.guard(t) for t in tools]

    def verify(self):
        """(ok, message) - does the ledger still verify?"""
        return self.ledger.verify()

    def entries(self):
        """The sealed decisions so far: list of (event_type, target)."""
        out = []
        for e in self.ledger._entries():
            out.append((e["event_type"], e.get("subject_id", "")))
        return out


# Module-level shortcut for the one-liner crowd.
def protect(tools, files=(), budget=50, loop=5, on_block="raise"):
    """Wrap a list of tools and return (guarded_tools, tombstone).

        guarded, tb = protect(tools, files=["./data"], budget=50)
    """
    tb = Tombstone(protect=files, budget=budget, loop=loop, on_block=on_block)
    return tb.guard_all(tools), tb
