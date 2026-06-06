"""
tombstone.integrations.langchain  -  wrap LangChain tools with an ActionGuard.

Give your LangChain agent GUARDED tools instead of raw ones. When the agent
calls a guarded tool to do something forbidden (a destructive action on a
protected target, or a runaway loop), Tombstone stops it before the underlying
function runs, and seals the attempt to the tamper-evident ledger.

The point: an LLM agent can only act through the tools you give it. Give it
guarded tools and "the agent went rogue and deleted everything" stops being
possible, because the dangerous tool refuses to run.

Requires: pip install langchain-core

Usage:

    from tombstone.action_guard import ActionGuard
    from tombstone.integrations.langchain import guarded_tool

    guard = ActionGuard(ledger=ledger)
    guard.protect_path("/important/data")

    def delete_path(path: str) -> str:
        '''Delete a file or directory at the given path.'''
        shutil.rmtree(path)
        return f"deleted {path}"

    tool = guarded_tool(guard, "delete", delete_path)
    # hand `tool` to your agent instead of a raw delete
"""

import functools
from typing import Callable, Optional

from ..action_guard import ActionGuard, ActionBlocked


def _default_target(*args, **kwargs) -> str:
    """Best-effort extraction of the action's target from call arguments.

    LangChain calls tools with keyword arguments from the schema, so we look at
    kwargs first, then positional args. Override with target_from for control.
    """
    if kwargs:
        return str(next(iter(kwargs.values())))
    if args:
        return str(args[0])
    return ""


def guarded_tool(
    guard: ActionGuard,
    action_type: str,
    func: Callable,
    *,
    name: Optional[str] = None,
    description: Optional[str] = None,
    target_from: Optional[Callable] = None,
    on_block: str = "raise",
    args_schema=None,
):
    """Return a LangChain StructuredTool whose execution is gated by `guard`.

    action_type: the verb the guard judges (e.g. "delete", "call", "overwrite").
    on_block:
        "raise"  -> a denied call raises ActionBlocked (hard stop, the real
                    function never runs). Use for truly irreversible actions.
        "return" -> a denied call returns a short message the agent can see and
                    react to, and the real function still never runs. Use when
                    you want the agent to recover gracefully instead of halting.
    target_from: optional function(*args, **kwargs) -> str to extract the target
                 the guard should judge. Defaults to the first argument.
    """
    if on_block not in ("raise", "return"):
        raise ValueError("on_block must be 'raise' or 'return'")

    try:
        from langchain_core.tools import StructuredTool
    except ImportError as exc:
        raise ImportError(
            "guarded_tool requires langchain-core. Install: pip install langchain-core"
        ) from exc

    extractor = target_from or _default_target
    inner = guard.guarded(action_type, target_from=extractor)(func)

    # functools.wraps preserves func's signature and type hints, which LangChain
    # needs to build the tool's input schema. Without it the schema is empty and
    # the tool is called with no arguments.
    @functools.wraps(func)
    def runner(*args, **kwargs):
        try:
            return inner(*args, **kwargs)
        except ActionBlocked as exc:
            if on_block == "return":
                return f"BLOCKED by Tombstone: {exc}"
            raise

    return StructuredTool.from_function(
        func=runner,
        name=name or func.__name__,
        description=description or (func.__doc__ or "").strip() or func.__name__,
        args_schema=args_schema,
    )
