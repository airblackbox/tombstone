"""
mcp_proxy.py  -  put Tombstone between any MCP client and any MCP server.

No code changes to the agent. The proxy speaks MCP's stdio transport (one
JSON-RPC message per line), spawns the real server, and relays everything
except the `tools/call` requests it decides to block.

For every tools/call it:

  1. asks the ActionGuard: destructive verb on a protected path? over the
     step budget? the same call repeated in a loop?  -> blocked
  2. asks the Policy: do the tool arguments contain a protected person's data
     (registered values or PII patterns)?             -> blocked
  3. seals the decision, allowed or blocked, to the tamper-evident ledger.

A blocked call never reaches the server. The client receives a normal MCP tool
result with isError=true and a plain-English reason, so the agent can recover.

Usage (Claude Code, Cursor, any MCP host: put this as the server command):

    python -m tombstone.mcp_proxy \\
        --protect ./data --protect ./prod \\
        --protect-value "jose@example.com" --protect-value "Jose Rios" \\
        --budget 200 --loop 5 --ledger ./tombstone_ledger.jsonl \\
        -- npx -y @modelcontextprotocol/server-filesystem /path/to/workspace

Everything after `--` is the real server's command line.

Honest scope: the proxy sees the arguments the agent sends to tools and the
tool names. It does not see what the server does internally, and it cannot
guard a tool the agent reaches without going through this proxy.
"""

import argparse
import json
import os
import subprocess
import sys
import threading

from .action_guard import ActionGuard
from .easy import _infer_action
from .ledger import Ledger
from .policy import Policy, _mask


def _target_of(arguments) -> str:
    """Best-effort target for the guard: an explicit path-like key first,
    otherwise the first string argument."""
    if not isinstance(arguments, dict):
        return str(arguments) if arguments is not None else ""
    for key in ("path", "file", "filepath", "file_path", "directory", "dir", "target", "uri", "url"):
        v = arguments.get(key)
        if isinstance(v, str):
            return v
    for v in arguments.values():
        if isinstance(v, str):
            return v
    return ""


class TombstoneMCPProxy:
    def __init__(self, server_cmd, protect=(), protect_values=(), budget=200, loop=5,
                 ledger_path="tombstone_ledger.jsonl", block_pii=False):
        self.server_cmd = list(server_cmd)
        self.ledger = Ledger(ledger_path)
        self.guard = ActionGuard(ledger=self.ledger, step_budget=budget, loop_threshold=loop)
        for p in protect:
            self.guard.protect_path(p)
        self.policy = None
        if protect_values or block_pii:
            self.policy = Policy()
            self.policy.protect("subject", *protect_values)
            self.policy.block_pii_patterns = bool(block_pii)
            self.policy.block_destination("*")   # every tool is a restricted destination
        self._out_lock = threading.Lock()
        self._proc = None

    # ---- decision ----

    def decide(self, tool_name: str, arguments) -> tuple[bool, str]:
        """(allowed, reason). Records to the ledger either way."""
        verb = _infer_action(tool_name)
        target = _target_of(arguments)
        d = self.guard.check_action(verb, target)
        if not d.allowed:
            return False, d.reason
        if self.policy is not None:
            payload = json.dumps(arguments, sort_keys=True) if arguments is not None else ""
            pd = self.policy.check_payload(tool_name, payload)
            commit = (f"flow-decision:{'ALLOW' if pd.allowed else 'BLOCK'}:{tool_name}:"
                      f"{','.join(pd.matched) if pd.matched else 'clean'}")
            self.ledger.append("proxy", "flow_decision", commit)
            if not pd.allowed:
                return False, f"protected personal data in arguments to '{tool_name}' ({', '.join(pd.matched)})"
        return True, d.reason

    # ---- plumbing ----

    def _write_client(self, line: bytes) -> None:
        with self._out_lock:
            sys.stdout.buffer.write(line if line.endswith(b"\n") else line + b"\n")
            sys.stdout.buffer.flush()

    def _write_server(self, line: bytes) -> None:
        self._proc.stdin.write(line if line.endswith(b"\n") else line + b"\n")
        self._proc.stdin.flush()

    def _blocked_response(self, req_id, reason: str) -> bytes:
        body = {
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {
                "content": [{"type": "text", "text": f"BLOCKED by Tombstone: {reason}"}],
                "isError": True,
            },
        }
        return json.dumps(body).encode()

    def _client_to_server(self) -> None:
        for raw in sys.stdin.buffer:
            line = raw.rstrip(b"\r\n")
            if not line:
                continue
            try:
                msg = json.loads(line)
            except ValueError:
                self._write_server(line)
                continue
            if isinstance(msg, dict) and msg.get("method") == "tools/call":
                params = msg.get("params") or {}
                name = str(params.get("name", ""))
                allowed, reason = self.decide(name, params.get("arguments"))
                if not allowed:
                    sys.stderr.write(f"[tombstone] BLOCKED {name}: {reason}\n")
                    sys.stderr.flush()
                    self._write_client(self._blocked_response(msg.get("id"), reason))
                    continue
            self._write_server(line)
        try:
            self._proc.stdin.close()
        except OSError:
            pass

    def _server_to_client(self) -> None:
        for raw in self._proc.stdout:
            self._write_client(raw)

    def run(self) -> int:
        self._proc = subprocess.Popen(
            self.server_cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=sys.stderr,
        )
        t_in = threading.Thread(target=self._client_to_server, daemon=True)
        t_out = threading.Thread(target=self._server_to_client, daemon=True)
        t_in.start()
        t_out.start()
        t_out.join()          # server closed stdout: it exited
        return self._proc.wait()


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        prog="python -m tombstone.mcp_proxy",
        description="Guard any MCP server with Tombstone. Put the real server command after --.",
    )
    ap.add_argument("--protect", action="append", default=[], metavar="PATH",
                    help="path that destructive tools may not touch (repeatable)")
    ap.add_argument("--protect-value", action="append", default=[], metavar="TEXT",
                    help="a person's data (email, name) that must not appear in tool arguments (repeatable)")
    ap.add_argument("--block-pii", action="store_true",
                    help="also block arguments matching generic PII patterns (email, SSN, card number)")
    ap.add_argument("--budget", type=int, default=200, help="max tool calls per session (default 200)")
    ap.add_argument("--loop", type=int, default=5, help="identical calls in a row before blocking (default 5)")
    ap.add_argument("--ledger", default=os.environ.get("TOMBSTONE_LEDGER", "tombstone_ledger.jsonl"),
                    help="ledger path (default tombstone_ledger.jsonl or $TOMBSTONE_LEDGER)")
    ap.add_argument("server", nargs=argparse.REMAINDER, help="-- then the real MCP server command")
    args = ap.parse_args(argv)

    cmd = [c for c in args.server if c != "--"] if args.server else []
    if not cmd:
        ap.error("missing server command: add `-- <command> [args...]` after the options")

    proxy = TombstoneMCPProxy(
        cmd, protect=args.protect, protect_values=args.protect_value, budget=args.budget,
        loop=args.loop, ledger_path=args.ledger, block_pii=args.block_pii,
    )
    sys.stderr.write(f"[tombstone] guarding {' '.join(cmd)}  ledger={proxy.ledger.path}\n")
    sys.stderr.flush()
    return proxy.run()


if __name__ == "__main__":
    sys.exit(main())
