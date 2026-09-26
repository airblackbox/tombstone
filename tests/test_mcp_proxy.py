"""End-to-end: the Tombstone MCP proxy in front of a real stdio MCP server."""
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from tombstone.ledger import Ledger

ROOT = Path(__file__).resolve().parent.parent
FAKE = str(Path(__file__).parent / "mcp_fake_server.py")


class ProxyClient:
    def __init__(self, tmp_path, *extra):
        self.ledger_path = tmp_path / "ledger.jsonl"
        self.outbox = tmp_path / "outbox.jsonl"
        env = dict(os.environ, PYTHONPATH=str(ROOT), FAKE_OUTBOX=str(self.outbox))
        cmd = [sys.executable, "-m", "tombstone.mcp_proxy", "--ledger", str(self.ledger_path),
               *extra, "--", sys.executable, FAKE]
        self.proc = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                     stderr=subprocess.PIPE, env=env, cwd=str(tmp_path))
        self._id = 0

    def request(self, method, params=None):
        self._id += 1
        msg = {"jsonrpc": "2.0", "id": self._id, "method": method}
        if params is not None:
            msg["params"] = params
        self.proc.stdin.write((json.dumps(msg) + "\n").encode())
        self.proc.stdin.flush()
        line = self.proc.stdout.readline()
        assert line, "proxy closed without replying"
        resp = json.loads(line)
        assert resp["id"] == self._id
        return resp["result"]

    def call(self, name, arguments):
        return self.request("tools/call", {"name": name, "arguments": arguments})

    def close(self):
        self.proc.stdin.close()
        self.proc.wait(timeout=10)


def _text(result):
    return result["content"][0]["text"]


def test_proxy_forwards_initialize_and_tool_list(tmp_path):
    c = ProxyClient(tmp_path)
    try:
        init = c.request("initialize", {"protocolVersion": "2025-03-26", "capabilities": {}})
        assert init["serverInfo"]["name"] == "fake"
        tools = c.request("tools/list")
        assert {t["name"] for t in tools["tools"]} == {"delete_file", "send_email", "transform_data"}
    finally:
        c.close()


def test_proxy_blocks_delete_on_protected_path_and_allows_elsewhere(tmp_path):
    protected = tmp_path / "data"
    protected.mkdir()
    keep = protected / "keep.txt"
    keep.write_text("irreplaceable")
    scratch = tmp_path / "scratch.txt"
    scratch.write_text("junk")

    c = ProxyClient(tmp_path, "--protect", "./data")
    try:
        # Relative spelling of a protected path: blocked, file survives.
        r = c.call("delete_file", {"path": "data/keep.txt"})
        assert r.get("isError") is True
        assert "BLOCKED by Tombstone" in _text(r)
        assert keep.exists()

        # A harmless tool whose name contains "rm" is not treated as destructive.
        r = c.call("transform_data", {"path": "data/keep.txt"})
        assert "transformed" in _text(r)
        assert keep.exists()

        # Outside the protected path: forwarded and executed for real.
        r = c.call("delete_file", {"path": str(scratch)})
        assert "deleted" in _text(r)
        assert not scratch.exists()
    finally:
        c.close()

    ok, msg = Ledger(str(c.ledger_path)).verify()
    assert ok, msg
    events = [e["event_type"] for e in Ledger(str(c.ledger_path))._entries()]
    assert events.count("action_blocked") == 1
    assert events.count("action_allowed") == 2


def test_proxy_blocks_protected_person_data_in_arguments(tmp_path):
    c = ProxyClient(tmp_path, "--protect-value", "jose@example.com", "--protect-value", "Jose Rios")
    try:
        r = c.call("send_email", {"to": "partner@example.org", "body": "Contact: Jose Rios"})
        assert r.get("isError") is True
        assert "protected personal data" in _text(r)

        r = c.call("send_email", {"to": "partner@example.org", "body": "Q3 numbers attached"})
        assert _text(r) == "sent"
    finally:
        c.close()

    sent = [json.loads(l) for l in c.outbox.read_text().splitlines()]
    assert len(sent) == 1
    assert "Jose" not in json.dumps(sent)

    entries = Ledger(str(c.ledger_path))._entries()
    flows = [e["data_commitment"] for e in entries if e["event_type"] == "flow_decision"]
    assert any(f.startswith("flow-decision:BLOCK:send_email:") for f in flows)
    # The ledger never carries the protected value in the clear.
    assert "jose@example.com" not in json.dumps(entries)
    assert "Jose Rios" not in json.dumps(entries)


def test_proxy_kills_a_loop(tmp_path):
    c = ProxyClient(tmp_path, "--loop", "3")
    try:
        results = [c.call("transform_data", {"path": "x"}) for _ in range(4)]
    finally:
        c.close()
    assert [r.get("isError", False) for r in results] == [False, False, True, True]
    assert "loop detected" in _text(results[2])


def test_proxy_requires_a_server_command():
    proc = subprocess.run([sys.executable, "-m", "tombstone.mcp_proxy"], capture_output=True,
                          env=dict(os.environ, PYTHONPATH=str(ROOT)))
    assert proc.returncode != 0
    assert b"missing server command" in proc.stderr
