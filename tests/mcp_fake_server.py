"""A minimal MCP server over stdio for testing the Tombstone proxy.

Tools: delete_file(path) removes a file; send_email(to, body) appends a line
to the file named in $FAKE_OUTBOX. Enough to prove the proxy blocks the right
calls and forwards the rest.
"""
import json
import os
import sys

TOOLS = [
    {"name": "delete_file", "description": "Delete a file.",
     "inputSchema": {"type": "object", "properties": {"path": {"type": "string"}}, "required": ["path"]}},
    {"name": "send_email", "description": "Send an email.",
     "inputSchema": {"type": "object", "properties": {"to": {"type": "string"}, "body": {"type": "string"}},
                     "required": ["to", "body"]}},
    {"name": "transform_data", "description": "Harmless tool whose name contains 'rm'.",
     "inputSchema": {"type": "object", "properties": {"path": {"type": "string"}}}},
]


def reply(msg_id, result):
    sys.stdout.write(json.dumps({"jsonrpc": "2.0", "id": msg_id, "result": result}) + "\n")
    sys.stdout.flush()


def call(name, args):
    if name == "delete_file":
        os.remove(args["path"])
        return {"content": [{"type": "text", "text": f"deleted {args['path']}"}]}
    if name == "send_email":
        with open(os.environ["FAKE_OUTBOX"], "a") as f:
            f.write(json.dumps(args) + "\n")
        return {"content": [{"type": "text", "text": "sent"}]}
    if name == "transform_data":
        return {"content": [{"type": "text", "text": f"transformed {args.get('path')}"}]}
    return {"content": [{"type": "text", "text": f"unknown tool {name}"}], "isError": True}


for line in sys.stdin:
    line = line.strip()
    if not line:
        continue
    msg = json.loads(line)
    method, mid = msg.get("method"), msg.get("id")
    if method == "initialize":
        reply(mid, {"protocolVersion": "2025-03-26", "capabilities": {"tools": {}},
                    "serverInfo": {"name": "fake", "version": "0"}})
    elif method == "tools/list":
        reply(mid, {"tools": TOOLS})
    elif method == "tools/call":
        p = msg.get("params", {})
        reply(mid, call(p.get("name"), p.get("arguments") or {}))
    elif mid is not None:
        reply(mid, {})
