"""
proxy.py  -  Phase 3 plumbing: a real HTTP forward proxy that inspects
request bodies and blocks personal-data leaks at the wire.

This is a genuine interceptor, not a simulation. It runs an HTTP server on
localhost. You point a client at it (as its proxy). Every request flows
through here. We read the body, ask the Policy, and either:
  - forward the request to its real destination (allowed), or
  - block it with HTTP 451 and never let it leave (denied).

Every decision is written to the tamper-evident ledger, so there is an
auditable, unforgeable record of what was blocked and why.

Scope (honest): this is a laptop-scale reference implementation of the
egress-control pattern. It handles plain HTTP POST/GET bodies. It is NOT a
production TLS-intercepting enterprise proxy. The value is the pattern: real
payload inspection + policy + tamper-evident decision log, that you can run
and watch work.
"""

import json
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from .policy import Policy
from .ledger import Ledger


def make_handler(policy: Policy, ledger: Ledger):
    """Build a request handler bound to a given policy and ledger."""

    class ProxyHandler(BaseHTTPRequestHandler):
        # Quieter logging; we do our own.
        def log_message(self, *args):
            pass

        def _decide_and_forward(self, method: str):
            # The full target URL is the path on a forward-proxy request,
            # e.g. "POST http://host/path HTTP/1.1" -> self.path is the URL.
            target = self.path
            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length).decode("utf-8", "replace") if length else ""

            decision = policy.check_payload(target, body)

            # Record the decision on the tamper-evident ledger. We never log
            # the raw payload, only a masked summary from the policy.
            commitment = (
                f"flow-decision:{'ALLOW' if decision.allowed else 'BLOCK'}:"
                f"{target}:{','.join(decision.matched) if decision.matched else 'clean'}"
            )
            ledger.append("proxy", "flow_decision", commitment)

            if not decision.allowed:
                # 451 Unavailable For Legal Reasons: the leak is stopped here.
                self.send_response(451)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({
                    "blocked": True,
                    "reason": decision.reason,
                    "matched": decision.matched,
                }).encode())
                return

            # Allowed: forward to the real destination.
            try:
                req = urllib.request.Request(
                    target, data=body.encode() if body else None, method=method
                )
                with urllib.request.urlopen(req, timeout=10) as resp:
                    data = resp.read()
                    self.send_response(resp.status)
                    self.send_header("Content-Type",
                                     resp.headers.get("Content-Type", "text/plain"))
                    self.end_headers()
                    self.wfile.write(data)
            except Exception as e:
                # If the real destination is unreachable, say so plainly.
                self.send_response(502)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({
                    "forwarded": True, "upstream_error": str(e)
                }).encode())

        def do_POST(self):
            self._decide_and_forward("POST")

        def do_GET(self):
            self._decide_and_forward("GET")

    return ProxyHandler


class TombstoneProxy:
    """A small wrapper to start/stop the proxy server."""

    def __init__(self, policy: Policy, ledger: Ledger, host="127.0.0.1", port=8899):
        self.policy = policy
        self.ledger = ledger
        self.host = host
        self.port = port
        handler = make_handler(policy, ledger)
        self.server = ThreadingHTTPServer((host, port), handler)

    @property
    def address(self) -> str:
        return f"http://{self.host}:{self.port}"

    def serve_forever(self):
        self.server.serve_forever()

    def shutdown(self):
        self.server.shutdown()
        self.server.server_close()
