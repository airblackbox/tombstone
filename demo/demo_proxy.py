"""
demo_proxy.py  -  Phase 3: stop the leak at the wire, for real.

Run it:  python demo/demo_proxy.py

This is not a simulation. It starts:
  1. a real destination HTTP server (pretending to be an external endpoint)
  2. a real Tombstone proxy in front of it that inspects every request body

Then it sends two REAL HTTP requests through the proxy:
  - a clean request (no personal data)  -> forwarded, reaches the destination
  - a request carrying Jose's email     -> BLOCKED at the proxy, never leaves

Every decision is written to the tamper-evident ledger.
"""

import json
import shutil
import threading
import urllib.request
from pathlib import Path
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from tombstone import Policy, Ledger, TombstoneProxy


def line():
    print("-" * 64)


# ---- a tiny "external destination" server, so the demo is fully real ----
class DestHandler(BaseHTTPRequestHandler):
    received = []

    def log_message(self, *a):
        pass

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length).decode() if length else ""
        DestHandler.received.append(body)  # record what actually arrived
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps({"stored": True}).encode())


def main():
    if Path("tombstone_data").exists():
        shutil.rmtree("tombstone_data")

    Path("tombstone_data").mkdir()
    ledger = Ledger("tombstone_data/ledger.jsonl")

    # Policy: this external analytics endpoint must never receive Jose's data.
    policy = Policy()
    policy.protect("jose-rios", "jose@example.com", "Jose Rios")
    policy.block_destination("127.0.0.1:9001")  # the "external" dest below

    # Start the real destination server on 9001.
    dest = ThreadingHTTPServer(("127.0.0.1", 9001), DestHandler)
    threading.Thread(target=dest.serve_forever, daemon=True).start()

    # Start the real Tombstone proxy on 8899.
    proxy = TombstoneProxy(policy, ledger, port=8899)
    threading.Thread(target=proxy.serve_forever, daemon=True).start()

    dest_url = "http://127.0.0.1:9001/ingest"

    def send_through_proxy(payload: str):
        # A forward-proxy request: the full URL is the request target.
        req = urllib.request.Request(dest_url, data=payload.encode(), method="POST")
        req.set_proxy("127.0.0.1:8899", "http")
        try:
            with urllib.request.urlopen(req, timeout=10) as r:
                return r.status, r.read().decode()
        except urllib.error.HTTPError as e:
            return e.code, e.read().decode()

    line()
    print("STEP 1  Send a CLEAN request through the proxy (no personal data)")
    line()
    status, body = send_through_proxy('{"event":"page_view","page":"/pricing"}')
    print(f"  HTTP {status}  ->  {body}")
    print("  expected: 200, forwarded to the destination")

    line()
    print("STEP 2  Send a request carrying Jose's email through the proxy")
    line()
    status, body = send_through_proxy('{"user":"Jose Rios","email":"jose@example.com"}')
    print(f"  HTTP {status}  ->  {body}")
    print("  expected: 451, BLOCKED at the proxy, never reached the destination")

    line()
    print("STEP 3  Prove the leak never reached the destination")
    line()
    arrived = DestHandler.received
    leaked = any("jose@example.com" in r for r in arrived)
    print(f"  requests that actually reached the destination: {len(arrived)}")
    print(f"  any of them contained Jose's email? {leaked}   (want False)")

    line()
    print("STEP 4  Show the decisions on the tamper-evident ledger")
    line()
    for e in ledger.events_for("proxy"):
        print(f"  {e['data_commitment']}")
    intact, detail = ledger.verify()
    print(f"  ledger intact = {intact}  ({detail})")

    line()
    ok = (not leaked) and intact and len(arrived) == 1
    print(f"  PHASE 3 PROVEN: {ok}")
    print("  Clean traffic flows. The leak was stopped at the wire. Both logged.")
    line()

    proxy.shutdown()
    dest.shutdown()


if __name__ == "__main__":
    main()
