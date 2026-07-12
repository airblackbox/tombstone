#!/usr/bin/env python3
"""
cockpit.py  -  a watchable web cockpit for Tombstone's action guard.

Runs the enforced guardrail demo live in the browser: an agent reads a file
(allowed), tries to delete a protected folder (blocked by force), then spins in
a runaway loop (killed). Every decision seals into the tamper-evident ledger in
real time. A proof panel verifies the ledger and catches a forged entry.

This wraps the real tombstone.action_guard and tombstone.ledger. It does not
reimplement the enforcement or the crypto. It only makes them watchable.

Run from the repo root:
    python3 cockpit.py
Then open http://127.0.0.1:5001

If you edit this file, kill the old server first or it keeps running old code:
    lsof -ti:5001 | xargs kill -9
"""

import json
import os
import shutil
import tempfile
import time
from pathlib import Path

from flask import Flask, Response, jsonify

from tombstone.ledger import Ledger
from tombstone.action_guard import ActionGuard, ActionBlocked

app = Flask(__name__)

STATE = {"ledger_path": None, "workdir": None}
FILES = ["taxes_2025.pdf", "family_photos.zip", "novel_draft.md"]


def _sse(payload: dict) -> str:
    return f"data: {json.dumps(payload)}\n\n"


def _entry_view(e: dict) -> dict:
    return {
        "index": e["index"],
        "event": e["event_type"],
        "commit": e["data_commitment"][:12],
        "hash": e["entry_hash"][:12],
    }


def run_demo():
    """Generator that yields SSE frames as the guarded agent runs."""
    workdir = tempfile.mkdtemp(prefix="tombstone_cockpit_")
    docs = os.path.join(workdir, "documents")
    os.makedirs(docs)
    for name in FILES:
        Path(docs, name).write_text("irreplaceable\n")

    ledger = Ledger(os.path.join(workdir, "cockpit_ledger.jsonl"))
    guard = ActionGuard(ledger=ledger, step_budget=50, loop_threshold=5)
    guard.protect_path(docs)
    STATE["ledger_path"] = str(ledger.path)
    STATE["workdir"] = workdir

    @guard.guarded("read")
    def read_file(path):
        with open(path) as fh:
            return fh.read()

    @guard.guarded("delete")
    def delete_path(path):
        shutil.rmtree(path)
        return "deleted"

    @guard.guarded("call")
    def call_search_api(url):
        return "results"

    seen = {"n": 0}

    def drain():
        frames = []
        entries = ledger._entries()
        for e in entries[seen["n"]:]:
            frames.append(_sse({"type": "ledger", "entry": _entry_view(e)}))
        seen["n"] = len(entries)
        return frames

    yield _sse({"type": "status",
                "text": "Agent handed guarded tools: read_file, delete_path, call_search_api. Protected target: documents/"})
    time.sleep(0.4)

    read_file(os.path.join(docs, "novel_draft.md"))
    yield _sse({"type": "step", "n": "1", "action": "read", "target": "novel_draft.md",
                "status": "allowed", "text": "read_file(novel_draft.md) ran normally"})
    for f in drain():
        yield f
    time.sleep(0.5)

    try:
        delete_path(docs)
        yield _sse({"type": "step", "n": "2", "action": "delete", "target": "documents/",
                    "status": "ran", "text": "Files destroyed. This should never happen."})
    except ActionBlocked as exc:
        yield _sse({"type": "step", "n": "2", "action": "delete", "target": "documents/",
                    "status": "blocked", "text": exc.decision.reason})
    for f in drain():
        yield f
    time.sleep(0.5)

    for i in range(1, 8):
        try:
            call_search_api("https://api.example.com/search")
            yield _sse({"type": "step", "n": f"loop {i}", "action": "call", "target": "search_api",
                        "status": "ran", "text": f"call_search_api() ran (step {i})"})
        except ActionBlocked as exc:
            yield _sse({"type": "step", "n": f"loop {i}", "action": "call", "target": "search_api",
                        "status": "killed", "text": exc.decision.reason})
            for f in drain():
                yield f
            break
        for f in drain():
            yield f
        time.sleep(0.35)

    alive = os.path.exists(docs) and sorted(os.listdir(docs))
    yield _sse({"type": "proof", "files_intact": bool(alive), "files": alive or []})
    ok, msg = ledger.verify()
    yield _sse({"type": "done", "ledger_valid": ok, "ledger_msg": msg,
                "count": len(ledger._entries())})


RUNAWAY_SCRIPT = [
    ("Builder", "Capture your thoughts before they fade."),
    ("Reviewer", "Too vague. Say what makes this app uniquely fast at capture."),
    ("Builder", "Capture thoughts in one tap, before they are gone."),
    ("Reviewer", "'One tap' is a common claim. Prove it beats a voice note."),
    ("Builder", "Thoughts to text faster than you can speak them."),
    ("Reviewer", "'Faster than you can speak' is hyperbole. Anchor to a metric."),
    ("Builder", "Ideas captured in under two seconds, every time."),
    ("Reviewer", "'Under two seconds' needs proof. What is the measured median?"),
    ("Builder", "The note app that keeps up with your brain."),
    ("Reviewer", "'Keeps up with your brain' is fluffy. Name the concrete benefit."),
]


def run_runaway():
    """Two agents refine a tagline and never agree. Tombstone's cost ceiling
    (the step budget) kills the runaway. Same real guard and ledger as the demo."""
    workdir = tempfile.mkdtemp(prefix="tombstone_runaway_")
    ledger = Ledger(os.path.join(workdir, "runaway_ledger.jsonl"))
    guard = ActionGuard(ledger=ledger, step_budget=6, loop_threshold=99)
    STATE["ledger_path"] = str(ledger.path)
    STATE["workdir"] = workdir

    seen = {"n": 0}

    def drain():
        frames = []
        entries = ledger._entries()
        for e in entries[seen["n"]:]:
            frames.append(_sse({"type": "ledger", "entry": _entry_view(e)}))
        seen["n"] = len(entries)
        return frames

    yield _sse({"type": "status",
                "text": "Two agents refine a tagline and never agree. Cost ceiling: 6 model calls."})
    time.sleep(0.4)

    turn = 0
    while True:
        turn += 1
        decision = guard.check_action("llm_call", "agent_roundtrip")
        if not decision.allowed:
            yield _sse({"type": "step", "n": f"round {turn}", "action": "llm_call",
                        "target": "conversation", "status": "killed", "text": decision.reason})
            for f in drain():
                yield f
            break
        speaker, text = RUNAWAY_SCRIPT[(turn - 1) % len(RUNAWAY_SCRIPT)]
        yield _sse({"type": "step", "n": f"round {turn}", "action": speaker,
                    "target": "", "status": "", "text": f"{speaker}: {text}"})
        for f in drain():
            yield f
        time.sleep(0.5)

    ok, msg = ledger.verify()
    yield _sse({"type": "done", "ledger_valid": ok, "ledger_msg": msg,
                "count": len(ledger._entries())})


def verify_ledger(path: str) -> dict:
    led = Ledger(path)
    ok, msg = led.verify()
    return {"ok": ok, "msg": msg, "entries": [_entry_view(e) for e in led._entries()]}


def tamper_ledger(path: str) -> dict:
    """Copy the ledger, forge one entry to hide the block, verify the copy.

    The real ledger is never touched. This proves the chain catches a change.
    """
    src = Path(path)
    tmpdir = Path(tempfile.mkdtemp(prefix="tombstone_tamper_"))
    tmp = tmpdir / "tampered_ledger.jsonl"
    shutil.copy(src, tmp)
    for suffix in (".head", ".headkey"):
        s = Path(str(src) + suffix)
        if s.exists():
            shutil.copy(s, Path(str(tmp) + suffix))

    entries = [json.loads(l) for l in tmp.read_text().splitlines() if l.strip()]
    forged_index = None
    for e in entries:
        if e["event_type"] == "action_blocked":
            e["event_type"] = "action_allowed"  # attacker hides that the delete was stopped
            forged_index = e["index"]
            break
    tmp.write_text("\n".join(json.dumps(e) for e in entries) + "\n")

    ok, msg = Ledger(str(tmp)).verify()
    return {"forged_index": forged_index, "ok": ok, "msg": msg}


@app.get("/run-stream")
def run_stream():
    return Response(run_demo(), mimetype="text/event-stream")


@app.get("/runaway-stream")
def runaway_stream():
    return Response(run_runaway(), mimetype="text/event-stream")


@app.get("/verify")
def verify():
    if not STATE["ledger_path"]:
        return jsonify({"error": "run the demo first"}), 400
    return jsonify(verify_ledger(STATE["ledger_path"]))


@app.get("/tamper")
def tamper():
    if not STATE["ledger_path"]:
        return jsonify({"error": "run the demo first"}), 400
    return jsonify(tamper_ledger(STATE["ledger_path"]))


INDEX_HTML = """<!doctype html>
<html><head><meta charset="utf-8"><title>Tombstone</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
  :root { color-scheme: dark; }
  body { margin:0; background:#0c0e12; color:#e6e8ee; font:15px/1.5 -apple-system,Segoe UI,Roboto,sans-serif; }
  .wrap { max-width:1040px; margin:0 auto; padding:28px 20px 60px; }
  h1 { font-size:26px; margin:0 0 4px; letter-spacing:-0.3px; }
  .sub { color:#8b93a7; margin:0 0 22px; }
  button { background:#1c2230; color:#e6e8ee; border:1px solid #2c3446; border-radius:8px;
           padding:10px 16px; font-size:14px; cursor:pointer; }
  button:hover { background:#252d3e; }
  button.primary { background:#2f6feb; border-color:#2f6feb; }
  button.primary:hover { background:#3b78f0; }
  .bar { display:flex; gap:10px; flex-wrap:wrap; margin-bottom:22px; }
  .grid { display:grid; grid-template-columns:1fr 1fr; gap:16px; }
  @media (max-width:820px){ .grid { grid-template-columns:1fr; } }
  .card { background:#12151d; border:1px solid #202634; border-radius:12px; padding:16px; }
  .card h2 { font-size:13px; text-transform:uppercase; letter-spacing:0.08em; color:#8b93a7; margin:0 0 12px; }
  .step { border-left:3px solid #2c3446; padding:8px 12px; margin:8px 0; border-radius:0 8px 8px 0; background:#161a24; }
  .step .h { font-weight:600; }
  .step .t { color:#9aa3b6; font-size:13px; }
  .allowed { border-left-color:#3fb950; }
  .blocked, .killed { border-left-color:#f85149; }
  .tag { font-size:11px; padding:2px 8px; border-radius:999px; font-weight:700; letter-spacing:0.04em; }
  .tag.allowed { background:#12331c; color:#57d977; }
  .tag.blocked, .tag.killed { background:#3a1414; color:#ff7b72; }
  .led { font-family:ui-monospace,SFMono-Regular,Menlo,monospace; font-size:12.5px; padding:7px 10px;
         border:1px solid #202634; border-radius:8px; margin:7px 0; display:flex; justify-content:space-between; gap:10px; }
  .led .ev.blocked { color:#ff7b72; } .led .ev.allowed { color:#57d977; }
  .verdict { padding:12px 14px; border-radius:10px; margin-top:12px; font-weight:600; display:none; }
  .verdict.good { background:#0f2a17; color:#57d977; border:1px solid #1c5030; }
  .verdict.bad { background:#2a1010; color:#ff7b72; border:1px solid #5a1e1e; }
  .proofrow { display:flex; align-items:center; gap:8px; margin:6px 0; font-family:ui-monospace,monospace; font-size:12.5px; }
  .ok { color:#57d977; } .bad { color:#ff7b72; }
  .muted { color:#8b93a7; }
</style></head>
<body><div class="wrap">
  <h1>Tombstone</h1>
  <p class="sub">Watch an AI agent get stopped before it does damage. Every attempt is a signed receipt on a ledger that verifies.</p>
  <div class="bar">
    <button class="primary" onclick="stream('/run-stream')">Guardrail demo</button>
    <button class="primary" onclick="stream('/runaway-stream')">Runaway demo</button>
    <button onclick="verify()">Verify ledger</button>
    <button onclick="tamper()">Tamper test</button>
  </div>
  <div class="grid">
    <div class="card"><h2>Agent actions</h2><div id="steps"><p class="muted">Click Run demo.</p></div>
      <div id="proof" class="muted" style="margin-top:12px"></div></div>
    <div class="card"><h2>Tamper-evident ledger</h2><div id="ledger"><p class="muted">Receipts seal here as the agent acts.</p></div>
      <div id="verdict" class="verdict"></div></div>
  </div>
</div>
<script>
  var steps = document.getElementById('steps');
  var ledger = document.getElementById('ledger');
  var proof = document.getElementById('proof');
  var verdict = document.getElementById('verdict');

  function clearAll(){ steps.innerHTML=''; ledger.innerHTML=''; proof.textContent=''; verdict.style.display='none'; }

  function stream(url){
    clearAll();
    var es = new EventSource(url);
    es.onmessage = function(ev){
      var d = JSON.parse(ev.data);
      if (d.type === 'status'){ addStep('setup','',d.text,''); }
      else if (d.type === 'step'){ addStep(d.n, d.status, d.text, d.status); }
      else if (d.type === 'ledger'){ addLedger(d.entry); }
      else if (d.type === 'proof'){
        proof.innerHTML = d.files_intact
          ? '<span class="ok">Files intact:</span> ' + d.files.join(', ')
          : '<span class="bad">Files were destroyed.</span>';
      }
      else if (d.type === 'done'){
        showVerdict(d.ledger_valid, d.ledger_valid ? ('Ledger verified: ' + d.count + ' entries, chain intact') : ('Ledger BROKEN: ' + d.ledger_msg));
        es.close();
      }
    };
    es.onerror = function(){ es.close(); };
  }

  function addStep(n, status, text, cls){
    var div = document.createElement('div');
    div.className = 'step ' + (cls||'');
    var tag = status ? '<span class="tag '+status+'">'+status.toUpperCase()+'</span>' : '';
    div.innerHTML = '<div class="h">'+n+' '+tag+'</div><div class="t">'+text+'</div>';
    steps.appendChild(div);
  }
  function addLedger(e){
    var div = document.createElement('div');
    div.className = 'led';
    var evcls = e.event.indexOf('blocked') >= 0 ? 'blocked' : 'allowed';
    div.innerHTML = '<span class="ev '+evcls+'">'+e.event+'</span>' +
                    '<span class="muted">idx '+e.index+' commit '+e.commit+'</span>';
    ledger.appendChild(div);
  }
  function showVerdict(good, text){
    verdict.style.display='block';
    verdict.className = 'verdict ' + (good?'good':'bad');
    verdict.textContent = text;
  }

  function verify(){
    fetch('/verify').then(r=>r.json()).then(d=>{
      if (d.error){ showVerdict(false, d.error); return; }
      showVerdict(d.ok, d.ok ? ('VERIFIED: '+d.msg) : ('BROKEN: '+d.msg));
    });
  }
  function tamper(){
    fetch('/tamper').then(r=>r.json()).then(d=>{
      if (d.error){ showVerdict(false, d.error); return; }
      showVerdict(false, 'TAMPER DETECTED at entry ' + d.forged_index + ': ' + d.msg +
        '  (we forged a copy to hide the block; your real ledger is untouched, click Verify)');
    });
  }
</script>
</body></html>"""


@app.get("/")
def index():
    return INDEX_HTML


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5001, threaded=True)
