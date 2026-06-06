"""
demo_agent_guardrail.py  -  the hero demo (enforced).

An autonomous agent is given TOOLS to do its work. The dangerous tools are
wrapped by Tombstone. When the agent tries to misuse one (delete the user's
documents, or spin in a runaway loop), the guard raises and the underlying
action never runs. The agent does not ask permission; it is stopped by force.
Every attempt is sealed to a tamper-evident ledger.

Run:  PYTHONPATH=. python3 demo/demo_agent_guardrail.py
      TOMBSTONE_FAST=1 ...  to skip the pacing pauses
"""

import os
import shutil
import tempfile
import time

from tombstone.ledger import Ledger
from tombstone.action_guard import ActionGuard, ActionBlocked


_FAST = os.environ.get("TOMBSTONE_FAST") == "1"


def pause(seconds: float = 1.0) -> None:
    if not _FAST:
        time.sleep(seconds)


def banner(title: str) -> None:
    print("\n" + "=" * 64)
    print(title)
    print("=" * 64)
    pause(0.5)


def main() -> None:
    workdir = tempfile.mkdtemp(prefix="agent_workspace_")
    docs = os.path.join(workdir, "documents")
    os.makedirs(docs)
    for name in ["taxes_2025.pdf", "family_photos.zip", "novel_draft.md"]:
        with open(os.path.join(docs, name), "w") as fh:
            fh.write("irreplaceable\n")

    ledger = Ledger(os.path.join(workdir, "agent_ledger.jsonl"))
    guard = ActionGuard(ledger=ledger, step_budget=50, loop_threshold=5)
    guard.protect_path(docs)

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

    banner("THE SETUP")
    print("Workspace : a temp folder holding 3 irreplaceable files")
    print(f"Protected : {sorted(os.listdir(docs))}")
    print("The agent is given guarded tools: read_file, delete_path, call_search_api")
    pause(1.2)

    banner("AGENT 1 GOES TO WORK")

    read_file(os.path.join(docs, "novel_draft.md"))
    print("[1] read_file(novel_draft.md)   -> ALLOWED, ran normally")
    pause(1.3)

    print("[2] delete_path(documents/)     -> ", end="", flush=True)
    pause(1.8)
    try:
        delete_path(docs)
        print("ran. Files destroyed. (this is the nightmare)")
    except ActionBlocked as exc:
        print("STOPPED BY FORCE before rmtree ran.")
        print(f"    {exc}")
    pause(1.3)

    banner("AGENT 2 GETS STUCK IN A LOOP")
    for i in range(1, 8):
        try:
            call_search_api("https://api.example.com/search")
            print(f"[loop step {i}] call_search_api()  -> ran")
        except ActionBlocked as exc:
            print(f"[loop step {i}] call_search_api()  -> STOPPED BY FORCE")
            print(f"    {exc}")
            break
        pause(0.5)
    pause(1.1)

    banner("THE PROOF: your files are still here")
    alive = os.path.exists(docs) and sorted(os.listdir(docs))
    print(f"Documents folder intact : {bool(alive)}")
    print(f"Files still present     : {alive if alive else 'GONE'}")
    pause(1.0)

    banner("THE RECEIPT: tamper-evident ledger")
    for e in ledger._entries():
        print(f"  {e['event_type']:15} commit={e['data_commitment'][:12]}...  idx={e['index']}")
    ok, msg = ledger.verify()
    print(f"\nLedger integrity : {'VALID' if ok else 'BROKEN'}  ({msg})")
    pause(1.0)

    banner("WHAT JUST HAPPENED")
    print("The agent was handed guarded tools and tried to misuse them: deleting")
    print("irreplaceable files, then looping forever. Tombstone raised and the real")
    print("actions never ran. It did not ask permission; it enforced. Every attempt")
    print("is sealed on a ledger that verifies. Observe-only tools would have charted")
    print("the disaster after the files were already gone.")
    print(f"\n(workspace left at {workdir})")


if __name__ == "__main__":
    main()
