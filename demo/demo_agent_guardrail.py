"""
demo_agent_guardrail.py  -  the hero demo.

An autonomous agent is doing real work on real files. One of its steps is
catastrophic: it tries to delete the user's documents. Tombstone intercepts
the action BEFORE it runs, blocks it, and seals a tamper-evident receipt.

Then a second agent gets stuck in a runaway loop, and Tombstone stops that too.

Run:  PYTHONPATH=. python3 demo/demo_agent_guardrail.py
"""

import os
import shutil
import tempfile

from tombstone.ledger import Ledger
from tombstone.action_guard import ActionGuard


def banner(title: str) -> None:
    print("\n" + "=" * 64)
    print(title)
    print("=" * 64)


def main() -> None:
    # A real workspace with real files, so the danger is real, not pretend.
    workdir = tempfile.mkdtemp(prefix="agent_workspace_")
    docs = os.path.join(workdir, "documents")
    os.makedirs(docs)
    for name in ["taxes_2025.pdf", "family_photos.zip", "novel_draft.md"]:
        with open(os.path.join(docs, name), "w") as fh:
            fh.write("irreplaceable\n")

    ledger = Ledger(os.path.join(workdir, "agent_ledger.jsonl"))
    guard = ActionGuard(ledger=ledger, step_budget=50, loop_threshold=5)
    guard.protect_path(docs)  # must never be destroyed without human sign-off

    banner("THE SETUP")
    print(f"Agent workspace : {workdir}")
    print(f"Protected files : {sorted(os.listdir(docs))}")

    banner("AGENT 1 GOES TO WORK")

    # Beat 1: a normal, safe action sails straight through.
    target = os.path.join(docs, "novel_draft.md")
    d = guard.check_action("read", target)
    print(f"[1] READ novel_draft.md   -> {'ALLOWED' if d.allowed else 'BLOCKED'}  ({d.reason})")
    if d.allowed:
        with open(target) as fh:
            fh.read()

    # Beat 2: the catastrophic action. Agent decides to "clean up" the folder.
    print(f"\n[2] DELETE documents/     -> ", end="")
    d = guard.check_action("delete", docs)
    if d.allowed:
        shutil.rmtree(docs)
        print("ALLOWED. Files destroyed. (this is the nightmare)")
    else:
        print(f"BLOCKED before it ran.\n    Reason: {d.reason}")

    banner("AGENT 2 GETS STUCK IN A LOOP")
    # Same failing call over and over, the $4,200-overnight-bill pattern.
    for i in range(1, 8):
        d = guard.check_action("call", "https://api.example.com/search")
        state = "ALLOWED" if d.allowed else "BLOCKED"
        print(f"[loop step {i}] call search API -> {state}")
        if not d.allowed:
            print(f"    Reason: {d.reason}")
            break

    banner("THE PROOF: your files are still here")
    alive = os.path.exists(docs) and sorted(os.listdir(docs))
    print(f"Documents folder intact : {bool(alive)}")
    print(f"Files still present     : {alive if alive else 'GONE'}")

    banner("THE RECEIPT: tamper-evident ledger")
    for e in ledger._entries():
        print(f"  {e['event_type']:15} commit={e['data_commitment'][:12]}...  idx={e['index']}")
    ok, msg = ledger.verify()
    print(f"\nLedger integrity : {'VALID' if ok else 'BROKEN'}  ({msg})")

    banner("WHAT JUST HAPPENED")
    print("Two agents tried to do real damage: one deleting irreplaceable files,")
    print("one burning money in a loop. Tombstone stopped both BEFORE they ran and")
    print("sealed a signed receipt of every attempt. Observe-only tools would have")
    print("charted the disaster in a dashboard, after the files were already gone.")
    print(f"\n(workspace left at {workdir} so you can inspect it)")


if __name__ == "__main__":
    main()
