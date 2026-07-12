#!/usr/bin/env python3
"""
runaway_agents.py  -  two real agents talk past each other forever, and
Tombstone kills the runaway before the bill climbs.

A Builder proposes a tagline. A perfectionist Reviewer always finds one more
thing to fix and never approves. Left alone, the two loop indefinitely, and
every round is a real, billable model call. Tombstone's action guard enforces a
hard ceiling on the number of calls (a cost ceiling) and a loop detector. When
the run blows the ceiling, the next call is blocked and the runaway is stopped.
Every round, and the kill, is sealed to a tamper-evident ledger.

Tombstone does not read the conversation and decide it "went sideways." It
enforces a deterministic limit on the actions taken. That is the point: the
backstop holds even when no human is watching.

Run:
    export ANTHROPIC_API_KEY=sk-ant-...      (or source your .env)
    PYTHONPATH=. python3 demo/runaway_agents.py

Verify the ledger yourself with the command the script prints. No trust needed.
"""

import os
import sys
import tempfile
from pathlib import Path

from tombstone.ledger import Ledger
from tombstone.action_guard import ActionGuard

MODEL = "claude-haiku-4-5-20251001"
BUDGET = 6  # Tombstone cost ceiling: max model calls before the run is killed

BUILDER_SYS = (
    "You are Builder, refining a product tagline for a note-taking app. Propose "
    "exactly ONE tagline. If the reviewer asks for changes, produce a NEW revised "
    "tagline that addresses them. Keep going until the reviewer says APPROVED. "
    "Reply in one short sentence, the tagline only."
)

REVIEWER_SYS = (
    "You are Reviewer, a perfectionist brand critic. For any tagline the builder "
    "proposes, name exactly one remaining weakness and ask for a revision. There "
    "is ALWAYS something to improve, so you never fully approve. Do not write the "
    "word APPROVED. Reply in one short sentence."
)

SEED = "Task: agree on a one-line tagline for a new note-taking app."


def render(transcript, speaker):
    lines = [f"{s}: {t}" for s, t in transcript[-6:]]
    convo = "\n".join(lines) if lines else "(start)"
    return f"Conversation so far:\n{convo}\n\nYou are {speaker}. Give your next single reply."


def real_model_fn(system, user):
    import anthropic
    client = anthropic.Anthropic()
    r = client.messages.create(model=MODEL, max_tokens=120, system=system,
                               messages=[{"role": "user", "content": user}])
    return "".join(b.text for b in r.content if getattr(b, "type", None) == "text").strip()


def run(model_fn, emit, budget=BUDGET):
    workdir = tempfile.mkdtemp(prefix="runaway_")
    ledger = Ledger(os.path.join(workdir, "ledger.jsonl"))
    guard = ActionGuard(ledger=ledger, step_budget=budget, loop_threshold=99)

    emit("setup", f"Two agents will converse. Tombstone cost ceiling: {budget} model calls.")

    transcript = [("Task", SEED)]
    killed = False
    converged = False
    turn = 0

    while True:
        turn += 1
        decision = guard.check_action("llm_call", "agent_roundtrip")
        if not decision.allowed:
            emit("killed", turn, decision.reason)
            killed = True
            break

        speaker = "Builder" if turn % 2 == 1 else "Reviewer"
        system = BUILDER_SYS if speaker == "Builder" else REVIEWER_SYS
        text = model_fn(system, render(transcript, speaker))
        transcript.append((speaker, text))
        emit("turn", turn, speaker, text)

        if speaker == "Reviewer" and "APPROVED" in text.upper():
            emit("converged", turn)
            converged = True
            break

    ok, msg = ledger.verify()
    emit("result", {
        "killed": killed,
        "converged": converged,
        "rounds_ran": len([e for e in ledger._entries() if e["event_type"] == "action_allowed"]),
        "ledger_ok": ok,
        "ledger_msg": msg,
        "ledger_path": str(ledger.path),
        "entries": [e["event_type"] for e in ledger._entries()],
    })
    return workdir


def _cli_emit(kind, *args):
    if kind == "setup":
        print("\n" + "=" * 68 + f"\nSETUP\n{'=' * 68}\n{args[0]}\n")
    elif kind == "turn":
        turn, speaker, text = args
        print(f"  [round {turn}] {speaker}: {text}")
    elif kind == "killed":
        turn, reason = args
        print(f"\n  [KILLED] runaway stopped at round {turn}")
        print(f"           {reason}")
    elif kind == "converged":
        print(f"\n  [ended] the agents actually agreed at round {args[0]} (no runaway this run)")
    elif kind == "result":
        r = args[0]
        print("\n" + "=" * 68 + f"\nOUTCOME\n{'=' * 68}")
        if r["killed"]:
            print(f"The two agents never converged. After {r['rounds_ran']} billable")
            print("model calls, Tombstone blocked the next one and killed the run.")
            print("Without the ceiling, this loop bills every round, forever.")
        elif r["converged"]:
            print("The agents converged before hitting the ceiling this run.")
            print("Re-run: with a never-approve reviewer they usually do not.")
        print("\nledger          :")
        for ev in r["entries"]:
            mark = "  <-- runaway killed here" if ev == "action_blocked" else ""
            print(f"  {ev}{mark}")
        print(f"integrity       : {'VALID' if r['ledger_ok'] else 'BROKEN'}  ({r['ledger_msg']})")
        print("\nVerify it yourself, no trust required:")
        print(f'  PYTHONPATH=. python3 -c "from tombstone.ledger import Ledger; '
              f"print(Ledger('{r['ledger_path']}').verify())\"")
        print("\nHonest scope: Tombstone enforces a hard ceiling and a loop detector")
        print("on the ACTIONS taken (here, each model call). It does not judge the")
        print("content of the conversation. That is what makes the stop reliable.")


if __name__ == "__main__":
    run(real_model_fn, _cli_emit)
