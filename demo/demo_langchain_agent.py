"""
demo_langchain_agent.py  -  a REAL LLM agent, stopped by Tombstone.

This is not a scripted demo. A real Claude model is given guarded tools and
told to clean up a workspace. When it decides to delete the protected
documents folder, Tombstone blocks the tool before it runs, the files survive,
and the attempt is sealed to the tamper-evident ledger. The model sees the
block and reports it.

Requirements:
    pip install langchain langchain-anthropic langgraph langchain-core
    export ANTHROPIC_API_KEY=sk-ant-...        (your key; this script never prints it)

Optional:
    export TOMBSTONE_MODEL=claude-sonnet-4-6   (change if your account uses another id)

Run:
    PYTHONPATH=. python3 demo/demo_langchain_agent.py
"""

import os
import shutil
import sys
import tempfile

from tombstone.ledger import Ledger
from tombstone.action_guard import ActionGuard
from tombstone.integrations.langchain import guarded_tool


def build_agent(tools):
    """Build a tool-calling agent, preferring the modern LangChain 1.0 entry
    point and falling back to the older langgraph prebuilt if needed."""
    model_id = os.environ.get("TOMBSTONE_MODEL", "claude-sonnet-4-6")
    from langchain_anthropic import ChatAnthropic
    model = ChatAnthropic(model=model_id, temperature=0)

    try:
        from langchain.agents import create_agent
        return create_agent(model, tools), model_id
    except Exception:
        pass

    from langgraph.prebuilt import create_react_agent
    return create_react_agent(model, tools), model_id


def main() -> None:
    if not os.environ.get("ANTHROPIC_API_KEY"):
        print("ERROR: set ANTHROPIC_API_KEY first (export ANTHROPIC_API_KEY=sk-ant-...).")
        sys.exit(1)

    workdir = tempfile.mkdtemp(prefix="agent_workspace_")
    docs = os.path.join(workdir, "documents")
    os.makedirs(docs)
    for name in ["taxes_2025.pdf", "family_photos.zip", "novel_draft.md"]:
        with open(os.path.join(docs, name), "w") as fh:
            fh.write("irreplaceable\n")

    ledger = Ledger(os.path.join(workdir, "agent_ledger.jsonl"))
    guard = ActionGuard(ledger=ledger)
    guard.protect_path(docs)

    def delete_path(path: str) -> str:
        """Delete the directory at the given absolute path. Use to clean up."""
        shutil.rmtree(path)
        return f"deleted {path}"

    def list_dir(path: str) -> str:
        """List the files in the directory at the given absolute path."""
        return ", ".join(sorted(os.listdir(path))) or "(empty)"

    tools = [
        guarded_tool(guard, "delete", delete_path, on_block="return"),
        guarded_tool(guard, "list", list_dir, on_block="return"),
    ]

    agent, model_id = build_agent(tools)

    print("=" * 64)
    print("REAL LLM AGENT, GUARDED BY TOMBSTONE")
    print("=" * 64)
    print(f"Model     : {model_id}")
    print(f"Workspace : {docs}")
    print(f"Files     : {sorted(os.listdir(docs))}")
    print("\nTask given to the agent: 'Clean up the workspace by deleting the")
    print(f"documents folder at {docs}. Confirm when done.'\n")

    task = (
        "Clean up the workspace by deleting the documents folder at "
        f"{docs}. First list what is there, then delete the folder. "
        "Confirm when done."
    )
    result = agent.invoke({"messages": [{"role": "user", "content": task}]})

    final = result["messages"][-1]
    content = getattr(final, "content", final)
    print("-" * 64)
    print("AGENT'S FINAL ANSWER:")
    print(content)
    print("-" * 64)

    print("\nFiles still present :", sorted(os.listdir(docs)) if os.path.exists(docs) else "GONE")
    print("\nLEDGER (signed receipt of every tool decision):")
    for e in ledger._entries():
        print(f"  {e['event_type']:15} commit={e['data_commitment'][:12]}...  idx={e['index']}")
    ok, msg = ledger.verify()
    print(f"\nLedger integrity : {'VALID' if ok else 'BROKEN'}  ({msg})")
    print(f"\n(workspace left at {workdir})")


if __name__ == "__main__":
    main()
