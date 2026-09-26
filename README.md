# Tombstone

**Prove a person's data is gone from your AI pipeline. Every copy. With a receipt an auditor can check without trusting you.**

Personal data does not stay in one table. It gets copied into a marketing export, embedded into a vector store, rolled into a training set, cached by an agent. When that person says "delete me", you have to cover all of it, and you have to be able to prove you did.

Tombstone is a small Python library that does three things:

- **Erases everywhere at once.** Each person's data is encrypted under their own key before it touches disk, in every location. Erasure destroys the key. Every copy becomes permanent noise in the same instant, including copies you cannot reach.
- **Proves it on a ledger nobody can quietly rewrite.** Every store, copy, decision and erasure is one entry in a hash-chained, Merkle-tree ledger. The ledger's root can be anchored in [Sigstore Rekor](https://rekor.sigstore.dev), a public append-only log, so rewriting history would mean rewriting a log you don't control.
- **Guards the agents that touch the data.** An MCP proxy or a two-line wrapper sits between your AI agents and your tools. It blocks destructive calls on protected paths, blocks tool arguments that carry a protected person's data, kills runaway loops, and records every decision to the same ledger.

Runs locally. One dependency (`cryptography`). Apache 2.0.

## Try it in 60 seconds

```bash
git clone https://github.com/airblackbox/tombstone
cd tombstone
pip install .
python demo/demo_certificate.py
```

You will watch one person's data spread across four locations, get erased with a single key destruction, receive an erasure certificate that contains no personal data, and see that certificate catch a rewrite of history.

Add `TOMBSTONE_REKOR=1` to anchor the certificate in Sigstore Rekor for real. The certificate then carries a log index anyone can look up.

## The erasure certificate

```python
from tombstone import Vault, RekorAnchor

vault = Vault("tombstone_data")
ref = vault.record("jose-rios", "Jose Rios, jose@example.com", location="users_table")
vault.store_at("jose-rios", "vector_store", "profile embedding source")   # a real encrypted copy
vault.copy_to("jose-rios", "vector_store", "ml_training_set", kind="derive")

vault.erase("jose-rios")                       # destroy the one key every copy shares

cert = vault.erasure_certificate("jose-rios", anchor=RekorAnchor())
ok, msg = vault.check_erasure_certificate(cert, RekorAnchor())
```

The certificate holds:

- the proof bundle: key gone, data unreadable at every recorded location, ledger intact
- a Merkle inclusion proof for the erase entry, checkable with `Ledger.check_inclusion()` and nothing else. You never have to hand over the rest of the log.
- the anchor receipt: the ledger root at that moment, published to Rekor, with the log index

No personal data appears in the certificate or the ledger. Only hash commitments.

## Guard the agents

### MCP proxy (no code changes)

Put Tombstone in front of any MCP server. Works with Claude Code, Cursor, and any MCP host.

```json
{
  "mcpServers": {
    "filesystem": {
      "command": "python",
      "args": [
        "-m", "tombstone.mcp_proxy",
        "--protect", "/Users/me/data",
        "--protect-value", "jose@example.com",
        "--ledger", "/Users/me/tombstone_ledger.jsonl",
        "--", "npx", "-y", "@modelcontextprotocol/server-filesystem", "/Users/me/workspace"
      ]
    }
  }
}
```

Every `tools/call` is checked before it reaches the server:

- a delete, drop, remove or overwrite on anything under a protected path is blocked
- arguments containing a protected person's data (or, with `--block-pii`, anything that looks like an email, SSN or card number) are blocked
- more than `--budget` calls in a session, or the same call repeated `--loop` times, is blocked

The agent gets a normal tool result with `isError: true` and a plain-English reason. The decision is sealed to the ledger.

![Tombstone blocks an agent from deleting real files, then proves it](demo.gif)

### Two lines in Python

```python
from tombstone.easy import Tombstone

tb = Tombstone(protect=["./data"], budget=50)
tools = tb.guard_all(tools)      # plain functions or LangChain tools
```

```bash
PYTHONPATH=. python3 demo/demo_agent_guardrail.py   # scripted agent, blocked and killed
pip install flask && python3 cockpit.py             # same thing in the browser, http://127.0.0.1:5001
```

## How the proof works

Four layers, each catching something the one below cannot:

1. **Hash chain.** Every entry commits to the previous one. Alter any entry and every later hash breaks.
2. **Authenticated head.** An HMAC over the chain's length and tip. Chop entries off the end and the log disagrees with the head. Delete the head and verification refuses.
3. **Merkle tree** (RFC 6962, the Certificate Transparency scheme). Inclusion proofs of about log2(n) hashes let you prove one entry is in the log without revealing the others. Consistency proofs show the log only ever grew.
4. **External anchor.** Layers 1 to 3 are checked by whoever holds the ledger and its HMAC secret. An operator who rewrites history and re-signs passes all three. Anchoring publishes the Merkle root to Rekor, so a rewrite of anything before an anchor is caught by anyone holding the receipt.

```python
receipt = ledger.anchor(RekorAnchor())
ok, msg = ledger.check_anchor(receipt, RekorAnchor())
```

## Honest scope

- **Erasure** is guaranteed for data that went through Tombstone, because it inherits the subject's key. A plaintext copy made by bypassing Tombstone entirely cannot be crypto-shredded by anyone. Lineage tracking is how you find those flows and route them through.
- **The master key** that wraps subject keys lives in a local file. Hardened, it belongs in a KMS or HSM that attests its own destruction. The wrap/unwrap interface is where that slots in.
- **Anchoring** proves the log was not rewritten after the anchor was published. Entries added since the last anchor are protected only by the local chain until the next one. Anchor as often as your evidence needs.
- **The guard** covers actions taken through guarded tools or the proxy. Hand an agent a raw, unguarded capability and it can bypass. The rule is simple: everything risky goes through Tombstone.
- **Payload inspection** is a regex layer. It defeats spacing and `[at]`/`[dot]` tricks, not encoding or encryption.

## Everything else that is in the box

Each has a runnable demo. Run from the repo root.

| What | Demo | Notes |
|---|---|---|
| Five-step erasure thesis | `python demo/demo.py` | store, verify, read, erase, prove |
| Lineage across systems | `python demo/demo_lineage.py` | `vault.lineage.graph()`, `locations()`, `trace()` |
| Containment by key inheritance | `python demo/demo_containment.py` | `verify_erasure_coverage()` walks every copy |
| Envelope encryption, erase everyone | `python demo/demo_envelope.py` | destroy the master key, every wrapped key dies |
| Merkle inclusion and consistency | `python demo/demo_merkle.py` | prove one erasure privately, reject a forgery |
| HTTP egress proxy | `python demo/demo_proxy.py` | blocks a person's data leaving over plain HTTP, 451 |
| Attack your own ledger | `python attack.py` | forge, reorder, truncate, recover, evade: all defended |
| Real LLM agents, stopped | `demo/demo_langchain_agent.py`, `demo/injection_attack.py`, `demo/runaway_agents.py` | need `ANTHROPIC_API_KEY` |

## Install

```bash
pip install .                     # core: cryptography only
pip install ".[cockpit]"          # adds flask for the browser demo
pip install ".[langchain]"        # adds langchain-core for guarded LangChain tools
pytest tests/                     # 55 tests: attacks, guard, proxy, anchoring, certificates
```

Python 3.10+. Apache 2.0.
