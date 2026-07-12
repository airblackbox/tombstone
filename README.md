# Tombstone

**Stop your AI agents from looping, running away, or wiping your data. In two lines. With a receipt.**

![Tombstone blocks an agent from deleting real files, then proves it](demo.gif)

Tombstone is an open-source control plane for AI agents. It wraps the tools you
hand an agent and intercepts the dangerous calls before they run: a runaway loop
that burns your token budget, the same call repeated forever, a delete or drop or
overwrite on data you marked protected. Every decision, allowed or blocked, is
sealed into a tamper-evident ledger, so you always have proof of exactly what
your agent tried to do.

Observability tools chart the disaster in a dashboard after it happens.
Tombstone stops it first, then proves it.

Runs locally. Framework-agnostic. Your data and your agents never leave your
environment.

## Guard any agent in two lines

```python
from tombstone.easy import Tombstone

tb = Tombstone(protect=["./data"], budget=50)   # a ledger + guard, ready
tools = tb.guard_all(tools)                       # wrap your tools
```

Hand `tools` to your agent the way you already do. That is the whole
integration. It works with plain Python tool functions (CrewAI, AutoGen, a raw
OpenAI or Anthropic tool loop) and with LangChain tools.

Three independent stops from one wrapper:

- **Runaway budget.** After `budget` tool calls, the next one is blocked. A cost
  ceiling for an agent that keeps going forever.
- **Loop detector.** The same call repeated in a row is blocked. Catches an agent
  stuck repeating itself.
- **Protected paths.** A delete, drop, or overwrite on anything under a protected
  path is blocked before it runs.

Check the ledger any time:

```python
ok, msg = tb.verify()   # (True, 'chain intact (N entries verified)')
```

## Proof: two runaways, one wrapper

The loop detector catches an agent repeating itself:
round 1: calling the tool
round 2: calling the tool
round 3: calling the tool
round 4: calling the tool
round 5: calling the tool
STOPPED at round 5: loop detected: 'call:keep going' repeated 5x in a row
verify: (True, 'chain intact (5 entries verified)')

The budget catches an agent that keeps doing new things forever:
round 1: calling the tool
round 2: calling the tool
round 3: calling the tool
round 4: calling the tool
round 5: calling the tool
round 6: calling the tool
STOPPED at round 6: step budget exceeded (6 > 5): possible runaway
verify: (True, 'chain intact (6 entries verified)')

Same two lines of setup. One catches repetition, the other catches endless
novelty. Most agent guardrail tools give you one, not both.

## Try it in 30 seconds
git clone https://github.com/airblackbox/tombstone
cd tombstone
pip install cryptography
PYTHONPATH=. python3 demo/demo_agent_guardrail.py

You will watch an agent get blocked from deleting real files, a runaway loop get
killed at step 5, and the signed receipt on a ledger that verifies.

Watch two real agents spiral until the run is killed:
PYTHONPATH=. python3 demo/runaway_agents.py

Or watch the whole thing in the browser, a destructive block plus a runaway plus
a live tamper test:
pip install flask
python3 cockpit.py     # then open http://127.0.0.1:5001

## How the proof works

Every decision is one entry in an append-only, hash-chained ledger. Each entry
commits to the previous one, so altering any past entry breaks verification, and
an HMAC-authenticated head makes truncation detectable too. You do not have to
trust Tombstone: run `ledger.verify()` yourself, or re-run any demo and check the
ledger it wrote.

## Honest scope

Enforcement covers actions taken through guarded tools. If you also hand the
agent a raw, unguarded capability (a bare `os.remove`), it can bypass the guard.
The rule is simple: give agents only guarded tools for anything risky. Tombstone
is the wrapper you put around every dangerous tool, not a kernel hook.

## Install
pip install cryptography      # core
pip install flask             # optional, for the browser cockpit

Apache 2.0. 13 security tests pass (`pytest tests/`).

---

## Beyond the agent guard: provable data erasure

The same tamper-evident spine powers Tombstone's second capability: erasing a
person's data so it is unrecoverable everywhere, even in copies, while the audit
log proving it existed and was deleted stays intact. That is what a tombstone is.

### How it works

- Personal data is encrypted with a per-subject key (AES-256-GCM) before it
  touches disk.
- The ledger stores only a SHA-256 commitment to the ciphertext, never the data.
  Each entry is hash-chained to the previous one, so altering any past entry
  breaks verification.
- Erasure = destroying the subject's key (crypto-shredding). The ciphertext
  becomes permanent noise. The ledger stays intact.

### The five-step proof
python demo/demo.py

1. Store a subject's data (encrypted; ledger holds only a hash).
2. Verify the ledger is tamper-evident.
3. Read the data back (proves it was really stored).
4. Erase the subject (destroy the key).
5. Prove erasure: data is unrecoverable AND the ledger still verifies.

### Lineage and containment (v0.2)

Erasing data in one place is the easy case. The real problem is that data gets
copied and derived across systems, and you have to cover all of it.

- Lineage: every copy or derivation is recorded as a flow on the ledger.
  `vault.lineage.graph(subject)` shows where data went; `locations(subject)`
  lists the full footprint; `trace(subject, start)` follows it downstream.
- Containment: copies stored via `vault.store_at(...)` inherit the subject's one
  key, so destroying that key crypto-shreds every copy at once.
  `vault.verify_erasure_coverage(subject)` walks every location and proves each
  copy is unreadable after erasure.
python demo/demo_lineage.py      # trace the sprawl, erase across all of it
python demo/demo_containment.py  # one key-shred kills every real copy

Honest scope: containment is guaranteed for data that went through Tombstone (it
inherits the key). A plaintext copy made by bypassing Tombstone entirely cannot
be crypto-shredded by anyone; lineage tracking is how you catch those flows and
route them through the system in the first place.

### Flow-control proxy (v0.3)

A real HTTP forward proxy that inspects request bodies and blocks personal-data
leaks before they leave, recording every decision on the tamper-evident ledger.
python demo/demo_proxy.py

The demo starts a real destination server and a real proxy, then sends two live
HTTP requests: a clean one (forwarded) and one carrying a subject's email
(blocked with HTTP 451, never reaches the destination). The ledger records both
decisions, with personal data masked so the audit log itself never leaks.

Honest scope: this is a laptop-scale reference implementation of the
egress-control pattern. It inspects plain HTTP bodies. It does NOT do TLS
interception or production-grade throughput. The value is the working pattern:
real payload inspection plus policy plus a tamper-evident decision log.

### Hardening: attack yourself (v0.4)

A security tool is only as good as the attacks it survives. Tombstone ships an
adversarial test suite that tries to defeat its own guarantees:
python attack.py          # readable attack report
pytest tests/             # the same attacks as assertions

Attacks and current status:

- Forge a past entry (alter contents, keep hash): DEFENDED (hash mismatch).
- Reorder entries: DEFENDED (broken prev_hash link).
- Truncate the log (delete recent entries to hide them): DEFENDED. The ledger
  keeps an HMAC-authenticated head recording chain length and tip; truncation
  makes the log disagree with the head, and the head cannot be forged without
  the secret key.
- Recover data after crypto-shred: DEFENDED (vault read fails; no plaintext on
  disk, only ciphertext for a destroyed key).
- Sneak obfuscated PII past the proxy (spacing, [at]/[dot] tricks): DEFENDED via
  payload normalization.

Honest limits (the next hardening targets, not yet done):
- The head-signing secret currently lives next to the ledger. Truly hardened, it
  belongs in a separate KMS/HSM so an attacker with full disk access still
  cannot forge the head.
- Secure key deletion on SSDs is hard (wear-leveling). The robust answer is
  envelope encryption: wrap subject keys under a KMS master key whose
  destruction is attestable, so erasure never depends on physically scrubbing
  bytes.
- Content inspection is an arms race. Normalization defeats trivial evasion;
  encoding, encryption, or splitting across requests still requires deeper
  inspection.

### Envelope encryption (v0.5)

Erasure no longer trusts the disk. Every subject key is wrapped (encrypted) under
a master key; only the wrapped form is ever written. Two erasure paths, neither
depending on physically scrubbing bytes:

- Erase one subject: destroy their wrapped key.
- Crypto-erase everyone at once: destroy the master key. Every wrapped subject
  key becomes permanently un-unwrappable, even copies an attacker hoarded.
python demo/demo_envelope.py   # destroy the master, watch everyone die at once

Honest limit: the master key still lives in a local file. Truly hardened, it
belongs in a KMS/HSM that performs and attests its own destruction. The
wrap/unwrap interface is exactly what a KMS slots into; that integration is the
next deployment-hardening step.

### Merkle-tree proofs (v0.6)

The hash chain proves the whole log is intact; a Merkle tree (RFC 6962 hashing,
the Certificate Transparency scheme) adds efficient single-entry proofs:

- Inclusion proof: prove "entry X is in the log" with about log2(n) hashes,
  without revealing other entries. Prove an erasure is recorded without dumping
  everyone else's events.
- Consistency proof: prove the log only ever grew, never rewrote history.
python demo/demo_merkle.py   # prove one erasure privately; reject a forgery

Layered integrity: the hash chain catches content tampering, the authenticated
head catches truncation, and the Merkle tree gives efficient inclusion and
consistency proofs.
