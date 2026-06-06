# Tombstone

Provable, crypto-shredded erasure on a tamper-evident ledger.

You should not have to choose between a permanent audit trail and a person's
right to be deleted. Tombstone gives you both. The audit log is append-only and
tamper-evident. Erasing a person destroys their encryption key, which makes all
of their data unrecoverable everywhere, even in copies you cannot see, without
ever altering the log. The data is gone. The proof that it existed, and was
deleted, remains. That is what a tombstone is.

Runs locally. Your data never leaves your environment.

## How it works

- Personal data is encrypted with a per-subject key (AES-256-GCM) before it
  touches disk.
- The ledger stores only a SHA-256 commitment to the ciphertext, never the data.
  Each entry is hash-chained to the previous one, so altering any past entry
  breaks verification.
- Erasure = destroying the subject's key (crypto-shredding). The ciphertext
  becomes permanent noise. The ledger stays intact.

## The five-step proof

```
python demo/demo.py
```

1. Store a subject's data (encrypted; ledger holds only a hash).
2. Verify the ledger is tamper-evident.
3. Read the data back (proves it was really stored).
4. Erase the subject (destroy the key).
5. Prove erasure: data is unrecoverable AND the ledger still verifies.

## Status

v0.1: the erasure core. This is the hard part, and it works.

Roadmap (not built yet): lineage tracking across systems, a data-flow control
gate, and an AI layer that detects and proposes remediation (with destructive
actions gated by human approval).

## Install

```
pip install cryptography
```

Apache 2.0.

## Phase 2: lineage and containment (v0.2)

Phase 1 erased data in one place. Phase 2 solves the real problem: data gets
copied and derived across systems, and you have to cover all of it.

- Lineage (2A): every copy/derivation is recorded as a flow on the ledger.
  `vault.lineage.graph(subject)` shows where data went; `locations(subject)`
  lists the full footprint; `trace(subject, start)` follows it downstream.
- Containment (2B): copies stored via `vault.store_at(...)` inherit the
  subject's one key, so destroying that key crypto-shreds every copy at once.
  `vault.verify_erasure_coverage(subject)` walks every location and proves
  each copy is unreadable after erasure.

Demos:
```
python demo/demo_lineage.py      # trace the sprawl, erase across all of it
python demo/demo_containment.py  # one key-shred kills every real copy
```

Honest scope: containment is guaranteed for data that went through Tombstone
(it inherits the key). A plaintext copy made by bypassing Tombstone entirely
cannot be crypto-shredded by anyone; lineage tracking is how you catch those
flows and route them through the system in the first place.

## Phase 3: flow-control proxy (v0.3)

Phases 1 and 2 handle data at rest and its copies. Phase 3 stops data in
motion: a real HTTP forward proxy that inspects request bodies and blocks
personal-data leaks before they leave, recording every decision on the
tamper-evident ledger.

```
python demo/demo_proxy.py
```

The demo starts a real destination server and a real proxy, then sends two
live HTTP requests: a clean one (forwarded) and one carrying a subject's
email (blocked with HTTP 451, never reaches the destination). The ledger
records both decisions, with personal data masked so the audit log itself
never leaks.

Honest scope: this is a laptop-scale reference implementation of the
egress-control pattern. It inspects plain HTTP bodies. It does NOT do TLS
interception or production-grade throughput. The value is the working
pattern: real payload inspection + policy + tamper-evident decision log.

## Phase 5: hardening, attack yourself (v0.4)

A security tool is only as good as the attacks it survives. Tombstone ships an
adversarial test suite that tries to defeat its own guarantees:

```
python attack.py          # readable attack report
pytest tests/             # the same attacks as assertions
```

Attacks and current status:

- Forge a past entry (alter contents, keep hash): DEFENDED (hash mismatch).
- Reorder entries: DEFENDED (broken prev_hash link).
- Truncate the log (delete recent entries to hide them): DEFENDED. The ledger
  keeps an HMAC-authenticated head recording chain length and tip; truncation
  makes the log disagree with the head, and the head cannot be forged without
  the secret key.
- Recover data after crypto-shred: DEFENDED (vault read fails; no plaintext on
  disk, only ciphertext for a destroyed key).
- Sneak obfuscated PII past the proxy (spacing, [at]/[dot] tricks): DEFENDED
  via payload normalization.

Honest limits (the next hardening targets, not yet done):
- The head-signing secret currently lives next to the ledger. Truly hardened,
  it belongs in a separate KMS/HSM so an attacker with full disk access still
  cannot forge the head.
- Secure key deletion on SSDs is hard (wear-leveling). The robust answer is
  envelope encryption: wrap subject keys under a KMS master key whose
  destruction is attestable, so erasure never depends on physically scrubbing
  bytes. Planned.
- Content inspection is an arms race. Normalization defeats trivial evasion;
  encoding, encryption, or splitting across requests still requires deeper
  inspection.

## Phase 5b: envelope encryption (v0.5)

Erasure no longer trusts the disk. Every subject key is wrapped (encrypted)
under a master key; only the wrapped form is ever written. Two erasure paths,
neither depending on physically scrubbing bytes:

- Erase one subject: destroy their wrapped key.
- Crypto-erase everyone at once: destroy the master key. Every wrapped subject
  key becomes permanently un-unwrappable, even copies an attacker hoarded.

```
python demo/demo_envelope.py   # destroy the master, watch everyone die at once
```

Attack 6 in the suite hoards wrapped key files, destroys the master, and
confirms the hoarded keys are useless. 8 security tests pass (pytest tests/).

Honest limit: the master key still lives in a local file. Truly hardened, it
belongs in a KMS/HSM that performs and attests its own destruction, so erasure
is provable to a third party and disk access alone cannot recover it. The
wrap/unwrap interface is exactly what a KMS slots into; that integration is the
next deployment-hardening step.

## Phase 6: Merkle-tree proofs (v0.6)

The hash chain proves the whole log is intact, but proving a single entry
meant handing over the whole log. A Merkle tree (RFC 6962 hashing, the
Certificate Transparency scheme) adds two things:

- Inclusion proof: prove "entry X is in the log" with about log2(n) hashes,
  without revealing other entries. Prove an erasure is recorded without
  dumping everyone else's events.
- Consistency proof: prove the log only ever grew, never rewrote history.

```
python demo/demo_merkle.py   # prove one erasure privately; reject a forgery
```

Tombstone now has layered integrity: the hash chain catches content tampering,
the authenticated head catches truncation, and the Merkle tree gives efficient
inclusion and consistency proofs. 10 security tests pass (pytest tests/).

Honest limit: this consistency proof returns the two roots and recomputes,
which is correct and demonstrable but not the minimal-subset RFC 6962 proof.
The minimal-hash optimization is a later refinement.
