"""
policy.py  -  Phase 3 brain: decide whether a data flow is allowed.

This is the part that is genuinely yours. The proxy (proxy.py) does the
plumbing; this decides allow vs block.

The model is deliberately simple and readable:

  - You register "protected values" for a subject: the actual strings that
    are that person's personal data (email, name, etc). In a real system
    these come from the vault; here we register them explicitly so the
    policy can recognize them in a payload.

  - You define rules. A rule says: if a payload contains protected data of
    a given class, and is heading to a destination of a given kind, block it.

  - check_payload() scans an outbound request body for any protected value
    and returns an allow/block decision with the reason.

Every decision is meant to be written to the tamper-evident ledger by the
caller (the proxy does this), so there is an auditable record of what was
blocked and why.
"""

import re
from dataclasses import dataclass, field


@dataclass
class Decision:
    allowed: bool
    reason: str
    matched: list[str] = field(default_factory=list)  # which protected items hit


# Built-in PII patterns, so the proxy can catch personal data even when it
# was not explicitly registered (defense in depth). Narrow on purpose to
# keep false positives low.
PII_PATTERNS = {
    "email": re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}"),
    "ssn": re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
    "credit_card": re.compile(r"\b(?:\d[ -]*?){13,16}\b"),
}


class Policy:
    def __init__(self):
        # subject_id -> set of exact protected strings (their personal data)
        self._protected: dict[str, set[str]] = {}
        # destinations that are considered "external / not allowed to receive PII"
        self._blocked_dests: set[str] = set()
        # if True, any PII pattern in a payload to a blocked dest is denied,
        # even if the exact value was never registered
        self.block_pii_patterns = True

    def protect(self, subject_id: str, *values: str) -> None:
        """Register the exact personal-data strings belonging to a subject."""
        self._protected.setdefault(subject_id, set()).update(v for v in values if v)

    def block_destination(self, *hosts: str) -> None:
        """Mark destinations that must NOT receive protected/PII data."""
        self._blocked_dests.update(hosts)

    def _dest_is_blocked(self, dest: str) -> bool:
        # Match on host substring so "us-analytics.example.com:443" still hits
        # a rule written as "us-analytics.example.com".
        return any(b in dest for b in self._blocked_dests)

    def check_payload(self, dest: str, payload: str) -> Decision:
        """
        Decide whether sending `payload` to `dest` is allowed.

        Block if the destination is restricted AND the payload contains either
        a registered protected value or a recognizable PII pattern.
        """
        if not self._dest_is_blocked(dest):
            return Decision(True, f"destination '{dest}' is not restricted")

        matched: list[str] = []

        # 1. Exact registered protected values (strongest signal).
        for subject_id, values in self._protected.items():
            for v in values:
                if v and v in payload:
                    matched.append(f"{subject_id}:{_mask(v)}")

        # 2. Generic PII patterns (defense in depth).
        if self.block_pii_patterns:
            for kind, pat in PII_PATTERNS.items():
                if pat.search(payload):
                    matched.append(f"pii:{kind}")

        if matched:
            return Decision(
                False,
                f"blocked: protected data heading to restricted '{dest}'",
                matched=sorted(set(matched)),
            )
        return Decision(True, f"no protected data found in payload to '{dest}'")


def _mask(value: str) -> str:
    """Mask a protected value so it is not echoed in logs/ledger in the clear."""
    if "@" in value:  # email: show first char + domain
        local, _, domain = value.partition("@")
        return f"{local[:1]}***@{domain}"
    if len(value) <= 4:
        return "***"
    return f"{value[:2]}***{value[-1:]}"
