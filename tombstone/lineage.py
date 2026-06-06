"""
lineage.py  -  Phase 2A: tracking where a subject's data goes.

Phase 1 erased data in ONE place. The real problem (the one that beat Meta)
is that data gets COPIED and DERIVED: an email lands in a marketing table, a
nightly job rolls it into an analytics summary, an analyst exports a CSV. When
the person says "delete me", you have to know EVERYWHERE their data went.

Lineage records each flow as an event:
    subject S's data flowed from location A to location B (as a copy or derivation)

Locations are just string labels you choose, e.g. "users_table",
"marketing_export", "ml_training_set". That is enough to build the graph.

Every flow is also written to the tamper-evident ledger, so the record of
where data went is itself auditable and cannot be quietly rewritten.
"""

from .ledger import Ledger


class Lineage:
    """A subject-keyed graph of data flows, backed by the tamper-evident ledger."""

    def __init__(self, ledger: Ledger):
        # Reuse the SAME ledger as the Vault, so flows and erasures live in
        # one chained, verifiable history.
        self.ledger = ledger

    def record_flow(
        self,
        subject_id: str,
        source: str,
        dest: str,
        kind: str = "copy",
    ) -> dict:
        """
        Record that a subject's data moved from `source` to `dest`.

        kind: "copy" (exact copy), "derive" (a transformation/rollup that
              still contains or reveals the subject), or "origin" (the first
              place the data entered the system).

        The flow is committed to the ledger. The commitment encodes the
        from/to/kind so the audit trail proves the claimed lineage.
        """
        # The ledger's data_commitment field carries a description of the flow.
        # It is not personal data, just "where to where, and how".
        commitment = f"flow:{kind}:{source}->{dest}"
        return self.ledger.append(subject_id, "flow", commitment)

    def _flows(self, subject_id: str) -> list[tuple[str, str, str]]:
        """Return [(source, dest, kind), ...] for a subject, oldest first."""
        out = []
        for e in self.ledger.events_for(subject_id):
            if e["event_type"] != "flow":
                continue
            # commitment looks like "flow:copy:A->B"
            try:
                _, kind, route = e["data_commitment"].split(":", 2)
                source, dest = route.split("->", 1)
                out.append((source, dest, kind))
            except ValueError:
                continue
        return out

    def locations(self, subject_id: str) -> set[str]:
        """
        Every location a subject's data has reached: all sources and all
        destinations seen in any recorded flow. This is the subject's full
        data footprint, the thing you must cover to erase them completely.
        """
        places: set[str] = set()
        for source, dest, _kind in self._flows(subject_id):
            places.add(source)
            places.add(dest)
        return places

    def graph(self, subject_id: str) -> list[dict]:
        """The lineage as a readable list of edges (for display/proof)."""
        return [
            {"from": s, "to": d, "kind": k}
            for (s, d, k) in self._flows(subject_id)
        ]

    def trace(self, subject_id: str, start: str) -> set[str]:
        """
        Follow the data downstream from `start`: every location reachable
        by following copy/derive edges. Answers "if data entered at `start`,
        where could it have spread?"
        """
        # Build adjacency from the recorded flows.
        edges: dict[str, list[str]] = {}
        for source, dest, _kind in self._flows(subject_id):
            edges.setdefault(source, []).append(dest)

        seen = {start}
        stack = [start]
        while stack:
            node = stack.pop()
            for nxt in edges.get(node, []):
                if nxt not in seen:
                    seen.add(nxt)
                    stack.append(nxt)
        return seen
