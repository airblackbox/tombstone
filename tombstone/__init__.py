"""Tombstone: provable erasure for AI data pipelines.

Crypto-shred every copy of a person's data, prove it on a tamper-evident ledger
anchored to a public transparency log, and guard the agents that touch the data.
"""

from .vault import Vault, SubjectErased
from .ledger import Ledger
from .keystore import KeyStore, MasterKeyDestroyed
from .lineage import Lineage
from .policy import Policy, Decision
from .proxy import TombstoneProxy
from . import merkle
from .anchor import RekorAnchor, LocalAnchor, AnchorError

__all__ = [
    "Vault", "SubjectErased", "Ledger", "KeyStore", "MasterKeyDestroyed", "Lineage",
    "Policy", "Decision", "TombstoneProxy", "merkle",
    "RekorAnchor", "LocalAnchor", "AnchorError",
]
__version__ = "0.7.0"
