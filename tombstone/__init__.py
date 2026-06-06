"""Tombstone: provable, crypto-shredded erasure on a tamper-evident ledger."""

from .vault import Vault, SubjectErased
from .ledger import Ledger
from .keystore import KeyStore, MasterKeyDestroyed
from .lineage import Lineage
from .policy import Policy, Decision
from .proxy import TombstoneProxy
from . import merkle

__all__ = [
    "Vault", "SubjectErased", "Ledger", "KeyStore", "MasterKeyDestroyed", "Lineage",
    "Policy", "Decision", "TombstoneProxy", "merkle",
]
__version__ = "0.6.0"
