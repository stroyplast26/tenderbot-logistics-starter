"""Safety-first core for the AlumKomplekt B2B Lead Factory.

The package is intentionally transport-agnostic.  Importing it never sends an
email, calls Bitrix, or invokes an AI provider.  External writers are added only
after the stage acceptance tests and an explicit production cutover.
"""

from .store import FactoryStore

__all__ = ["FactoryStore"]

