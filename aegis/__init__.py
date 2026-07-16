"""Aegis — runtime security and governance for the Model Context Protocol.

Public API surface for external integrators (see docs/WAXELL_INTEGRATION.md
once it exists). Internal modules — aegis.wrapper, aegis.policy, aegis.audit,
aegis.proposer, aegis.fingerprint, aegis.startup — remain directly importable
and unchanged; this facade only adds a stable top-level import path.
"""

from aegis.config import AegisConfig
from aegis.policy import AegisApprovalRequired, CapabilitySpec, SpecValidationError, load_spec
from aegis.proposer import propose_spec
from aegis.wrapper import wrap_toolset

__version__ = "0.1.0"

__all__ = [
    "wrap_toolset",
    "AegisConfig",
    "propose_spec",
    "load_spec",
    "CapabilitySpec",
    "SpecValidationError",
    "AegisApprovalRequired",
]
