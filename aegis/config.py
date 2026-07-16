"""
aegis/config.py — AegisConfig: the public configuration surface.

No runtime imports from other aegis.* modules — so it can be imported early
by aegis/__init__.py without any risk of circular imports as wrapper.py,
audit.py, etc. consume its fields. approval_callback's type hint references
aegis.policy.Decision, but only under TYPE_CHECKING (see below), so that
stays true at runtime — a type checker sees the real type; nothing is
actually imported when this module loads.

No behavior yet for log_path: pure data, not yet wired into audit.py.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Callable, Literal

if TYPE_CHECKING:
    from aegis.policy import Decision


@dataclass(frozen=True)
class AegisConfig:
    """Configuration for a single Aegis-governed agent run.

    sandbox_root has no default — every run must state what it's allowed to
    touch. log_path, run_id, otlp_endpoint, approval_callback, and
    response_inspection_mode have sensible defaults so a minimal
    AegisConfig(sandbox_root=...) is always constructible.
    """

    sandbox_root: Path
    log_path: Path = Path("logs/audit.jsonl")
    run_id: str | None = field(default_factory=lambda: str(uuid.uuid4()))
    otlp_endpoint: str | None = None
    # Called synchronously from the wrapper when a call is INTERCEPTed:
    # (server, tool, args, decision) -> True to approve, False to deny.
    # None (default) means no callback is wired — an INTERCEPT verdict then
    # raises AegisApprovalRequired instead. See aegis/wrapper.py.
    approval_callback: "Callable[[str, str, dict, Decision], bool] | None" = None
    # "off" (default, zero cost — no scanning): "warn" logs pattern matches
    # to audit but still returns the response; "block" additionally raises
    # PermissionError for block-tier matches. See aegis/response_inspection.py.
    response_inspection_mode: Literal["off", "warn", "block"] = "off"
