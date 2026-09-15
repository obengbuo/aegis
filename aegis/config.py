"""
aegis/config.py — AegisConfig: the public configuration surface.

No MODULE-LEVEL imports from other aegis.* modules — so it can be imported
early by aegis/__init__.py without any risk of circular imports as wrapper.py,
audit.py, etc. consume its fields. approval_callback's type hint references
aegis.policy.Decision, but only under TYPE_CHECKING (see below), so that
stays true at runtime — a type checker sees the real type; nothing is
actually imported when this module loads.

__post_init__ does import aegis.shipper, but function-locally, at call time
rather than load time — the same deferred pattern aegis.audit.write_record
uses. The load-time import graph is unchanged, and tests/test_import_graph.py
pins that: it fails if this import is ever promoted to module level.

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
    # Control-plane shipping (aegis-controlplane). All three default to None:
    # shipping is inert unless control_plane_url is set. When set, audit
    # records are POSTed best-effort to {control_plane_url}/v1/records on a
    # background thread — never on the enforcement path. deployment_id labels
    # this deployment's stream in the aggregated backend. See aegis/shipper.py.
    control_plane_url: str | None = None
    control_plane_api_key: str | None = None
    deployment_id: str | None = None

    def __post_init__(self) -> None:
        """Activate control-plane shipping the moment a destination is declared.

        This constructor is the earliest point at which *where records go* is
        known. wrap_toolset — the previous activation point — is only the
        earliest point at which a *toolset* is known, which is a different
        fact. Anything written in between went to JSONL and nowhere else,
        silently; and that window is guaranteed non-empty in exactly the
        integrations that want linked run provenance, because
        run_id=config.run_id forces this config to precede load_spec /
        propose_spec. Activating here makes the window empty by construction
        rather than by documentation.

        This keeps the destination out of load_spec and propose_spec entirely:
        the coupling runs config -> shipper, so neither loader learns about
        config.py and no sandbox_root-vs-config.sandbox_root contradiction
        surface reappears. The shipper reads three fields nobody else passes.

        The import is function-local, mirroring aegis.audit.write_record's, so
        config.py keeps its no-runtime-imports-from-aegis.* property at module
        load and the config -> shipper edge cannot close into a cycle (shipper
        names AegisConfig only under TYPE_CHECKING). Pinned by
        tests/test_import_graph.py. No-op and near-free when
        control_plane_url is unset — the common case.
        """
        if not self.control_plane_url:
            return

        from aegis import shipper

        shipper.configure(self)
