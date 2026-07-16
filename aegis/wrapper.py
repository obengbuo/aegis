"""
aegis/wrapper.py — the interception layer between agents and MCP servers.

THIS IS THE HEART OF THE PRODUCT.

Pydantic AI fires `process_tool_call` for every tool call before it reaches
the MCP server. In Phase 1 this hook logs the call and returns the result
unchanged. In Phase 2 the same hook evaluates policy and may block the call.

Every MCP server wired into any agent MUST pass:
    process_tool_call=process_tool_call
Never let a tool call bypass this function.
"""

from __future__ import annotations

import time
import uuid
from datetime import datetime, timezone
from typing import Any, Callable, Awaitable, TYPE_CHECKING

from aegis.audit import write_record
from aegis.fingerprint import note_server_seen
from aegis.policy import AegisApprovalRequired, CapabilitySpec, Decision, evaluate
from aegis.response_inspection import scan_response

if TYPE_CHECKING:
    from pydantic_ai.mcp import MCPToolset

    from aegis.config import AegisConfig

ApprovalCallback = Callable[[str, str, dict[str, Any], Decision], bool]

# Generated once at module load — the run_id used when no AegisConfig (and
# so no config.run_id) is supplied. Keeps Phase 1 callers (make_process_tool_call
# with no config) correlatable across a process lifetime without requiring
# any code change on their part.
_DEFAULT_RUN_ID: str = str(uuid.uuid4())


def wrap_toolset(
    toolset: "MCPToolset",
    server_name: str,
    spec: CapabilitySpec | None = None,
    config: "AegisConfig | None" = None,
) -> "MCPToolset":
    """Wire Aegis enforcement onto an existing MCPToolset.

    Mutates the passed toolset in place — sets its process_tool_call hook —
    and returns the same object for chaining convenience. Do NOT keep a
    separate reference to the pre-wrap toolset expecting it to remain
    un-enforced; there is only one toolset object. Preserves all other
    MCPToolset configuration by not touching it.

    This is the deliberate choice over reconstructing a new MCPToolset:
    process_tool_call is a plain mutable attribute on MCPToolset (not
    frozen), and reconstruction would require copying every other
    constructor-derived attribute by hand — a maintenance burden that
    silently drops config on future pydantic-ai upgrades we don't track.
    Mutation-in-place cannot drop anything because nothing is rebuilt.

    config.otlp_endpoint (Week 5 Stream 2), config.run_id (Stream 3),
    config.approval_callback (Stream 4), and config.response_inspection_mode
    (Stream 5), when set, are threaded into every call this server's hook
    makes — audit records are mirrored as OTLP spans, every record from this
    server carries the same run_id for cross-call correlation, INTERCEPT
    verdicts are routed through the callback for synchronous approval, and
    tool responses are scanned for sensitive-data patterns. config.log_path
    is accepted but not yet consumed — a later stream.

    Usage:
        filesystem = wrap_toolset(MCPToolset(...), "filesystem", spec=spec)
    """
    otlp_endpoint = config.otlp_endpoint if config is not None else None
    run_id = config.run_id if config is not None else None
    approval_callback = config.approval_callback if config is not None else None
    response_inspection_mode = config.response_inspection_mode if config is not None else "off"
    toolset.process_tool_call = make_process_tool_call(
        server_name,
        spec,
        otlp_endpoint=otlp_endpoint,
        run_id=run_id,
        approval_callback=approval_callback,
        response_inspection_mode=response_inspection_mode,
    )
    return toolset


def make_process_tool_call(
    server_name: str,
    spec: CapabilitySpec | None = None,
    otlp_endpoint: str | None = None,
    run_id: str | None = None,
    approval_callback: "ApprovalCallback | None" = None,
    response_inspection_mode: str = "off",
) -> Callable[..., Awaitable[Any]]:
    """Return a process_tool_call hook bound to a specific server name.

    Pass spec to enable enforcement; omit (or pass None) for Phase 1 log-only
    behavior. Pass otlp_endpoint to additionally mirror every audit record
    this hook writes as an OTLP span. Pass run_id to correlate every record
    this hook writes with the rest of one agent run; if omitted (Phase 1
    mode — no AegisConfig), records still get a run_id, drawn from a
    per-process default generated once at module load, so every record
    stays correlatable even without explicit configuration. Pass
    approval_callback to synchronously resolve INTERCEPT verdicts (see
    aegis.policy.evaluate); if omitted, an INTERCEPT verdict raises
    AegisApprovalRequired instead of calling anything. Pass
    response_inspection_mode ("off" default, "warn", or "block") to scan
    tool responses for sensitive-data patterns after a successful call; see
    aegis.response_inspection.scan_response. Existing callsites that pass
    only server_name are unaffected.

    Usage in servers.py:
        filesystem = MCPToolset(..., process_tool_call=make_process_tool_call("filesystem"))
        fetch      = MCPToolset(..., process_tool_call=make_process_tool_call("fetch", spec=spec))
    """
    async def _hook(
        ctx: Any,
        call_tool: Callable[..., Awaitable[Any]],
        tool_name: str,
        args: dict[str, Any],
    ) -> Any:
        return await _process(
            server_name, spec, otlp_endpoint, run_id, approval_callback, response_inspection_mode,
            ctx, call_tool, tool_name, args,
        )

    return _hook


async def process_tool_call(
    ctx: Any,
    call_tool: Callable[..., Awaitable[Any]],
    tool_name: str,
    args: dict[str, Any],
) -> Any:
    """Pydantic AI process_tool_call hook (unnamed fallback — prefer make_process_tool_call).

    No spec → Phase 1 log-only behavior.
    """
    return await _process(
        "unknown-server", None, None, None, None, "off", ctx, call_tool, tool_name, args
    )


async def _process(
    server_name: str,
    spec: CapabilitySpec | None,
    otlp_endpoint: str | None,
    run_id: str | None,
    approval_callback: "ApprovalCallback | None",
    response_inspection_mode: str,
    ctx: Any,
    call_tool: Callable[..., Awaitable[Any]],
    tool_name: str,
    args: dict[str, Any],
) -> Any:
    """Core interception logic shared by the named and unnamed hooks."""
    call_id = str(uuid.uuid4())
    started = time.monotonic()

    # No run_id supplied (Phase 1 mode, or an AegisConfig with run_id
    # explicitly set to None) — fall back to the per-process default so
    # every record is still correlatable.
    effective_run_id = run_id if run_id is not None else _DEFAULT_RUN_ID

    base_record: dict[str, Any] = {
        "call_id": call_id,
        "ts": datetime.now(timezone.utc).isoformat(),
        "server": server_name,
        "tool": tool_name,
        "run_id": effective_run_id,
        "args": _safe_args(args),
    }

    # Phase 1: note that we've seen this server (feeds fingerprinting)
    note_server_seen(server_name)

    # Set True only when an INTERCEPT verdict was approved via callback —
    # flags the eventual ok/error record so an investigator can tell
    # "approved after intercept" apart from a straight ALLOW.
    approved_after_intercept = False

    # Phase 2: policy enforcement — skipped when no spec is provided
    if spec is not None:
        try:
            decision = evaluate(spec, server_name, tool_name, args)
        except Exception as exc:  # noqa: BLE001 — fail closed
            write_record({
                **base_record,
                "status": "policy_evaluation_error",
                "error": f"{type(exc).__name__}: {exc}",
                "spec_hash": spec.spec_hash,
            }, otlp_endpoint=otlp_endpoint)
            raise PermissionError("policy evaluation failed") from exc

        if decision.verdict == "DENY":
            write_record({
                **base_record,
                "status": "denied",
                "reason": decision.reason,
                "matched_rule": decision.matched_rule,
                "spec_hash": spec.spec_hash,
            }, otlp_endpoint=otlp_endpoint)
            raise PermissionError(decision.reason)

        if decision.verdict == "INTERCEPT":
            write_record({
                **base_record,
                "status": "intercepted",
                "reason": decision.reason,
                "matched_rule": decision.matched_rule,
                "spec_hash": spec.spec_hash,
            }, otlp_endpoint=otlp_endpoint)

            if approval_callback is not None:
                approved = approval_callback(server_name, tool_name, args, decision)
                if not approved:
                    write_record({
                        **base_record,
                        "status": "denied_after_intercept",
                        "reason": "operator declined intercepted call",
                        "matched_rule": "rule-9-intercept-denied-by-operator",
                        "spec_hash": spec.spec_hash,
                    }, otlp_endpoint=otlp_endpoint)
                    raise PermissionError("operator declined intercepted call")
                approved_after_intercept = True
            else:
                raise AegisApprovalRequired(server_name, tool_name, args, decision)
        # ALLOW, or an INTERCEPT approved above, falls through to the call below

    try:
        result = await call_tool(tool_name, args)
    except Exception as exc:  # noqa: BLE001 - we re-raise after logging
        error_record: dict[str, Any] = {
            **base_record,
            "status": "error",
            "latency_ms": round((time.monotonic() - started) * 1000, 1),
            "error": f"{type(exc).__name__}: {exc}",
        }
        if approved_after_intercept:
            error_record["intercepted"] = True
        write_record(error_record, otlp_endpoint=otlp_endpoint)
        raise

    # call_tool succeeded. Response inspection runs outside the except above
    # on purpose: a block-mode PermissionError raised below must never be
    # caught and relogged as a tool-call "error" — the call succeeded; Aegis
    # is choosing not to forward the response, which is a different event.
    response_had_matches = False
    if response_inspection_mode != "off":
        scan = scan_response(result, {"server": server_name, "tool": tool_name, "call_id": call_id})
        if scan.verdict != "clean":
            response_had_matches = True
            write_record({
                **base_record,
                "status": "response_pattern_detected",
                "patterns": [
                    {"name": p.pattern_name, "preview": p.match_repr, "pos": p.position}
                    for p in scan.patterns_matched
                ],
                "response_inspection_verdict": scan.verdict,
            }, otlp_endpoint=otlp_endpoint)

            if scan.verdict == "block" and response_inspection_mode == "block":
                raise PermissionError(
                    f"response blocked: {scan.patterns_matched[0].pattern_name} detected"
                )
            # "warn" mode, or "block" mode with only warn-tier matches:
            # fall through and return the response as-is.

    ok_record: dict[str, Any] = {
        **base_record,
        "status": "ok",
        "latency_ms": round((time.monotonic() - started) * 1000, 1),
        # If response inspection matched, the raw response is not previewed
        # here — the audit log must not become the leak it just detected.
        # The response_pattern_detected record above already carries
        # redacted previews via PatternMatch.match_repr.
        "result_preview": (
            "[redacted: response matched a sensitive-data pattern — "
            "see the response_pattern_detected record for this call_id]"
            if response_had_matches
            else _preview(result)
        ),
    }
    if approved_after_intercept:
        ok_record["intercepted"] = True
    write_record(ok_record, otlp_endpoint=otlp_endpoint)
    return result


def _safe_args(args: dict[str, Any]) -> dict[str, Any]:
    """Truncate oversized argument values so the audit log stays readable.

    NOTE for Phase 2: this is also where PII redaction will live.
    """
    safe: dict[str, Any] = {}
    for key, value in args.items():
        text = str(value)
        safe[key] = text if len(text) <= 1000 else text[:1000] + "...[truncated]"
    return safe


def _preview(result: Any, limit: int = 500) -> str:
    """Short, log-friendly preview of a tool result."""
    text = str(result)
    return text if len(text) <= limit else text[:limit] + "...[truncated]"
