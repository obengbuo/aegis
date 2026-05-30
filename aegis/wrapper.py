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
from typing import Any, Callable, Awaitable

from aegis.audit import write_record
from aegis.fingerprint import note_server_seen
from aegis.policy import CapabilitySpec, evaluate


def make_process_tool_call(
    server_name: str,
    spec: CapabilitySpec | None = None,
) -> Callable[..., Awaitable[Any]]:
    """Return a process_tool_call hook bound to a specific server name.

    Pass spec to enable enforcement; omit (or pass None) for Phase 1 log-only
    behavior. Existing callsites that pass only server_name are unaffected.

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
        return await _process(server_name, spec, ctx, call_tool, tool_name, args)

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
    return await _process("unknown-server", None, ctx, call_tool, tool_name, args)


async def _process(
    server_name: str,
    spec: CapabilitySpec | None,
    ctx: Any,
    call_tool: Callable[..., Awaitable[Any]],
    tool_name: str,
    args: dict[str, Any],
) -> Any:
    """Core interception logic shared by the named and unnamed hooks."""
    call_id = str(uuid.uuid4())
    started = time.monotonic()

    base_record: dict[str, Any] = {
        "call_id": call_id,
        "ts": datetime.now(timezone.utc).isoformat(),
        "server": server_name,
        "tool": tool_name,
        "args": _safe_args(args),
    }

    # Phase 1: note that we've seen this server (feeds fingerprinting)
    note_server_seen(server_name)

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
            })
            raise PermissionError("policy evaluation failed") from exc

        if decision.verdict == "DENY":
            write_record({
                **base_record,
                "status": "denied",
                "reason": decision.reason,
                "matched_rule": decision.matched_rule,
                "spec_hash": spec.spec_hash,
            })
            raise PermissionError(decision.reason)
        # ALLOW falls through to the call below

    try:
        result = await call_tool(tool_name, args)
        write_record({
            **base_record,
            "status": "ok",
            "latency_ms": round((time.monotonic() - started) * 1000, 1),
            "result_preview": _preview(result),
        })
        return result
    except Exception as exc:  # noqa: BLE001 - we re-raise after logging
        write_record({
            **base_record,
            "status": "error",
            "latency_ms": round((time.monotonic() - started) * 1000, 1),
            "error": f"{type(exc).__name__}: {exc}",
        })
        raise


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
