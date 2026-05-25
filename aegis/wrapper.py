"""
aegis/wrapper.py — the interception layer between agents and MCP servers.

THIS IS THE HEART OF THE PRODUCT.

Pydantic AI fires `process_tool_call` for every tool call before it reaches
the MCP server. In Phase 1 this hook logs the call and returns the result
unchanged. In Phase 2 the same hook will evaluate policy and may block,
modify, or pause the call.

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


async def process_tool_call(
    ctx: Any,
    call_tool: Callable[..., Awaitable[Any]],
    tool_name: str,
    args: dict[str, Any],
) -> Any:
    """Pydantic AI process_tool_call hook.

    Args:
        ctx: run context provided by Pydantic AI
        call_tool: the actual callable that forwards to the MCP server
        tool_name: the name of the tool being called
        args: the arguments the agent wants to pass

    Returns:
        Whatever the MCP server returns (unchanged in Phase 1).

    Phase 1 behavior: log everything, pass through.
    Phase 2 behavior: evaluate policy first; ALLOW / DENY / INTERCEPT.
    """
    call_id = str(uuid.uuid4())
    server_name = getattr(ctx, "tool_name", None) or "unknown-server"
    started = time.monotonic()

    base_record = {
        "call_id": call_id,
        "ts": datetime.now(timezone.utc).isoformat(),
        "server": server_name,
        "tool": tool_name,
        "args": _safe_args(args),
    }

    # Phase 1: note that we've seen this server (feeds fingerprinting)
    note_server_seen(server_name)

    # -------------------------------------------------------------------
    # PHASE 2 INSERTION POINT:
    #   decision = evaluate_policy(server_name, tool_name, args)
    #   if decision == "DENY":   write_record({**base_record, "status": "denied"}); raise PermissionError(...)
    #   if decision == "INTERCEPT": await await_human_approval(call_id)
    # -------------------------------------------------------------------

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
