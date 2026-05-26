"""
aegis/startup.py — governed MCP server startup with Aegis audit trail.

Server startup failures are security-relevant events, not just crashes. A
server that never comes up could mean:
  - a supply-chain package was yanked / maliciously replaced
  - a credentials problem (token revoked, env var missing)
  - a cold-start timeout hiding a hung process
  - a network partition in a remote server scenario

This module wraps the startup path so every failure is:
  1. Written to the audit log (status: server_init_failed)
  2. Retried once with backoff to rule out transient cold-start issues
  3. Loud — printed clearly before the exception is re-raised

Fail-closed policy: if a server cannot start after all attempts, the run
halts. A partial stack is not a safe stack. We never fail open silently.
"""

from __future__ import annotations

import asyncio
import uuid
from contextlib import asynccontextmanager, AsyncExitStack
from datetime import datetime, timezone
from typing import Any, AsyncIterator

from pydantic_ai.mcp import MCPToolset

from aegis.audit import write_record

# One retry gives the server a second chance on transient cold-start failures
# (npm/uvx JIT installs, slow Windows process spawning). Two attempts total.
_MAX_ATTEMPTS = 2
_RETRY_DELAY_S = 3.0


def _init_fail_record(
    server_name: str,
    attempt: int,
    exc: Exception,
) -> dict[str, Any]:
    return {
        "call_id": str(uuid.uuid4()),
        "ts": datetime.now(timezone.utc).isoformat(),
        "server": server_name,
        "status": "server_init_failed",
        "attempt": attempt,
        "max_attempts": _MAX_ATTEMPTS,
        "error": f"{type(exc).__name__}: {exc}",
    }


@asynccontextmanager
async def managed_servers(
    servers: dict[str, MCPToolset],
) -> AsyncIterator[dict[str, MCPToolset]]:
    """Start every MCP server, logging all failures to the Aegis audit trail.

    Each server gets up to _MAX_ATTEMPTS startup attempts. Every failed
    attempt is written to the audit log immediately. If all attempts fail,
    a RuntimeError is raised and any already-started servers are cleanly
    shut down (AsyncExitStack handles this).

    This is a context manager: enter it before the agent context managers
    so governance runs at the outermost layer.

    Usage:
        async with managed_servers(ACTIVE_SERVERS):
            async with orchestrator:
                ...
    """
    async with AsyncExitStack() as stack:
        for name, toolset in servers.items():
            last_exc: Exception | None = None

            for attempt in range(1, _MAX_ATTEMPTS + 1):
                try:
                    await stack.enter_async_context(toolset)
                    break  # success — move to next server
                except Exception as exc:
                    last_exc = exc
                    write_record(_init_fail_record(name, attempt, exc))

                    if attempt < _MAX_ATTEMPTS:
                        print(
                            f"  [Aegis] '{name}' init failed "
                            f"(attempt {attempt}/{_MAX_ATTEMPTS}), "
                            f"retrying in {_RETRY_DELAY_S:.0f}s  "
                            f"[{type(exc).__name__}]"
                        )
                        await asyncio.sleep(_RETRY_DELAY_S)
            else:
                # All attempts exhausted — fail closed.
                print(
                    f"\n[Aegis] Server '{name}' failed to initialize "
                    f"after {_MAX_ATTEMPTS} attempt(s).\n"
                    f"  status  : server_init_failed  (logged to audit)\n"
                    f"  policy  : fail-closed - a partial stack is not safe\n"
                    f"  action  : halting run\n"
                    f"  error   : {last_exc}"
                )
                # AsyncExitStack cleans up any already-started servers.
                raise RuntimeError(
                    f"Server '{name}' failed to initialize after "
                    f"{_MAX_ATTEMPTS} attempt(s)"
                ) from last_exc

        yield servers
