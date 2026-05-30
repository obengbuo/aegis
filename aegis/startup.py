"""
aegis/startup.py — governed MCP server startup with Aegis audit trail.

Server startup failures are security-relevant events, not just crashes.
This module is responsible for three things:

  1. Starting each MCP server with up to _MAX_ATTEMPTS attempts, logging
     every failure to the audit trail (status: server_init_failed).

  2. On any startup failure: tearing down already-started servers in
     reverse order with explicit instrumentation — __aexit__ is logged,
     then surviving child processes are identified and force-killed.

  3. Logging a server_teardown audit record for every shutdown so we can
     prove that cleanup happened (critical for fail-closed policy claims).

Why we need explicit PID-level cleanup
---------------------------------------
The MCP SDK's stdio_client() finally block calls _terminate_process_tree,
but that path is reached only after process.stdin.aclose() returns cleanly.
If fastmcp's _disconnect cancels the session task mid-cleanup, a
CancelledError escapes the `except Exception` guard on stdin.aclose(),
aborting the rest of the finally block before _terminate_process_tree runs.
On Windows, even when termination does run, it only kills the direct child
(npx.exe); node.exe is a grandchild that survives unless a Job Object
(requires pywin32) is in play. Either failure leaves orphaned node.exe
processes that hold ports and consume memory.

psutil fills the gap: we snapshot child PIDs before/after each server
starts, call __aexit__, then kill anything from that snapshot that is
still alive. This is belt-and-suspenders, not a replacement for the SDK's
own cleanup.

Fail-closed policy
-------------------
If a server cannot start after _MAX_ATTEMPTS, the run halts entirely.
A partial stack is not a safe stack: some tool calls would be logged and
some would not, which is worse than no run at all from a governance
perspective. Phase 2 can add graceful degradation once the policy engine
can mark specific servers as unavailable.
"""

from __future__ import annotations

import asyncio
import os
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Any, AsyncIterator

import psutil as _psutil

from pydantic_ai.mcp import MCPToolset

from aegis.audit import write_record

_MAX_ATTEMPTS = 2
_RETRY_DELAY_S = 3.0
_KILL_GRACE_S = 2.0  # seconds between SIGTERM and SIGKILL escalation

_self = _psutil.Process(os.getpid())


# ── Process-level helpers ─────────────────────────────────────────────────────

def _snapshot_children() -> set[int]:
    """Return PIDs of all current descendants of this Python process."""
    try:
        return {p.pid for p in _self.children(recursive=True)}
    except _psutil.Error:
        return set()


def _pid_alive(pid: int) -> bool:
    try:
        return _psutil.Process(pid).status() not in (
            _psutil.STATUS_ZOMBIE,
            _psutil.STATUS_DEAD,
        )
    except _psutil.NoSuchProcess:
        return False


async def _force_kill(pids: set[int]) -> dict[int, str]:
    """Terminate all pids, wait _KILL_GRACE_S, then kill survivors.

    Returns {pid: "terminated" | "force_killed" | "already_dead"}.
    """
    if not pids:
        return {}

    procs: list[_psutil.Process] = []
    for pid in pids:
        try:
            procs.append(_psutil.Process(pid))
        except _psutil.NoSuchProcess:
            pass

    # SIGTERM / TerminateProcess
    for proc in procs:
        try:
            proc.terminate()
        except _psutil.NoSuchProcess:
            pass

    # Non-blocking grace period
    await asyncio.sleep(_KILL_GRACE_S)

    # Escalate survivors to SIGKILL
    outcomes: dict[int, str] = {pid: "already_dead" for pid in pids}
    for proc in procs:
        try:
            if proc.is_running() and proc.status() not in (
                _psutil.STATUS_ZOMBIE,
                _psutil.STATUS_DEAD,
            ):
                proc.kill()
                outcomes[proc.pid] = "force_killed"
            else:
                outcomes[proc.pid] = "terminated"
        except _psutil.NoSuchProcess:
            outcomes[proc.pid] = "already_dead"

    return outcomes


# ── Audit record helpers ──────────────────────────────────────────────────────

def _ts() -> str:
    return datetime.now(timezone.utc).isoformat()


def _init_fail_record(server_name: str, attempt: int, exc: Exception) -> dict[str, Any]:
    return {
        "call_id": str(uuid.uuid4()),
        "ts": _ts(),
        "server": server_name,
        "status": "server_init_failed",
        "attempt": attempt,
        "max_attempts": _MAX_ATTEMPTS,
        "error": f"{type(exc).__name__}: {exc}",
    }


def _teardown_record(
    server_name: str,
    aexit_ok: bool,
    aexit_error: str | None,
    forced_pids: dict[int, str],
) -> dict[str, Any]:
    return {
        "call_id": str(uuid.uuid4()),
        "ts": _ts(),
        "server": server_name,
        "status": "server_teardown",
        "aexit_ok": aexit_ok,
        "aexit_error": aexit_error,
        "forced_pids": {str(k): v for k, v in forced_pids.items()},
    }


# ── Per-server shutdown ───────────────────────────────────────────────────────

async def _shutdown_server(
    name: str,
    toolset: MCPToolset,
    tracked_pids: set[int],
    verbose: bool,
) -> None:
    """Call __aexit__ on one toolset, verify child processes died, force-kill survivors.

    Writes a server_teardown audit record unconditionally so every shutdown
    is provable in the audit log.

    Args:
        name: Server name (matches the key in ACTIVE_SERVERS).
        toolset: The MCPToolset being shut down.
        tracked_pids: Child PIDs that appeared when this server was started.
        verbose: If True, print each step (used on the failure/halt path).
    """
    if verbose:
        print(f"  [Aegis] tearing down '{name}': __aexit__...", end=" ", flush=True)

    aexit_ok = False
    aexit_error: str | None = None

    try:
        await toolset.__aexit__(None, None, None)
        aexit_ok = True
        if verbose:
            print("ok")
    except Exception as exc:
        aexit_error = f"{type(exc).__name__}: {exc}"
        # Always print __aexit__ errors regardless of verbosity.
        print(f"\n  [Aegis] WARNING: '{name}' __aexit__ raised: {aexit_error}")

    # Belt-and-suspenders: check for surviving child processes.
    surviving = {pid for pid in tracked_pids if _pid_alive(pid)}
    forced: dict[int, str] = {}

    if surviving:
        print(
            f"  [Aegis] '{name}': {len(surviving)} child process(es) still alive "
            f"after __aexit__ - force-killing PIDs {surviving}"
        )
        forced = await _force_kill(surviving)
        for pid, outcome in sorted(forced.items()):
            marker = "[ok]" if outcome != "force_killed" else "[KILL]"
            print(f"    {marker} PID {pid}: {outcome}")
    elif verbose:
        print(f"  [Aegis] '{name}': all child processes exited cleanly.")

    write_record(_teardown_record(name, aexit_ok, aexit_error, forced))


# ── Context manager ───────────────────────────────────────────────────────────

@asynccontextmanager
async def managed_servers(
    servers: dict[str, MCPToolset],
) -> AsyncIterator[dict[str, MCPToolset]]:
    """Start every MCP server under Aegis governance.

    Each server is started individually. A PID snapshot is taken before and
    after each startup so we know exactly which child processes it owns.
    On any failure, already-started servers are torn down in reverse order
    with explicit instrumentation and PID-level force-kill.

    Fail-closed: a server that cannot start after _MAX_ATTEMPTS halts the
    run. A partial stack is not a safe stack.

    Usage::

        async with managed_servers(ACTIVE_SERVERS):
            async with orchestrator:   # re-enters same toolsets; _running_count nesting is safe
                ...
    """
    # (name, toolset, pids_spawned_by_this_server)
    started: list[tuple[str, MCPToolset, set[int]]] = []

    async def teardown_all(verbose: bool) -> None:
        for srv_name, ts, child_pids in reversed(started):
            try:
                await _shutdown_server(srv_name, ts, child_pids, verbose=verbose)
            except Exception as exc:
                print(f"  [Aegis] ERROR during teardown of '{srv_name}': {exc}")

    try:
        for name, toolset in servers.items():
            before = _snapshot_children()
            last_exc: Exception | None = None

            for attempt in range(1, _MAX_ATTEMPTS + 1):
                try:
                    await toolset.__aenter__()
                    break  # success
                except Exception as exc:
                    last_exc = exc
                    write_record(_init_fail_record(name, attempt, exc))

                    if attempt < _MAX_ATTEMPTS:
                        print(
                            f"  [Aegis] '{name}' init failed "
                            f"(attempt {attempt}/{_MAX_ATTEMPTS}), "
                            f"retrying in {_RETRY_DELAY_S:.0f}s  [{type(exc).__name__}]"
                        )
                        await asyncio.sleep(_RETRY_DELAY_S)
            else:
                # All attempts exhausted — fail closed.
                print(
                    f"\n[Aegis] Server '{name}' failed to initialize "
                    f"after {_MAX_ATTEMPTS} attempt(s).\n"
                    f"  status  : server_init_failed  (logged to audit)\n"
                    f"  policy  : fail-closed - a partial stack is not safe\n"
                    f"  action  : tearing down {len(started)} previously-started server(s)\n"
                    f"  error   : {last_exc}"
                )
                await teardown_all(verbose=True)
                started.clear()
                raise RuntimeError(
                    f"Server '{name}' failed to initialize after "
                    f"{_MAX_ATTEMPTS} attempt(s)"
                ) from last_exc

            # Record which child PIDs this server spawned.
            after = _snapshot_children()
            started.append((name, toolset, after - before))

        yield servers

    finally:
        # Normal exit or exception from the `async with` body.
        # started is empty only if we already tore down on the failure path.
        if started:
            await teardown_all(verbose=False)
            started.clear()
