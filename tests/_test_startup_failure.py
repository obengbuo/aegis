"""
Smoke-test for managed_servers failure path. Run manually:
    python -m tests._test_startup_failure

Not in the pytest suite (underscore prefix) — it spawns real subprocesses
and reads/writes the shared audit log.

What this tests
---------------
1. One server starts OK (the demo server), one fails (a bad script path).
2. managed_servers logs 2 x server_init_failed records for the bad server.
3. managed_servers calls __aexit__ on the good server and logs a
   server_teardown record with aexit_ok=True.
4. No node/python child processes belonging to the demo server survive after
   teardown (forced_pids should be empty if MCP SDK cleanup ran cleanly, or
   contain "terminated"/"force_killed" entries if it needed our help).
5. A RuntimeError is raised — the run halts (fail-closed policy).
"""
import asyncio
import sys
from pathlib import Path

from fastmcp.client.transports import StdioTransport
from pydantic_ai.mcp import MCPToolset

from aegis.audit import read_records
from aegis.startup import managed_servers

_REPO_ROOT = Path(__file__).parent.parent

good_server = MCPToolset(
    StdioTransport(sys.executable, [str(_REPO_ROOT / "tools" / "demo_server.py")]),
    init_timeout=30,
)

bad_server = MCPToolset(
    StdioTransport("python", ["__nonexistent_xyz__.py"]),
    init_timeout=5,
)


async def main() -> None:
    before = len(list(read_records()))

    print("Running managed_servers with one good server and one bad server...\n")
    try:
        async with managed_servers({"demo": good_server, "bad-demo": bad_server}):
            print("ERROR: should not reach here")
    except RuntimeError as exc:
        print(f"\n[ok] RuntimeError raised: {exc}")

    new_records = list(read_records())[before:]

    init_fail = [r for r in new_records if r.get("status") == "server_init_failed"]
    teardown = [r for r in new_records if r.get("status") == "server_teardown"]

    print(f"\n--- Audit records written: {len(new_records)} ---")
    print(f"  server_init_failed : {len(init_fail)}")
    for r in init_fail:
        print(
            f"    server={r['server']!r}  "
            f"attempt={r['attempt']}/{r['max_attempts']}  "
            f"error={r['error'][:60]}"
        )

    print(f"  server_teardown    : {len(teardown)}")
    for r in teardown:
        survivors = r.get("forced_pids", {})
        print(
            f"    server={r['server']!r}  "
            f"aexit_ok={r['aexit_ok']}  "
            f"aexit_error={r.get('aexit_error')!r}  "
            f"forced_pids={survivors}"
        )

    # Assertions
    assert len(init_fail) == _MAX_ATTEMPTS_EXPECTED, (
        f"Expected {_MAX_ATTEMPTS_EXPECTED} server_init_failed records, got {len(init_fail)}"
    )
    assert len(teardown) == 1, f"Expected 1 server_teardown record, got {len(teardown)}"
    assert teardown[0]["server"] == "demo", "Teardown should be for the demo server"
    assert teardown[0]["aexit_ok"] is True, "__aexit__ should have succeeded"

    forced = teardown[0].get("forced_pids", {})
    if not forced:
        print("\n[ok] No PIDs needed cleanup - __aexit__ terminated all child processes cleanly.")
    else:
        sigkilled = [p for p, o in forced.items() if o == "force_killed"]
        terminated = [p for p, o in forced.items() if o == "terminated"]
        print(
            f"\n[note] {len(forced)} PID(s) were still alive after __aexit__ "
            f"(MCP SDK did not clean them up):"
        )
        if terminated:
            print(f"  {len(terminated)} responded to SIGTERM: {terminated}")
        if sigkilled:
            print(f"  {len(sigkilled)} needed SIGKILL: {sigkilled}")
        if not sigkilled:
            print("[ok] All orphaned processes terminated cleanly (no SIGKILL needed).")

    print("\n[ok] All assertions passed.")


_MAX_ATTEMPTS_EXPECTED = 2  # from aegis/startup.py _MAX_ATTEMPTS

if __name__ == "__main__":
    asyncio.run(main())
