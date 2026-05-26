"""
Smoke-test for managed_servers failure path. Run manually:
    python tests/_test_startup_failure.py

Not in the pytest suite (underscore prefix) — it hits the real audit log
and spawns subprocesses, so it is an integration test, not a unit test.
"""
import asyncio

from fastmcp.client.transports import StdioTransport
from pydantic_ai.mcp import MCPToolset

from aegis.audit import read_records
from aegis.startup import managed_servers

before = len(list(read_records()))

bad_server = MCPToolset(
    StdioTransport("python", ["__nonexistent_xyz__.py"]),
    init_timeout=5,
)


async def main() -> None:
    try:
        async with managed_servers({"bad-demo": bad_server}):
            print("ERROR: should not reach here")
    except RuntimeError as exc:
        print(f"[ok] RuntimeError raised as expected:\n     {exc}")

    new_records = list(read_records())[before:]
    init_fail = [r for r in new_records if r.get("status") == "server_init_failed"]
    print(f"\n[ok] {len(init_fail)} server_init_failed record(s) logged to audit:")
    for rec in init_fail:
        print(
            f"     server={rec['server']!r}  "
            f"attempt={rec['attempt']}/{rec['max_attempts']}  "
            f"error={rec['error'][:70]}"
        )


if __name__ == "__main__":
    asyncio.run(main())
