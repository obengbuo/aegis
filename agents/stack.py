"""
agents/stack.py — the multi-agent, multi-MCP-server test stack.

Run this to exercise Aegis. Three agents with different jobs, all of their
tool calls flowing through the Aegis interception layer into logs/audit.jsonl.

Usage:
    python -m agents.stack
"""

from __future__ import annotations

import asyncio
import os
import sys

from dotenv import load_dotenv
from pydantic_ai import Agent

from agents.servers import ACTIVE_SERVERS, SANDBOX_DIR, demo, fetch, filesystem
from aegis.audit import summary
from aegis.fingerprint import check_server
from aegis.startup import managed_servers

load_dotenv()

MODEL = "anthropic:claude-sonnet-4-5"

# --- Three agents, three roles ---------------------------------------------

researcher = Agent(
    MODEL,
    toolsets=[fetch],
    system_prompt="You research topics using web fetch. Be concise and factual.",
)

ops_agent = Agent(
    MODEL,
    toolsets=[filesystem],
    system_prompt="You manage files inside the sandbox directory. Be careful.",
)

orchestrator = Agent(
    MODEL,
    toolsets=[filesystem, fetch, demo],
    system_prompt=(
        "You handle tasks that need both web research and file operations. "
        "Research first, then write results to files."
    ),
)


async def _fingerprint_servers() -> None:
    """List tools on every active server and compare against stored baselines."""
    print("\n--- Aegis: server fingerprinting ---")
    for name, toolset in ACTIVE_SERVERS.items():
        tools = await toolset.list_tools()
        result = check_server(name, tools)
        status = result["status"]
        fp = result.get("fingerprint", {})

        if status == "new":
            print(
                f"  [new]     {name:15s}  {fp['tool_count']} tools"
                f"  hash={fp['surface_hash'][:16]}..."
            )
        elif status == "unchanged":
            print(
                f"  [ok]      {name:15s}  {fp['tool_count']} tools  unchanged"
            )
        elif status == "drift":
            print(f"  [DRIFT!]  {name:15s}  SUPPLY-CHAIN ALERT")
            if result["tools_added"]:
                print(f"            added    : {result['tools_added']}")
            if result["tools_removed"]:
                print(f"            removed  : {result['tools_removed']}")
            if result["tools_modified"]:
                print(f"            modified : {result['tools_modified']}")
            print(
                f"            prev={result['previous_hash'][:16]}..."
                f"  curr={result['current_hash'][:16]}..."
            )
    print()


async def main() -> None:
    """Run a few representative tasks across the three agents."""
    os.makedirs(SANDBOX_DIR, exist_ok=True)

    # managed_servers is the outermost layer: starts each server under Aegis
    # governance and logs any startup failure to the audit trail before halting.
    # orchestrator re-enters the same toolsets (MCPToolset nesting is safe —
    # _running_count means the subprocess only starts and stops once).
    try:
        async with managed_servers(ACTIVE_SERVERS):
            async with orchestrator:
                print("=" * 60)
                print("AEGIS - multi-agent test stack")
                print("=" * 60)

                await _fingerprint_servers()

                r1 = await ops_agent.run(
                    "Create a file called notes.txt containing the line 'hello aegis'."
                )
                print(f"\n[ops_agent]      {r1.output}")

                r2 = await researcher.run(
                    "In one sentence, what is the Model Context Protocol?"
                )
                print(f"\n[researcher]     {r2.output}")

                r3 = await orchestrator.run(
                    "Fetch https://modelcontextprotocol.io and save a one-line "
                    "summary of what the site is about to summary.txt."
                )
                print(f"\n[orchestrator]   {r3.output}")

    except RuntimeError:
        # managed_servers already printed the formatted status block, logged
        # server_init_failed to the audit trail, and ran teardown before
        # raising. Exit cleanly — no traceback needed here.
        sys.exit(1)

    # Show what Aegis captured (outside managed_servers — servers are stopped).
    print("\n" + "=" * 60)
    print("AEGIS AUDIT SUMMARY")
    print("=" * 60)
    stats = summary()
    print(f"Total tool calls logged : {stats['total_calls']}")
    print(f"By status               : {stats['by_status']}")
    print(f"By server               : {stats['by_server']}")
    print(f"By tool                 : {stats['by_tool']}")
    print("\nFull detail in logs/audit.jsonl")


if __name__ == "__main__":
    asyncio.run(main())
