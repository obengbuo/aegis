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

from dotenv import load_dotenv
from pydantic_ai import Agent

from agents.servers import SANDBOX_DIR, fetch, filesystem
from aegis.audit import summary

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
    toolsets=[filesystem, fetch],
    system_prompt=(
        "You handle tasks that need both web research and file operations. "
        "Research first, then write results to files."
    ),
)


async def main() -> None:
    """Run a few representative tasks across the three agents."""
    os.makedirs(SANDBOX_DIR, exist_ok=True)

    # The orchestrator's context manager starts ALL its MCP servers.
    # Running agents inside it keeps every server's subprocess alive.
    async with orchestrator:
        print("=" * 60)
        print("AEGIS — multi-agent test stack")
        print("=" * 60)

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

    # Show what Aegis captured.
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
