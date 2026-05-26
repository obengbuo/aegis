"""
agents/servers.py — definitions of the MCP servers used by the test stack.

Every server is wired with Aegis's process_tool_call hook. That is the rule:
no MCP server enters an agent without going through Aegis.

Servers requiring credentials are commented out. Uncomment as you add the
matching values to your .env file.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

from fastmcp.client.transports import StdioTransport
from pydantic_ai.mcp import MCPToolset

from aegis.wrapper import make_process_tool_call

_REPO_ROOT = Path(__file__).parent.parent

# Directory the filesystem server is allowed to touch. Keep it a sandbox.
SANDBOX_DIR = os.path.expanduser("~/aegis-sandbox")

# --- Zero-credential servers (work immediately) ----------------------------

filesystem = MCPToolset(
    StdioTransport(
        "npx",
        ["-y", "@modelcontextprotocol/server-filesystem", SANDBOX_DIR],
    ),
    process_tool_call=make_process_tool_call("filesystem"),
)

# @modelcontextprotocol/server-fetch was removed from npm; the canonical
# replacement is the Python package mcp-server-fetch, run via uvx.
# uvx needs ~2-3s to start; raise init_timeout above the default so the
# MCP initialize handshake has headroom after the process spawns.
fetch = MCPToolset(
    StdioTransport("uvx", ["mcp-server-fetch"]),
    process_tool_call=make_process_tool_call("fetch"),
    init_timeout=30,
)

# Local demo server — exists so fingerprinting drift detection can be
# demonstrated without touching the real servers. Edit tools/demo_server.py
# to see "drift" status on the next run.
demo = MCPToolset(
    StdioTransport(sys.executable, [str(_REPO_ROOT / "tools" / "demo_server.py")]),
    process_tool_call=make_process_tool_call("demo"),
    init_timeout=30,
)

# --- Credentialed servers (uncomment once .env is populated) ----------------

# github = MCPToolset(
#     StdioTransport("npx", ["-y", "@modelcontextprotocol/server-github"],
#                    env={"GITHUB_PERSONAL_ACCESS_TOKEN": os.environ.get("GITHUB_TOKEN", "")}),
#     process_tool_call=make_process_tool_call("github"),
# )

# postgres = MCPToolset(
#     StdioTransport("npx", ["-y", "@modelcontextprotocol/server-postgres",
#                             os.environ.get("POSTGRES_URL", "")]),
#     process_tool_call=make_process_tool_call("postgres"),
# )

# brave = MCPToolset(
#     StdioTransport("npx", ["-y", "@modelcontextprotocol/server-brave-search"],
#                    env={"BRAVE_API_KEY": os.environ.get("BRAVE_API_KEY", "")}),
#     process_tool_call=make_process_tool_call("brave"),
# )

# Active servers — keyed by the same name passed to make_process_tool_call.
# Used by agents/stack.py to fingerprint every server at startup.
# Add github / postgres / brave as you enable them.
ACTIVE_SERVERS: dict[str, MCPToolset] = {
    "filesystem": filesystem,
    "fetch": fetch,
    "demo": demo,
}
