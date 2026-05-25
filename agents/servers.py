"""
agents/servers.py — definitions of the MCP servers used by the test stack.

Every server is wired with Aegis's process_tool_call hook. That is the rule:
no MCP server enters an agent without going through Aegis.

Servers requiring credentials are commented out. Uncomment as you add the
matching values to your .env file.
"""

from __future__ import annotations

import os

from pydantic_ai.mcp import MCPServerStdio

from aegis.wrapper import process_tool_call

# Directory the filesystem server is allowed to touch. Keep it a sandbox.
SANDBOX_DIR = os.path.expanduser("~/aegis-sandbox")

# --- Zero-credential servers (work immediately) ----------------------------

filesystem = MCPServerStdio(
    "npx",
    args=[
        "-y",
        "@modelcontextprotocol/server-filesystem",
        SANDBOX_DIR,
    ],
    process_tool_call=process_tool_call,
)

fetch = MCPServerStdio(
    "npx",
    args=["-y", "@modelcontextprotocol/server-fetch"],
    process_tool_call=process_tool_call,
)

# --- Credentialed servers (uncomment once .env is populated) ----------------

# github = MCPServerStdio(
#     "npx",
#     args=["-y", "@modelcontextprotocol/server-github"],
#     env={"GITHUB_PERSONAL_ACCESS_TOKEN": os.environ.get("GITHUB_TOKEN", "")},
#     process_tool_call=process_tool_call,
# )

# postgres = MCPServerStdio(
#     "npx",
#     args=[
#         "-y",
#         "@modelcontextprotocol/server-postgres",
#         os.environ.get("POSTGRES_URL", ""),
#     ],
#     process_tool_call=process_tool_call,
# )

# brave = MCPServerStdio(
#     "npx",
#     args=["-y", "@modelcontextprotocol/server-brave-search"],
#     env={"BRAVE_API_KEY": os.environ.get("BRAVE_API_KEY", "")},
#     process_tool_call=process_tool_call,
# )

# The servers currently active. Add github / postgres / brave as you enable them.
ACTIVE_SERVERS = [filesystem, fetch]
