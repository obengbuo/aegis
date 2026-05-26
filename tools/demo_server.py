"""
tools/demo_server.py — local demo MCP server for Aegis fingerprinting tests.

This server exists to demonstrate supply-chain drift detection:
  1. Run agents/stack.py once  -> fingerprint saved as baseline (status: new)
  2. Run again unchanged       -> hash matches (status: unchanged)
  3. Edit a tool description   -> Aegis reports drift and shows which tool changed

To demonstrate drift: change a tool description string below and re-run.
"""

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("aegis-demo")


@mcp.tool()
def ping(message: str) -> str:
    """Confirm the server is reachable."""
    return f"pong: {message}"


@mcp.tool()
def add(a: int, b: int) -> int:
    """Add two integers and return the result."""
    return a + b


if __name__ == "__main__":
    mcp.run()
