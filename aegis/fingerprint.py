"""
aegis/fingerprint.py — MCP server fingerprinting for supply-chain integrity.

The canonical MCP supply-chain attack: a community MCP server you trust gets
updated to silently add a tool that exfiltrates data, or changes a tool's
description to smuggle a prompt injection. Fingerprinting catches this by
hashing each server's advertised tool surface and alerting when it changes
between sessions.

Phase 1: hash the tool list + tool descriptions, store to a JSON file,
compare on each run, flag drift.

Phase 2: real-time alerting, severity scoring, integration with the policy
engine (a drifted server can be auto-quarantined).
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

FINGERPRINT_PATH = Path("logs/fingerprints.json")

# In-memory record of servers seen this session (populated by the wrapper).
_seen_this_session: set[str] = set()


def note_server_seen(server_name: str) -> None:
    """Called by the wrapper each time a server is used. Cheap, idempotent."""
    _seen_this_session.add(server_name)


def fingerprint_tools(tools: list[Any]) -> dict[str, Any]:
    """Produce a stable fingerprint of an MCP server's advertised tools.

    Args:
        tools: the tool objects returned by an MCP server's list_tools().
               Each is expected to have `.name` and `.description`.

    Returns:
        A dict with the per-tool hashes and an overall surface hash.
    """
    tool_hashes: dict[str, str] = {}
    for tool in sorted(tools, key=lambda t: getattr(t, "name", "")):
        name = getattr(tool, "name", "")
        description = getattr(tool, "description", "") or ""
        # input schema also matters — a changed schema can smuggle behavior
        schema = json.dumps(
            getattr(tool, "inputSchema", {}) or {}, sort_keys=True
        )
        material = f"{name}\n{description}\n{schema}".encode("utf-8")
        tool_hashes[name] = hashlib.sha256(material).hexdigest()

    surface_material = json.dumps(tool_hashes, sort_keys=True).encode("utf-8")
    surface_hash = hashlib.sha256(surface_material).hexdigest()

    return {
        "tool_count": len(tool_hashes),
        "tool_hashes": tool_hashes,
        "surface_hash": surface_hash,
        "captured_at": datetime.now(timezone.utc).isoformat(),
    }


def _load_store() -> dict[str, Any]:
    if FINGERPRINT_PATH.exists():
        return json.loads(FINGERPRINT_PATH.read_text(encoding="utf-8"))
    return {}


def _save_store(store: dict[str, Any]) -> None:
    FINGERPRINT_PATH.parent.mkdir(parents=True, exist_ok=True)
    FINGERPRINT_PATH.write_text(json.dumps(store, indent=2), encoding="utf-8")


def check_server(server_name: str, tools: list[Any]) -> dict[str, Any]:
    """Compare a server's current fingerprint against the stored baseline.

    Returns a dict describing the result:
        {"status": "new"}            first time we've seen this server
        {"status": "unchanged"}      surface matches the baseline
        {"status": "drift", ...}     surface changed — possible supply-chain attack
    """
    current = fingerprint_tools(tools)
    store = _load_store()
    previous = store.get(server_name)

    if previous is None:
        store[server_name] = current
        _save_store(store)
        return {"status": "new", "fingerprint": current}

    if previous["surface_hash"] == current["surface_hash"]:
        return {"status": "unchanged", "fingerprint": current}

    # Drift detected — figure out exactly what changed.
    added = set(current["tool_hashes"]) - set(previous["tool_hashes"])
    removed = set(previous["tool_hashes"]) - set(current["tool_hashes"])
    modified = {
        name
        for name in set(current["tool_hashes"]) & set(previous["tool_hashes"])
        if current["tool_hashes"][name] != previous["tool_hashes"][name]
    }

    # Update the baseline to the new state (Phase 2: require human approval).
    store[server_name] = current
    _save_store(store)

    return {
        "status": "drift",
        "server": server_name,
        "tools_added": sorted(added),
        "tools_removed": sorted(removed),
        "tools_modified": sorted(modified),
        "previous_hash": previous["surface_hash"],
        "current_hash": current["surface_hash"],
    }
