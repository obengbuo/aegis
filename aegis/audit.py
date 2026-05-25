"""
aegis/audit.py — the audit log: write, read, and query tool-call records.

Phase 1: append-only JSONL file at logs/audit.jsonl.
Phase 2: this module's interface stays the same, but the backend becomes
Postgres (RDS). Keep the public functions stable so the swap is painless.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Iterator

LOG_PATH = Path("logs/audit.jsonl")


def write_record(record: dict[str, Any]) -> None:
    """Append one tool-call record to the audit log."""
    LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    with LOG_PATH.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(record) + "\n")


def read_records() -> Iterator[dict[str, Any]]:
    """Yield every record in the audit log, oldest first."""
    if not LOG_PATH.exists():
        return
    with LOG_PATH.open("r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                yield json.loads(line)


def query(
    *,
    server: str | None = None,
    tool: str | None = None,
    status: str | None = None,
) -> list[dict[str, Any]]:
    """Filter audit records. All filters are optional and ANDed together.

    Example:
        query(server="filesystem", status="error")
    """
    results: list[dict[str, Any]] = []
    for rec in read_records():
        if server is not None and rec.get("server") != server:
            continue
        if tool is not None and rec.get("tool") != tool:
            continue
        if status is not None and rec.get("status") != status:
            continue
        results.append(rec)
    return results


def summary() -> dict[str, Any]:
    """Quick stats over the whole audit log — useful for a CLI dashboard."""
    total = 0
    by_status: dict[str, int] = {}
    by_server: dict[str, int] = {}
    by_tool: dict[str, int] = {}

    for rec in read_records():
        total += 1
        by_status[rec.get("status", "?")] = by_status.get(rec.get("status", "?"), 0) + 1
        by_server[rec.get("server", "?")] = by_server.get(rec.get("server", "?"), 0) + 1
        by_tool[rec.get("tool", "?")] = by_tool.get(rec.get("tool", "?"), 0) + 1

    return {
        "total_calls": total,
        "by_status": by_status,
        "by_server": by_server,
        "by_tool": by_tool,
    }


if __name__ == "__main__":
    # `python -m aegis.audit` prints a quick summary
    import pprint
    pprint.pprint(summary())
