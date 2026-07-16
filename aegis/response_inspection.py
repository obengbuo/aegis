"""
aegis/response_inspection.py — deterministic scanning of tool RESPONSES.

wrapper.py already inspects tool CALLS (capability enforcement). This module
inspects what a tool CALL RETURNS, before the response reaches the agent.

Same architectural rule as aegis/policy.py: no LLM in this path. Regex and
Luhn validation only. If a pattern can't be detected deterministically, it
isn't detected in v1 — heuristic scoring is a future stream's problem.

scan_response() never modifies the response. The only choices are: return it
unchanged (clean or warn) or block it entirely (block). Redaction is a v2
concern — a binary choice keeps this deterministic and avoids the "did
Aegis silently change my agent's output" support question.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Literal

# ---------------------------------------------------------------------------
# Result types
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class PatternMatch:
    pattern_name: str  # e.g. "ssn", "credit_card", "private_key", "aws_access_key"
    match_repr: str  # repr() of a redacted preview — never the raw match
    position: int  # character offset in the scanned text


@dataclass(frozen=True)
class ScanResult:
    verdict: Literal["clean", "warn", "block"]
    patterns_matched: list[PatternMatch]


# Default per-pattern severity. Not yet configurable (that's a v2 knob,
# AegisConfig.response_inspection_pattern_verdicts) — documented here as the
# single source of truth for v1.
_DEFAULT_PATTERN_VERDICT: dict[str, Literal["warn", "block"]] = {
    "ssn": "warn",
    "credit_card": "block",
    "private_key": "block",
    "aws_access_key": "block",
    "aws_secret_key": "warn",
}


# ---------------------------------------------------------------------------
# SSN — \d{3}-\d{2}-\d{4}, skipped if clearly labeled as test/dummy data
# ---------------------------------------------------------------------------

_SSN_RE = re.compile(r"\d{3}-\d{2}-\d{4}")
_SSN_DUMMY_MARKERS = ("test", "dummy", "example")
_SSN_DUMMY_WINDOW = 20


def _scan_ssn(text: str) -> list[PatternMatch]:
    matches: list[PatternMatch] = []
    for m in _SSN_RE.finditer(text):
        raw = m.group(0)
        if raw == "000-00-0000":
            continue
        window = text[max(0, m.start() - _SSN_DUMMY_WINDOW):m.end() + _SSN_DUMMY_WINDOW].lower()
        if any(marker in window for marker in _SSN_DUMMY_MARKERS):
            continue
        redacted = f"XXX-XX-{raw[-4:]}"
        matches.append(PatternMatch(pattern_name="ssn", match_repr=repr(redacted), position=m.start()))
    return matches


# ---------------------------------------------------------------------------
# Credit card — 13-19 digit sequence (optionally space/dash separated) that
# passes Luhn validation. Luhn is what separates this from "any long digit
# run," which would false-positive constantly.
# ---------------------------------------------------------------------------

_CC_CANDIDATE_RE = re.compile(r"\d(?:[ -]?\d){12,18}")


def _luhn_valid(digits: str) -> bool:
    total = 0
    for i, ch in enumerate(reversed(digits)):
        d = int(ch)
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def _redact_credit_card(digits: str) -> str:
    last4 = digits[-4:]
    masked_len = len(digits) - 4
    groups: list[str] = []
    remaining = masked_len
    while remaining > 0:
        take = min(4, remaining)
        groups.append("X" * take)
        remaining -= take
    groups.append(last4)
    return "-".join(groups)


def _scan_credit_card(text: str) -> list[PatternMatch]:
    matches: list[PatternMatch] = []
    for m in _CC_CANDIDATE_RE.finditer(text):
        digits = re.sub(r"[ -]", "", m.group(0))
        if not (13 <= len(digits) <= 19):
            continue
        if not _luhn_valid(digits):
            continue
        redacted = _redact_credit_card(digits)
        matches.append(
            PatternMatch(pattern_name="credit_card", match_repr=repr(redacted), position=m.start())
        )
    return matches


# ---------------------------------------------------------------------------
# Private key headers — unambiguous literal format
# ---------------------------------------------------------------------------

_PRIVATE_KEY_RE = re.compile(
    r"-----BEGIN (RSA PRIVATE KEY|PRIVATE KEY|EC PRIVATE KEY|OPENSSH PRIVATE KEY)-----"
)


def _scan_private_key(text: str) -> list[PatternMatch]:
    matches: list[PatternMatch] = []
    for m in _PRIVATE_KEY_RE.finditer(text):
        redacted = f"-----BEGIN {m.group(1)}-----..."
        matches.append(
            PatternMatch(pattern_name="private_key", match_repr=repr(redacted), position=m.start())
        )
    return matches


# ---------------------------------------------------------------------------
# AWS access key — unambiguous format
# ---------------------------------------------------------------------------

_AWS_ACCESS_KEY_RE = re.compile(r"AKIA[0-9A-Z]{16}")


def _scan_aws_access_key(text: str) -> list[PatternMatch]:
    matches: list[PatternMatch] = []
    for m in _AWS_ACCESS_KEY_RE.finditer(text):
        raw = m.group(0)
        redacted = f"AKIA...{raw[-4:]}"
        matches.append(
            PatternMatch(pattern_name="aws_access_key", match_repr=repr(redacted), position=m.start())
        )
    return matches


# ---------------------------------------------------------------------------
# AWS secret key — 40-char base64-shaped string near an "aws_secret" marker.
# Higher false-positive rate than the other patterns (any 40-char base64-ish
# string qualifies once a marker is nearby); gated on the marker to keep it
# usable rather than firing on every long token in a response.
# ---------------------------------------------------------------------------

_AWS_SECRET_CANDIDATE_RE = re.compile(r"[A-Za-z0-9/+=]{40}")
_AWS_SECRET_MARKER_RE = re.compile(r"aws_secret", re.IGNORECASE)
_AWS_SECRET_MARKER_WINDOW = 40


def _scan_aws_secret_key(text: str) -> list[PatternMatch]:
    matches: list[PatternMatch] = []
    for m in _AWS_SECRET_CANDIDATE_RE.finditer(text):
        window = text[max(0, m.start() - _AWS_SECRET_MARKER_WINDOW):m.start()]
        if not _AWS_SECRET_MARKER_RE.search(window):
            continue
        raw = m.group(0)
        redacted = f"{raw[:4]}...{raw[-4:]}"
        matches.append(
            PatternMatch(pattern_name="aws_secret_key", match_repr=repr(redacted), position=m.start())
        )
    return matches


# ---------------------------------------------------------------------------
# scan_response — the public entry point
# ---------------------------------------------------------------------------


def scan_response(response: Any, context: dict[str, Any]) -> ScanResult:
    """Scan a tool response for sensitive-data patterns.

    response is whatever the MCP tool returned — usually a string or dict,
    but anything is accepted and stringified. context is
    {"server", "tool", "call_id"} for the caller's own audit correlation;
    this function does not read it — detection is content-only, never
    influenced by which server or tool produced the response.

    Deterministic and synchronous: regex and Luhn validation only, no LLM,
    no I/O. Mirrors the enforcement-path guarantee in aegis/policy.py.
    """
    text = response if isinstance(response, str) else str(response)

    matches: list[PatternMatch] = [
        *_scan_ssn(text),
        *_scan_credit_card(text),
        *_scan_private_key(text),
        *_scan_aws_access_key(text),
        *_scan_aws_secret_key(text),
    ]

    if not matches:
        return ScanResult(verdict="clean", patterns_matched=[])

    verdict: Literal["warn", "block"] = "warn"
    for match in matches:
        if _DEFAULT_PATTERN_VERDICT.get(match.pattern_name, "warn") == "block":
            verdict = "block"
            break

    return ScanResult(verdict=verdict, patterns_matched=matches)
