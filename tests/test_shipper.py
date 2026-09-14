"""
tests/test_shipper.py — the control-plane audit shipper (self-hosted backend).

The one rule that governs every test here: the control plane must never
become a dependency of the enforcement path. If it is unreachable, slow,
misconfigured, or erroring, tool calls are still evaluated, decisions are
still correct, records still land in local JSONL, and the run completes.
Failing to ship a record is an observability problem; failing to enforce is
a security incident. These never couple.

No test touches a real network endpoint. A fake poster is injected at the
same lazy seam the OTLP tests use for their in-memory exporter: the real
HTTP client is built only inside shipper._build_client, and tests either
replace that factory or set _Shipper._client directly — so write_record's
ship path runs for real while never opening a socket.
"""

from __future__ import annotations

import asyncio
import copy
import json
import threading
import time
import uuid
from datetime import datetime
from pathlib import Path

import pytest
import yaml
from fastmcp.client.transports import StdioTransport
from pydantic_ai.mcp import MCPToolset

from aegis import AegisConfig, audit, load_spec, proposer, shipper, wrap_toolset
from aegis.policy import CapabilitySpec
from aegis.shipper import _Shipper


# ---------------------------------------------------------------------------
# Fixtures & helpers
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def temp_log(tmp_path, monkeypatch):
    """Redirect the audit log to a temp file for each test."""
    log = tmp_path / "audit.jsonl"
    monkeypatch.setattr(audit, "LOG_PATH", log)
    yield log


@pytest.fixture(autouse=True)
def reset_active_shipper():
    """Never let a configured global shipper (or its thread) leak between
    tests. Runs around every test regardless of what it configures."""
    shipper._active_shipper = None
    yield
    sh = shipper._active_shipper
    if sh is not None:
        sh.shutdown(timeout=1.0)
    shipper._active_shipper = None


def _wait_until(predicate, timeout: float = 3.0, interval: float = 0.01) -> bool:
    """Poll predicate until true or timeout. Returns its final value."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(interval)
    return bool(predicate())


class FakePoster:
    """Stand-in for the httpx-backed poster. Records every POST; can be told
    to fail the first N calls (to exercise retry) or to block inside post()
    (to exercise a hung backend at shutdown). Thread-safe: post() runs on the
    shipper's worker thread while the test asserts on the main thread."""

    def __init__(self, fail_first: int = 0, exc: Exception | None = None, block: threading.Event | None = None):
        self.calls: list[dict] = []
        self._lock = threading.Lock()
        self._fail_first = fail_first
        self._exc = exc or ConnectionError("simulated unreachable control plane")
        self._block = block

    def post(self, url, payload, headers):
        # Record first, so a blocked/failing call is still observable.
        with self._lock:
            self.calls.append({"url": url, "payload": copy.deepcopy(payload), "headers": headers})
            n = len(self.calls)
        if self._block is not None:
            self._block.wait(timeout=10)
        if n <= self._fail_first:
            raise self._exc
        return 200


def _allow_spec(spec_hash: str = "shiphash001") -> CapabilitySpec:
    """filesystem/read_text_file with a single 'path' arg — mirrors the
    helper in test_wrapper.py."""
    return CapabilitySpec.model_validate({
        "task": "test task",
        "deny_all_others": True,
        "servers": {"filesystem": {"tools": {"read_text_file": {"args": {"path": None}}}}},
        "spec_hash": spec_hash,
    })


class FakeCtx:
    """Minimal RunContext stand-in — the wrapper never reads from it."""


# --- offline Anthropic doubles, so proposer.py runs without a live call ------


class _FakeBlock:
    def __init__(self, name, tool_input):
        self.type = "tool_use"
        self.name = name
        self.input = tool_input


class _FakeResponse:
    def __init__(self, blocks):
        self.content = blocks


class _FakeMessages:
    def __init__(self, response):
        self._response = response

    def create(self, **kwargs):
        return self._response


class _FakeAnthropic:
    def __init__(self, response):
        self.messages = _FakeMessages(response)


def _install_fake_anthropic(monkeypatch, blocks):
    response = _FakeResponse(blocks)
    monkeypatch.setattr(proposer.anthropic, "Anthropic", lambda *a, **k: _FakeAnthropic(response))


# ---------------------------------------------------------------------------
# 1. Lazy: no control plane -> no HTTP client built, no queue, no thread.
# ---------------------------------------------------------------------------


def test_unconfigured_builds_no_client_no_queue_no_thread(monkeypatch, temp_log):
    """With no control_plane_url, configure() returns None, no global shipper
    exists, and the HTTP client factory is never reached.

    NOTE on 'verify via sys.modules': httpx is already resident (a transitive
    dependency of anthropic/pydantic-ai), so `"httpx" not in sys.modules`
    would be meaningless here. The faithful equivalent of the OTLP lazy seam
    is to prove the client *builder* is never invoked when unconfigured — a
    stronger claim than module presence.
    """
    def _boom(*a, **k):
        raise AssertionError("HTTP client must not be built when control plane is unset")

    monkeypatch.setattr(shipper, "_build_client", _boom)

    config = AegisConfig(sandbox_root=temp_log.parent)  # no control_plane_url
    assert shipper.configure(config) is None
    assert shipper._active_shipper is None

    # Writing records must not spin up a queue/thread or touch the client.
    audit.write_record({"call_id": "x", "ts": "2026-09-14T00:00:00+00:00", "status": "ok"})
    assert shipper._active_shipper is None
    assert len(temp_log.read_text().splitlines()) == 1


# ---------------------------------------------------------------------------
# 2. Configured but unreachable -> JSONL still written, no raise.
# ---------------------------------------------------------------------------


def test_write_record_with_unreachable_control_plane_still_writes_jsonl(monkeypatch, temp_log):
    fake = FakePoster(fail_first=10**9)  # every POST fails
    monkeypatch.setattr(shipper, "_build_client", lambda timeout: fake)

    config = AegisConfig(
        sandbox_root=temp_log.parent,
        control_plane_url="http://cp.invalid",
        control_plane_api_key="secret",
        deployment_id="prod-us-east",
    )
    assert shipper.configure(config) is not None

    # Must return normally, must not raise, despite the dead control plane.
    audit.write_record({"call_id": "c1", "ts": "t1", "server": "fs", "status": "ok"})

    lines = temp_log.read_text().splitlines()
    assert len(lines) == 1
    assert json.loads(lines[0])["call_id"] == "c1"


# ---------------------------------------------------------------------------
# 3. Overflow drops oldest + increments counter; JSONL keeps every record.
# ---------------------------------------------------------------------------


def test_overflow_drops_oldest_and_jsonl_keeps_all(temp_log):
    sh = _Shipper(url="http://cp", deployment_id="d", maxsize=3, start=False)
    shipper._active_shipper = sh  # torn down by reset_active_shipper

    for i in range(5):
        audit.write_record({"call_id": f"c{i}", "ts": "t", "status": "ok"})

    # JSONL is the durable record — it keeps everything.
    lines = temp_log.read_text().splitlines()
    assert len(lines) == 5
    assert [json.loads(x)["call_id"] for x in lines] == ["c0", "c1", "c2", "c3", "c4"]

    # Ship queue kept the newest 3; the two oldest were dropped and counted.
    assert sh._dropped == 2
    assert [r["call_id"] for r in sh._queue] == ["c2", "c3", "c4"]


# ---------------------------------------------------------------------------
# 4. Batching triggers on the count threshold.
# ---------------------------------------------------------------------------


def test_batch_triggers_on_count(temp_log):
    fake = FakePoster()
    # age is huge, so only the count threshold can fire.
    sh = _Shipper(url="http://cp", deployment_id="d", batch_max_count=5, batch_max_age=100.0, start=False)
    sh._client = fake
    sh.start()
    try:
        for i in range(5):
            sh.enqueue({"call_id": f"c{i}", "ts": "t", "status": "ok"})
        assert _wait_until(lambda: len(fake.calls) >= 1), "count threshold did not trigger a batch"
        payload = fake.calls[0]["payload"]
        assert len(payload["records"]) == 5
        assert payload["deployment_id"] == "d"
        assert payload["dropped_since_last_batch"] == 0
        assert fake.calls[0]["url"].endswith("/v1/records")
    finally:
        sh.shutdown(timeout=1.0)


# ---------------------------------------------------------------------------
# 5. Batching triggers on the age threshold.
# ---------------------------------------------------------------------------


def test_batch_triggers_on_age(temp_log):
    fake = FakePoster()
    # count is huge, so only the age threshold can fire.
    sh = _Shipper(url="http://cp", deployment_id="d", batch_max_count=1000, batch_max_age=0.2, start=False)
    sh._client = fake
    sh.start()
    try:
        sh.enqueue({"call_id": "a", "ts": "t", "status": "ok"})
        sh.enqueue({"call_id": "b", "ts": "t", "status": "ok"})
        assert _wait_until(lambda: len(fake.calls) >= 1), "age threshold did not trigger a batch"
        payload = fake.calls[0]["payload"]
        assert {r["call_id"] for r in payload["records"]} == {"a", "b"}
    finally:
        sh.shutdown(timeout=1.0)


# ---------------------------------------------------------------------------
# 6. A failed POST leaves the batch queued for retry.
# ---------------------------------------------------------------------------


def test_failed_post_is_retried_until_success(temp_log):
    fake = FakePoster(fail_first=2)  # calls 1 and 2 raise, call 3 succeeds
    sh = _Shipper(
        url="http://cp", deployment_id="d",
        batch_max_count=2, batch_max_age=100.0,
        initial_backoff=0.02, max_backoff=0.05, start=False,
    )
    sh._client = fake
    sh.start()
    try:
        sh.enqueue({"call_id": "r0", "ts": "t", "status": "ok"})
        sh.enqueue({"call_id": "r1", "ts": "t", "status": "ok"})
        assert _wait_until(lambda: len(fake.calls) >= 3), "failed batch was not retried to success"
        # The SAME records are redelivered on every attempt — nothing is lost.
        for call in fake.calls[:3]:
            assert {r["call_id"] for r in call["payload"]["records"]} == {"r0", "r1"}
        # After success, no further attempts of the same batch.
        time.sleep(0.1)
        assert len(fake.calls) == 3
    finally:
        sh.shutdown(timeout=1.0)


# ---------------------------------------------------------------------------
# 7. dropped_since_last_batch rides the next successful batch after overflow.
# ---------------------------------------------------------------------------


def test_dropped_count_reported_on_next_successful_batch(temp_log):
    fake = FakePoster()
    sh = _Shipper(
        url="http://cp", deployment_id="d",
        maxsize=5, batch_max_count=100, batch_max_age=0.1, start=False,
    )
    # Overflow before the worker runs: 7 into a queue of 5 => 2 dropped.
    for i in range(7):
        sh.enqueue({"call_id": f"c{i}", "ts": "t", "status": "ok"})
    assert sh._dropped == 2
    assert len(sh._queue) == 5

    sh._client = fake
    sh.start()
    try:
        # First batch (age-triggered) carries the gap marker.
        assert _wait_until(lambda: len(fake.calls) >= 1)
        first = fake.calls[0]["payload"]
        assert first["dropped_since_last_batch"] == 2
        assert len(first["records"]) == 5

        # A subsequent batch reports zero — the gap was already accounted for.
        sh.enqueue({"call_id": "c7", "ts": "t", "status": "ok"})
        assert _wait_until(lambda: len(fake.calls) >= 2)
        assert fake.calls[1]["payload"]["dropped_since_last_batch"] == 0
    finally:
        sh.shutdown(timeout=1.0)


# ---------------------------------------------------------------------------
# 8. Shutdown does not hang when the backend is unreachable/hung.
# ---------------------------------------------------------------------------


def test_shutdown_does_not_hang_on_hung_backend(temp_log):
    block = threading.Event()
    fake = FakePoster(block=block)  # post() blocks until released
    sh = _Shipper(url="http://cp", deployment_id="d", batch_max_count=1, batch_max_age=100.0, start=False)
    sh._client = fake
    sh.start()
    try:
        sh.enqueue({"call_id": "c0", "ts": "t", "status": "ok"})  # worker picks it up, blocks in post()
        assert _wait_until(lambda: len(fake.calls) >= 1), "worker never entered post()"

        start = time.monotonic()
        sh.shutdown(timeout=0.5)  # production default is 3.0; small here to keep the suite fast
        elapsed = time.monotonic() - start
        assert elapsed < 2.0, f"shutdown hung for {elapsed:.2f}s while the backend was unresponsive"
    finally:
        block.set()  # release the abandoned (daemon) worker so it can die


# ---------------------------------------------------------------------------
# 9. Lifecycle records reach the shipper carrying a real call_id and ts,
#    so the backend's derived-call_id path is a fallback, not the norm.
# ---------------------------------------------------------------------------


def _assert_identity(record: dict) -> None:
    uuid.UUID(str(record["call_id"]))                 # parses => real uuid4
    datetime.fromisoformat(str(record["ts"]))         # parses => real ISO ts


def test_spec_loaded_reaches_shipper_with_identity(tmp_path, temp_log):
    sh = _Shipper(url="http://cp", deployment_id="d", start=False)
    shipper._active_shipper = sh

    spec_file = tmp_path / "spec.yaml"
    spec_file.write_text(
        yaml.dump({
            "task": "read one file",
            "servers": {"filesystem": {"tools": {"read_text_file": {"args": {"path": None}}}}},
        }),
        encoding="utf-8",
    )
    load_spec(spec_file)

    queued = [r for r in sh._queue if r.get("status") == "spec_loaded"]
    assert len(queued) == 1
    _assert_identity(queued[0])


def test_spec_clarification_requested_reaches_shipper_with_identity(monkeypatch, temp_log):
    sh = _Shipper(url="http://cp", deployment_id="d", start=False)
    shipper._active_shipper = sh

    _install_fake_anthropic(
        monkeypatch,
        [_FakeBlock("request_clarification", {"question": "which directory?"})],
    )
    with pytest.raises(Exception):
        proposer.propose_spec("do something vague", Path("/sandbox"))

    queued = [r for r in sh._queue if r.get("status") == "spec_clarification_requested"]
    assert len(queued) == 1
    _assert_identity(queued[0])


def test_proposer_validation_failed_reaches_shipper_with_identity(monkeypatch, temp_log):
    sh = _Shipper(url="http://cp", deployment_id="d", start=False)
    shipper._active_shipper = sh

    # Valid YAML, invalid spec (no 'servers') => the schema-validation branch.
    _install_fake_anthropic(
        monkeypatch,
        [_FakeBlock("emit_capability_spec", {"spec_yaml": "task: hi\n"})],
    )
    with pytest.raises(Exception):
        proposer.propose_spec("read a file", Path("/sandbox"))

    queued = [r for r in sh._queue if r.get("status") == "proposer_validation_failed"]
    assert len(queued) == 1
    _assert_identity(queued[0])


# ---------------------------------------------------------------------------
# 10. THE NON-NEGOTIABLE ONE.
#     A governed tool call with a dead control plane completes normally, the
#     policy decision is correct, and the JSONL record is present.
# ---------------------------------------------------------------------------


def test_tool_call_completes_when_control_plane_is_dead(monkeypatch, temp_log):
    fake = FakePoster(fail_first=10**9)  # control plane is dead for the whole test
    monkeypatch.setattr(shipper, "_build_client", lambda timeout: fake)

    config = AegisConfig(
        sandbox_root=temp_log.parent,
        control_plane_url="http://cp.invalid",
        control_plane_api_key="secret",
        deployment_id="prod-us-east",
    )
    toolset = MCPToolset(StdioTransport("python", ["-c", "pass"]))
    wrap_toolset(toolset, "filesystem", spec=_allow_spec(), config=config)
    assert shipper._active_shipper is not None  # shipping activated by wrap_toolset

    async def fake_call_tool(tool_name, args):
        return "file contents"

    # The call that must not be affected by the dead control plane.
    result = asyncio.run(
        toolset.process_tool_call(FakeCtx(), fake_call_tool, "read_text_file", {"path": "/x"})
    )

    # Enforcement path is intact: ALLOW decision honored, result returned.
    assert result == "file contents"

    records = [json.loads(x) for x in temp_log.read_text().splitlines()]
    ok = [r for r in records if r["status"] == "ok"]
    assert len(ok) == 1
    assert ok[0]["server"] == "filesystem"
    assert ok[0]["tool"] == "read_text_file"


def test_denied_call_still_denies_when_control_plane_is_dead(monkeypatch, temp_log):
    """Companion to the above: a DENY decision is still enforced (call blocked)
    regardless of the control plane's state."""
    fake = FakePoster(fail_first=10**9)
    monkeypatch.setattr(shipper, "_build_client", lambda timeout: fake)

    config = AegisConfig(
        sandbox_root=temp_log.parent,
        control_plane_url="http://cp.invalid",
        deployment_id="prod-us-east",
    )
    toolset = MCPToolset(StdioTransport("python", ["-c", "pass"]))
    wrap_toolset(toolset, "filesystem", spec=_allow_spec(), config=config)

    called = threading.Event()

    async def fake_call_tool(tool_name, args):
        called.set()
        return "should never run"

    with pytest.raises(PermissionError):
        asyncio.run(
            toolset.process_tool_call(FakeCtx(), fake_call_tool, "write_file", {"path": "/x", "content": "y"})
        )
    assert not called.is_set()

    records = [json.loads(x) for x in temp_log.read_text().splitlines()]
    assert any(r["status"] == "denied" for r in records)
