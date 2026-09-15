"""
aegis/shipper.py — best-effort shipper of audit records to a self-hosted
control plane (aegis-controlplane), over HTTP.

THE CONTROL PLANE IS NOT A DEPENDENCY OF THE ENFORCEMENT PATH.

This is the same fail-open contract that governs the OTLP exporter in
aegis/audit.py, and the deliberate mirror image of policy evaluation's
fail-closed contract in aegis/wrapper.py. If the control plane is
unreachable, slow, misconfigured, or erroring:

  - tool calls are still evaluated,
  - decisions are still correct,
  - records still land in local JSONL (the durable record),
  - and the agent run completes normally.

Failing to centralise an audit record is an observability problem. Failing
to enforce is a security incident. Nothing here may ever couple the two.

Design consequences of that rule:

  * write_record() writes JSONL first and unchanged; only then does it hand
    the record to enqueue(), which never blocks and never raises.
  * There is no backpressure, ever. If the in-memory ship queue is full, the
    OLDEST queued record is dropped (recent activity is more useful during an
    outage) and a counter is incremented — the record is dropped from the
    ship queue only, never from JSONL.
  * All network I/O happens on a background daemon thread. The httpx client
    is imported lazily (see _build_client), only once a control plane is
    actually configured — callers that never configure one pay nothing.
  * Shutdown makes exactly one final flush attempt, bounded by a timeout, and
    is allowed to fail: unshipped records simply remain in JSONL.

Fail-open is not the same as fail-silent. Every way shipping can fail must
leave a signal, or "records are safely local" is indistinguishable from
"records are arriving". Two mechanisms carry that:

  * Failures are classified by whether retrying can fix them (see
    _PostOutcome). A 4xx is a configuration error, reported immediately and
    not retried; a 5xx or transport error is transient, retried with backoff
    and reported only once it has outlived a blip.
  * Reports are deduplicated per failure signature per outage, because a
    stderr line every few seconds is the noise that teaches operators to stop
    reading stderr.
"""

from __future__ import annotations

import sys
import threading
import time
from collections import deque
from typing import TYPE_CHECKING, Any, Literal

if TYPE_CHECKING:
    from aegis.config import AegisConfig

# The single process-global shipper. None until a control plane is configured.
# Lifecycle records (spec_loaded, proposer_*), emitted by load_spec /
# propose_spec which never receive an AegisConfig, reach the control plane
# only because write_record consults this global rather than a per-call
# parameter — the one structural difference from the OTLP exporter's per-call
# otlp_endpoint threading.
#
# WHEN this global is installed is the whole ballgame. It is installed by
# configure(), which AegisConfig.__post_init__ calls — i.e. the moment the
# operator DECLARES a destination. It used to be installed by wrap_toolset,
# which is the earliest point a TOOLSET is known, not the earliest point the
# DESTINATION is known. Those are different facts, and every record written
# between them went to JSONL only, silently — spec_loaded above all, since
# load_spec must run before a toolset can be wrapped with its spec.
_active_shipper: "_Shipper | None" = None

# Accounting for records written while no shipper was active. A SUMMARY, not
# the records: a count, a status tally (bounded by the ~12-value status
# vocabulary) and a capped run_id sample. Deliberately not a buffer of record
# bodies — the durable copy is already in JSONL, so there is no bound to pick
# and no discard policy to design. All the operator needs is to be told which
# records are only there. Drained and reported by configure(); see
# _report_missed_records for why nothing is reported when no control plane was
# ever declared.
_MISSED_RUN_ID_CAP = 8
_missed_lock = threading.Lock()
_missed_count = 0
_missed_statuses: dict[str, int] = {}
_missed_run_ids: set[str] = set()


# The outcome of one POST attempt. The distinction that matters is not
# success/failure but whether a failure can EVER succeed if repeated:
#
#   "ok"        — 2xx. Delivered.
#   "permanent" — 4xx. A configuration error: a bad key, the wrong URL, a batch
#                 over the size cap, a payload the backend can't parse. The
#                 identical request will be rejected identically forever, so
#                 retrying accomplishes nothing but hiding the problem.
#   "transient" — 5xx or a transport exception. The backend is restarting, or
#                 the network is down. This is what backoff is for.
#
# Collapsing these two into one boolean is what made a wrong API key
# indistinguishable from a working deployment: the 401 was retried forever and
# never reported, so records silently stayed local while everything looked fine.
_PostOutcome = Literal["ok", "transient", "permanent"]

# status -> what an operator should go and check. Shown verbatim in the warning,
# so each one names a specific thing to change rather than restating the code.
_PERMANENT_HINTS: dict[int, str] = {
    400: "the control plane rejected the batch as malformed — the library and "
         "control plane may be version-mismatched",
    401: "invalid or missing API key — check AegisConfig.control_plane_api_key "
         "against the control plane's own configuration",
    403: "the API key was rejected for this deployment — check it grants write "
         "access for AegisConfig.deployment_id",
    404: "no /v1/records endpoint at this URL — check AegisConfig.control_plane_url",
    413: "the batch exceeded the control plane's size cap — lower the shipper's "
         "batch_max_count, or raise the cap on the backend",
    422: "the control plane could not parse the batch payload — the library and "
         "control plane may be version-mismatched",
}


# ---------------------------------------------------------------------------
# HTTP poster — the lazy seam. The real httpx client is never imported at
# module load; only _build_client pulls it in, and only when a batch actually
# needs sending. Tests replace _build_client (or set _Shipper._client) to
# inject a fake, exactly as the OTLP tests pre-seed audit._otlp_tracer.
# ---------------------------------------------------------------------------


class _HttpxPoster:
    """Thin adapter around an httpx.Client exposing post(url, payload, headers)
    -> status_code. Isolates the shipper from the HTTP library so the whole
    network surface is one replaceable object in tests."""

    def __init__(self, client: Any) -> None:
        self._client = client

    def post(self, url: str, payload: dict[str, Any], headers: dict[str, str]) -> int:
        resp = self._client.post(url, json=payload, headers=headers)
        return resp.status_code


def _build_client(timeout: float) -> Any:
    """Lazily construct the real HTTP poster.

    httpx is imported here, not at module load, so importing aegis.shipper (as
    aegis.audit does) stays cheap and configuring a control plane is the only
    thing that pulls in the HTTP client — the same lazy contract as
    audit._get_or_create_tracer's OpenTelemetry import.
    """
    import httpx  # noqa: PLC0415 — deliberate lazy import; see docstring

    return _HttpxPoster(httpx.Client(timeout=timeout))


# ---------------------------------------------------------------------------
# _Shipper — owns the bounded queue and the background drain/POST thread.
# ---------------------------------------------------------------------------


class _Shipper:
    """Bounded, non-blocking, fail-open audit-record shipper.

    enqueue() is called from the enforcement path (via write_record) and must
    never block or raise. All network work happens on a background daemon
    thread that batches by count or age, POSTs to {url}/v1/records, and
    retries failed batches with exponential backoff without ever losing a
    record it has accepted for shipping.
    """

    def __init__(
        self,
        url: str,
        api_key: str | None = None,
        deployment_id: str | None = None,
        *,
        maxsize: int = 10_000,
        batch_max_count: int = 100,
        batch_max_age: float = 5.0,
        timeout: float = 5.0,
        initial_backoff: float = 0.5,
        max_backoff: float = 30.0,
        warn_interval: float = 30.0,
        transient_warn_after: int = 3,
        start: bool = True,
    ) -> None:
        # _base_url is retained (not just the derived POST target) so
        # configure() can report a conflicting second configuration in the
        # operator's own terms.
        self._base_url = url.rstrip("/")
        self._url = self._base_url + "/v1/records"
        self._deployment_id = deployment_id
        self._maxsize = maxsize
        self._batch_max_count = batch_max_count
        self._batch_max_age = batch_max_age
        self._timeout = timeout
        self._initial_backoff = initial_backoff
        self._max_backoff = max_backoff
        self._warn_interval = warn_interval
        # A transient failure that resolves on the next attempt is a blip, not
        # an incident; warning about it is the noise that teaches operators to
        # ignore stderr. Stay quiet until a failure has survived this many
        # consecutive attempts, then say it once.
        self._transient_warn_after = transient_warn_after

        self._headers: dict[str, str] = {"Content-Type": "application/json"}
        if api_key:
            self._headers["Authorization"] = f"Bearer {api_key}"

        # Guarded by _lock: the queue, the drop counters. _client is only ever
        # assigned by the worker thread (or a test before start()), so it needs
        # no lock.
        self._lock = threading.Lock()
        self._queue: deque[dict[str, Any]] = deque()
        self._dropped = 0          # dropped since the last SUCCESSFUL batch
        self._dropped_total = 0    # dropped over the shipper's lifetime
        self._client: Any = None
        self._last_warn = 0.0
        # Failure signatures already reported ("HTTP 401", "ConnectionError"),
        # so one outage produces one line rather than one line per retry.
        # Cleared on any successful POST, so a LATER outage is reported again.
        self._warned_failures: set[str] = set()
        self._consecutive_transient = 0

        # _wake lets enqueue() nudge the worker the instant the count threshold
        # is crossed, instead of waiting out the age timer. _stop ends the loop.
        self._wake = threading.Event()
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, name="aegis-shipper", daemon=True)
        if start:
            self._thread.start()

    # -- public, enforcement-path-facing surface ---------------------------

    def start(self) -> None:
        """Start the worker thread if it isn't already running. Idempotent."""
        if not self._thread.is_alive():
            self._thread.start()

    def enqueue(self, record: dict[str, Any]) -> None:
        """Accept a record for shipping. Non-blocking; never raises.

        On overflow the oldest queued record is dropped and counted — the ship
        queue only; JSONL already holds the durable copy. This is the whole
        no-backpressure guarantee: the enforcement path is never made to wait
        on the network.
        """
        try:
            with self._lock:
                if len(self._queue) >= self._maxsize:
                    self._queue.popleft()
                    self._dropped += 1
                    self._dropped_total += 1
                self._queue.append(record)
                count = len(self._queue)
            if count >= self._batch_max_count:
                self._wake.set()
        except Exception as exc:  # noqa: BLE001 — must never raise into enforcement
            print(f"[aegis] shipper enqueue failed (record kept in JSONL): {exc}", file=sys.stderr)

    def shutdown(self, timeout: float = 3.0) -> None:
        """Signal the worker to make one final flush attempt, then stop.

        Bounded by `timeout`: if the backend is unresponsive the worker (a
        daemon thread) is abandoned mid-call rather than allowed to hang the
        process. Any records not shipped simply remain in JSONL.
        """
        self._stop.set()
        self._wake.set()
        # ident is None until the thread has been started; joining a
        # never-started worker raises. A start=False shipper (used for
        # inspection) simply has nothing to wind down.
        if self._thread.ident is not None:
            self._thread.join(timeout=timeout)

    # -- background worker --------------------------------------------------

    def _run(self) -> None:
        """Drain-and-ship loop. Batches by count or age; retries failures with
        backoff; makes a final best-effort pass when asked to stop."""
        while True:
            self._maybe_warn_dropped()
            stopping = self._stop.is_set()
            batch = self._take_batch()

            if not batch:
                if stopping:
                    return
                # Idle: wait for a count-trigger wake or the age timeout.
                self._wake.wait(timeout=self._batch_max_age)
                self._wake.clear()
                continue

            dropped = self._snapshot_dropped()
            # During normal operation, block-retry the same batch until it
            # lands (records already popped into `batch` are never lost). On
            # shutdown, one attempt only — then abandon to JSONL.
            if self._deliver(batch, dropped, allow_backoff=not stopping):
                self._commit_dropped(dropped)
            elif stopping:
                return

    def _take_batch(self) -> list[dict[str, Any]]:
        with self._lock:
            batch: list[dict[str, Any]] = []
            while self._queue and len(batch) < self._batch_max_count:
                batch.append(self._queue.popleft())
            return batch

    def _snapshot_dropped(self) -> int:
        with self._lock:
            return self._dropped

    def _commit_dropped(self, reported: int) -> None:
        """Subtract the count we just reported on a successful batch. Drops
        that occurred while that batch was in flight remain counted and ride
        the next batch."""
        with self._lock:
            self._dropped = max(0, self._dropped - reported)

    def _deliver(self, batch: list[dict[str, Any]], dropped: int, allow_backoff: bool) -> bool:
        """POST one batch, retrying only failures that retrying can fix.

        Returns True when delivered; False when abandoned — either because
        shutdown cut the retries short, or because the control plane rejected
        the batch with a 4xx, which no number of identical retries will change.
        An abandoned batch is not lost: JSONL already holds every record.
        Never raises.
        """
        backoff = self._initial_backoff
        while True:
            outcome = self._post(batch, dropped)
            if outcome == "ok":
                return True
            if outcome == "permanent":
                # Already reported by _post; retrying would only hide it. Count
                # the abandoned records as dropped so the gap rides the next
                # SUCCESSFUL batch as dropped_since_last_batch. Without this a
                # 413 — which rejects only oversized batches, not all of them —
                # would leave a hole in the centralised view that the backend
                # had no way to know about: the same silent-gap problem this
                # classification exists to remove.
                with self._lock:
                    self._dropped += len(batch)
                    self._dropped_total += len(batch)
                return False
            if not allow_backoff:
                return False  # shutdown: single attempt, no waiting
            # Interruptible backoff. If shutdown fires mid-wait, take one final
            # shot so a transient failure right at shutdown still gets a chance.
            if self._stop.wait(timeout=backoff):
                return self._post(batch, dropped) == "ok"
            backoff = min(backoff * 2, self._max_backoff)

    def _post(self, batch: list[dict[str, Any]], dropped: int) -> _PostOutcome:
        """One POST attempt, classified. Never raises.

        Reports failures at most once per distinct signature per outage — see
        _warn_failure_once. A success clears the reported set, so a genuinely
        new outage later is reported again rather than swallowed.
        """
        try:
            client = self._get_or_create_client()
            payload = {
                "deployment_id": self._deployment_id,
                "dropped_since_last_batch": dropped,
                "records": batch,
            }
            status = client.post(self._url, payload, self._headers)
        except Exception as exc:  # noqa: BLE001 — shipping failure is never fatal
            return self._note_transient(f"{type(exc).__name__}: {exc}")

        if 200 <= status < 300:
            self._note_success()
            return "ok"

        if 400 <= status < 500:
            self._note_permanent(status)
            return "permanent"

        return self._note_transient(f"HTTP {status}")

    # -- failure classification & reporting ---------------------------------

    def _note_success(self) -> None:
        """Reset outage state so a future failure is reported as news."""
        self._consecutive_transient = 0
        self._warned_failures.clear()

    def _note_permanent(self, status: int) -> None:
        """Report a 4xx immediately: there is no point waiting to see whether
        it resolves, because it cannot."""
        self._consecutive_transient = 0
        hint = _PERMANENT_HINTS.get(status, "the control plane rejected the batch")
        self._warn_failure_once(
            f"HTTP {status}",
            [
                f"[aegis] control plane rejected a batch: HTTP {status} — {hint}.",
                "        This batch will NOT be retried; a 4xx cannot succeed as sent.",
                "        Its records remain in JSONL, which is the durable record.",
                "        Shipping continues for later batches; this is reported once.",
            ],
        )

    def _note_transient(self, signature: str) -> _PostOutcome:
        """Count a retryable failure, and report it only once it has stopped
        looking like a blip."""
        self._consecutive_transient += 1
        if self._consecutive_transient >= self._transient_warn_after:
            self._warn_failure_once(
                signature,
                [
                    f"[aegis] control plane unreachable: {signature} "
                    f"(attempt {self._consecutive_transient}).",
                    "        Still retrying with backoff — records stay queued and in",
                    "        JSONL. This is reported once per outage, not per retry.",
                ],
            )
        return "transient"

    def _warn_failure_once(self, signature: str, lines: list[str]) -> None:
        if signature in self._warned_failures:
            return
        self._warned_failures.add(signature)
        print(*lines, sep="\n", file=sys.stderr)

    def _get_or_create_client(self) -> Any:
        if self._client is None:
            self._client = _build_client(self._timeout)
        return self._client

    def _maybe_warn_dropped(self) -> None:
        """Emit a throttled stderr warning while records are being dropped, so
        an operator sees the gap even before it rides a successful batch."""
        with self._lock:
            dropped = self._dropped
            total = self._dropped_total
        if dropped <= 0:
            return
        now = time.monotonic()
        if now - self._last_warn < self._warn_interval:
            return
        self._last_warn = now
        print(
            f"[aegis] shipper ship-queue overflow: {dropped} record(s) dropped since "
            f"the last successful batch ({total} total). JSONL retains every record; "
            f"the gap will be reported to the control plane as dropped_since_last_batch.",
            file=sys.stderr,
        )


# ---------------------------------------------------------------------------
# Module-level API consumed by audit.write_record and aegis.wrapper.
# ---------------------------------------------------------------------------


def _note_missed(record: dict[str, Any]) -> None:
    """Count one record written while no shipper was active.

    Runs on the audit-write path, so like everything else here it never
    raises. Records only a summary — see the module-level notes.
    """
    global _missed_count
    try:
        with _missed_lock:
            _missed_count += 1
            status = str(record.get("status", "?"))
            _missed_statuses[status] = _missed_statuses.get(status, 0) + 1
            run_id = record.get("run_id")
            # Capped: a long-lived process that never configures a control
            # plane must not accumulate run ids forever. A sample is enough to
            # point an operator at the right run.
            if run_id is not None and len(_missed_run_ids) < _MISSED_RUN_ID_CAP:
                _missed_run_ids.add(str(run_id))
    except Exception as exc:  # noqa: BLE001 — bookkeeping never raises into a write
        print(f"[aegis] shipper missed-record accounting failed: {exc}", file=sys.stderr)


def _report_missed_records(url: str) -> None:
    """Report, once, that records were written before this control plane was
    configured — then drain the counters.

    Called ONLY from configure(). That is the design, not an implementation
    detail: if no control plane is ever declared, nothing was ever expected to
    ship, and warning would be noise. A warning that fires when nobody asked
    for shipping teaches operators to ignore it, and then it is noise when it
    fires for real. So records are counted unconditionally and reported only
    once a destination exists to have missed them.
    """
    global _missed_count
    with _missed_lock:
        count = _missed_count
        statuses = dict(_missed_statuses)
        run_ids = sorted(_missed_run_ids)
        _missed_count = 0
        _missed_statuses.clear()
        _missed_run_ids.clear()

    if count == 0:
        return

    lines = [
        f"[aegis] control plane ({url}) configured AFTER {count} audit record(s) were",
        "        already written. Those records are in JSONL only and will NOT be",
        "        shipped:",
    ]
    lines += [f"          {status} x{n}" for status, n in sorted(statuses.items())]
    if run_ids:
        lines.append(f"        affected run_id(s): {', '.join(run_ids)}")
    lines += [
        "        Construct AegisConfig before load_spec/propose_spec so the run's",
        "        opening record ships. The control plane will fall back to",
        "        spec_hash+timestamp inference for these runs.",
    ]
    print(*lines, sep="\n", file=sys.stderr)


def _warn_on_conflict(active: "_Shipper", url: str, deployment_id: str | None) -> None:
    """Report a second AegisConfig naming a different control plane.

    Aegis installs ONE process-global shipper, so the first configuration wins.
    That was always true, but was previously silent, and activating at
    AegisConfig construction makes it reachable by simply building two configs.
    Removing one silent failure must not introduce another.
    """
    if url.rstrip("/") == active._base_url and deployment_id == active._deployment_id:
        return
    print(
        f"[aegis] control plane already configured for {active._base_url} "
        f"(deployment_id={active._deployment_id}); ignoring a second",
        f"        AegisConfig naming {url.rstrip('/')} (deployment_id={deployment_id}).",
        "        The FIRST configuration wins for this process — every record ships",
        f"        to {active._base_url}. Build one AegisConfig per process, or call",
        "        aegis.shipper.shutdown() before reconfiguring.",
        sep="\n",
        file=sys.stderr,
    )


def configure(config: "AegisConfig") -> "_Shipper | None":
    """Install the process-global shipper from an AegisConfig, if (and only if)
    control_plane_url is set. Idempotent: a shipper already active for this
    process is reused, never duplicated — so multiple wrap_toolset() calls
    don't spawn multiple threads.

    Called from AegisConfig.__post_init__, so activation happens when the
    operator declares a destination — the earliest moment the destination is
    known. wrap_toolset also calls it, harmlessly, to cover a config reused
    after an explicit shutdown().

    Returns the active shipper, or None when no control plane is configured.
    """
    global _active_shipper
    url = getattr(config, "control_plane_url", None)
    if not url:
        return None

    deployment_id = getattr(config, "deployment_id", None)
    if _active_shipper is not None:
        _warn_on_conflict(_active_shipper, url, deployment_id)
        return _active_shipper

    # Before accepting records, say what this window already swallowed.
    _report_missed_records(url)

    _active_shipper = _Shipper(
        url=url,
        api_key=getattr(config, "control_plane_api_key", None),
        deployment_id=deployment_id,
    )
    return _active_shipper


def enqueue(record: dict[str, Any]) -> None:
    """Hand a record to the active shipper. Never blocks, never raises.

    With no control plane configured this is near-free, but no longer a pure
    no-op: the record is counted, so that if a control plane is configured
    later, configure() can name what the window swallowed. JSONL holds the
    durable copy either way.
    """
    sh = _active_shipper
    if sh is None:
        _note_missed(record)
        return
    sh.enqueue(record)


def shutdown(timeout: float = 3.0) -> None:
    """Shut down and clear the process-global shipper, if any.

    Missed-record counters are deliberately NOT cleared: records written after
    this call, with no shipper active, are genuinely unshipped, and a
    subsequent configure() should say so.
    """
    global _active_shipper
    sh = _active_shipper
    if sh is not None:
        sh.shutdown(timeout=timeout)
    _active_shipper = None
