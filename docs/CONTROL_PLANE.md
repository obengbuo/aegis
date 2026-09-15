# Aegis — Control Plane (optional)

**Nothing in this document is required to use Aegis.** The library enforces
policy and writes its audit trail to local JSONL with no control plane
configured, exactly as described in [INTEGRATION.md](INTEGRATION.md). If you
stop reading here, everything still works.

## What it is

`logs/audit.jsonl` is the durable record, and it is enough for one agent on
one machine. It stops being enough at a fleet: the audit trail is scattered
across hosts, `grep` is the query language, and nobody can answer "show me
every denial across every agent this week" without collecting files first.

The control plane is a self-hosted backend that makes the audit trail
centrally queryable. It accepts batched audit records over HTTP, stores them,
and exposes a query API plus a read-only web UI. It does batch ingest, bearer
auth, retention with rollups, and ships as a Docker Compose stack.

It lives in a separate repository — **[aegis-controlplane](https://github.com/obengbuo/aegis-controlplane)**
— and shares no code with this library. The only coupling between the two is
an HTTP POST to `/v1/records`. You can run one without the other in either
direction.

## Getting it running

```bash
git clone https://github.com/obengbuo/aegis-controlplane.git
cd aegis-controlplane
cp .env.example .env     # set an API key, database credentials
docker compose up -d
```

The repo's own README is authoritative for ports, environment variables, and
the retention configuration. Defaults in the examples below assume the API on
`:8100` and the UI on `:8080`.

## Pointing the library at it

Three `AegisConfig` fields, all defaulting to `None`. Shipping is entirely
inert unless `control_plane_url` is set.

```python
import os
from pathlib import Path
from aegis import AegisConfig

config = AegisConfig(
    sandbox_root=Path("/var/agent-sandbox"),
    control_plane_url="http://localhost:8100",
    control_plane_api_key=os.environ["AEGIS_CP_API_KEY"],
    deployment_id="prod-us-east",
)
```

| Field | Purpose |
|---|---|
| `control_plane_url` | Base URL. Records are POSTed to `{url}/v1/records`. Unset (default) disables shipping completely. |
| `control_plane_api_key` | Bearer token, sent as `Authorization: Bearer …`. Read it from the environment; never commit it. |
| `deployment_id` | Labels this deployment's stream in the aggregated backend, so one backend can serve several deployments. |

## The control plane is not in the enforcement path

This is the design constraint the whole shipper is built around, and it is
worth stating plainly because it is what makes the control plane safe to
adopt: **if the control plane is unreachable, slow, misconfigured, or
erroring, nothing about enforcement changes.** Tool calls are still evaluated,
decisions are still correct, records still land in JSONL, and the run
completes normally.

Failing to centralise an audit record is an observability problem. Failing to
enforce is a security incident. Aegis never couples the two.

Concretely:

- `write_record` writes JSONL **first**, then hands the record to a
  non-blocking in-memory queue. All network I/O happens on a background daemon
  thread.
- There is no backpressure, ever. If the queue fills, the **oldest** queued
  record is dropped and counted — dropped from the ship queue only, never from
  JSONL — and the gap is reported to the backend as
  `dropped_since_last_batch` on the next successful batch, so a hole in the
  centralised view is visible as a hole rather than as silence.
- Shutdown makes exactly one final flush attempt, bounded by a timeout.
  Anything unshipped simply stays in JSONL.

Verified with the API key deliberately wrong against a live backend — an
`ALLOW` was honoured, a `DENY` was still enforced, and both records were
written locally:

```
ALLOW honoured, result returned: 'file contents'
DENY still enforced: arg 'path' value '/etc/shadow' not in capability spec
JSONL still durable: ['ok', 'denied']
```

## Ordering: construct `AegisConfig` first

**Construct `AegisConfig` before you call `load_spec` or `propose_spec`.**

Constructing the config is what activates the shipper — the moment you set
`control_plane_url`, shipping is on. Any audit record written before that
config exists goes to JSONL only and will never be shipped. The record most
likely to be lost is `spec_loaded`, the record that *opens* a run, because
loading a spec is the first thing an integration does.

```python
config = AegisConfig(                                       # 1. first: this
    sandbox_root=sandbox,                                   #    activates the shipper
    control_plane_url="http://localhost:8100",
    control_plane_api_key=os.environ["AEGIS_CP_API_KEY"],
    deployment_id="prod-us-east",
)
spec = propose_spec(user_request, sandbox_root=sandbox,     # 2. then the spec
                    run_id=config.run_id)
wrap_toolset(fs, "filesystem", spec=spec, config=config)    # 3. then the toolset
```

**If you get this wrong**, the run is not silently broken. The shipper reports
it on stderr at the point the control plane is finally configured, naming how
many records were missed, which statuses, and the affected `run_id`:

```
[aegis] control plane (http://localhost:8100) configured AFTER 1 audit record(s) were
        already written. Those records are in JSONL only and will NOT be
        shipped:
          spec_loaded x1
        affected run_id(s): d941c7e2-fecd-4e52-8c30-b504c67451ab
        Construct AegisConfig before load_spec/propose_spec so the run's
        opening record ships. The control plane will fall back to
        spec_hash+timestamp inference for these runs.
```

The records themselves are not lost — they are in JSONL, which is the durable
record. What is lost is their presence in the centralised view, and the run's
spec association degrades to inference (see below).

## `run_id`: linked vs. inferred spec association

Pass `run_id=config.run_id` to `load_spec` or `propose_spec`. Both accept it
as an optional keyword.

```python
spec = propose_spec(user_request, sandbox_root=sandbox, run_id=config.run_id)
# or
spec = load_spec("specs/config_reader.yaml", run_id=config.run_id)
```

This is what stamps the run's identity onto the `spec_loaded` record, letting
the control plane report the spec association as **LINKED** — an exact
`run_id` match between the record that opened the run and the tool-call
records that followed.

Omit it and the association is **INFERRED**: the backend deduces it from
`spec_hash` plus timestamp ordering within the deployment. That inference is
sound, but it is a deduction, not a link — and it is knowably ambiguous when
the same spec was loaded twice before a run, in which case the backend returns
both candidates rather than picking one.

Both loaders take a bare `run_id` string rather than the whole config, on
purpose: neither has any dependency on `AegisConfig`.

## Runnable end-to-end

`tools/demo_end_to_end.py` in this repository is the real thing — the LLM
proposer, deterministic enforcement, a genuine prompt injection in a file the
agent reads, the shipper, and the control plane, all exercised in one run. It
prints the run URL when it finishes.

```bash
export ANTHROPIC_API_KEY=sk-ant-...
export AEGIS_CP_API_KEY=...          # same key as the control plane's .env
python tools/demo_end_to_end.py
```

It reads the control-plane key from `AEGIS_CP_API_KEY`. Keep that pattern —
the key is a credential for your audit backend.

## Troubleshooting

### Records aren't arriving and nothing is being logged

**A non-2xx response from the control plane currently produces no
operator-visible output.** Only a transport-level exception (connection
refused, DNS failure, timeout) prints to stderr. A wrong or revoked API key
returns `401`, which the shipper treats as a retryable failure and retries
silently with backoff — so an unauthorised deployment looks exactly like a
working one from the library's side.

Check the key directly:

```bash
curl -s -o /dev/null -w '%{http_code}\n' -X POST http://localhost:8100/v1/records \
  -H 'Content-Type: application/json' -H "Authorization: Bearer $AEGIS_CP_API_KEY" \
  -d '{"records":[]}'
```

`401` means the key is wrong — the body is
`{"detail":"Invalid or missing API key."}`. Confirm it matches the control
plane's `.env`. Note there is no `/health` endpoint; `/v1/records` with an
empty batch is the cheapest liveness probe.

### The run's opening record is missing from the UI

You constructed `AegisConfig` after calling `load_spec` or `propose_spec`.
See [Ordering](#ordering-construct-aegisconfig-first) — check stderr for the
warning, which names the affected `run_id`.

### Spec association shows as inferred rather than linked

You didn't pass `run_id=config.run_id` to the loader. See
[run_id](#run_id-linked-vs-inferred-spec-association).

### Records are in JSONL but the centralised count is lower

Expected under sustained backend unavailability: the ship queue is bounded and
drops oldest. Look for `dropped_since_last_batch` in the backend, and for the
throttled stderr warning naming the drop count. JSONL retains every record —
it is the durable copy, and this is the designed trade rather than a bug.
