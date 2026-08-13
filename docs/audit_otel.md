# OpenTelemetry AuditSink

Doberman can forward its redacted decision records to any **OTLP/HTTP-compatible collector** — Grafana Alloy, the OpenTelemetry Collector, Honeycomb, Datadog Agent, and so on.

## How it works

Each time Doberman reaches a PASS / AUTH / BLOCK verdict, it calls every registered `AuditSink`. The OTel sink enqueues the record (non-blocking, O(1)) and a background daemon thread serialises and POSTs it as an OTLP `LogRecord` to your collector.

The sink is **best-effort**. Records lost on queue overflow or process exit are lost — this is a bridge to your own log pipeline, not a delivery guarantee.

## Setup

### 1. Configure the collector endpoint

Create `.doberman/audit_otel.yaml` beside your repo's existing policy files:

```yaml
# .doberman/audit_otel.yaml

# Required: OTLP/HTTP base URL of your collector.
# The sink will POST to <endpoint>/v1/logs.
endpoint: https://otel-collector.internal:4318

# Optional: name of the environment variable whose value becomes the
# Authorization header.  The token is read at send time and is never
# stored or logged.
auth_env: OTEL_AUTH_TOKEN

# Optional: per-request HTTP timeout in seconds (default: 5).
timeout_s: 5

# Optional: maximum records to buffer in memory before dropping-oldest
# (default: 1000).  Records are dropped when the worker is slower than
# the decision rate.
queue_max: 1000
```

> **Security note:** Never put the token value in the YAML. Store it in the environment variable named by `auth_env`.

### 2. Set the auth token (if required)

```bash
export OTEL_AUTH_TOKEN="Bearer <your-token>"
```

### 3. Run Doberman normally

No CLI flag needed. The sink activates automatically when `.doberman/audit_otel.yaml` is present. To disable it, remove or rename the file — no config means zero network I/O.

---

## Collector example — OpenTelemetry Collector

A minimal `otel-collector-config.yaml` that accepts Doberman's records and forwards them to stdout (replace the exporter for production):

```yaml
receivers:
  otlp:
    protocols:
      http:
        endpoint: 0.0.0.0:4318

processors:
  batch:

exporters:
  logging:
    loglevel: debug

service:
  pipelines:
    logs:
      receivers: [otlp]
      processors: [batch]
      exporters: [logging]
```

Run it:

```bash
docker run --rm -p 4318:4318 \
  -v $(pwd)/otel-collector-config.yaml:/etc/otelcol/config.yaml \
  otel/opentelemetry-collector:latest
```

Doberman will start shipping records immediately.

---

## What gets exported

Each record contains only the **allowlisted fields** — the same fields already redacted by Doberman upstream:

| Field | Example value |
|---|---|
| `timestamp` | `2026-08-14T10:00:00Z` |
| `verdict` | `BLOCK` |
| `tool` | `run_terminal_cmd` |
| `reason_codes` | `["destructive_command"]` |
| `explanation` | `Recursive force-delete of a home/root target.` |
| `session_id` | `sess-abc123` |

The sink adds **no fields of its own** — no raw payloads, no prompt text, no secrets.

---

## Honest scope

- **Best-effort delivery.** If the queue fills (worker lagging) the oldest record is silently dropped.
- **No retry.** A failed POST is logged at `DEBUG` and discarded.
- **Process exit.** In-queue records not yet POSTed are lost.
- **Not a substitute** for a proper log pipeline with durability guarantees.
