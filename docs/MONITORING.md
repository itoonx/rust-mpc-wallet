# MPC Wallet — Monitoring & Observability

Prometheus metrics, Grafana dashboards, and alert rules for production monitoring.

---

## Metrics Endpoint

```
GET /v1/metrics
```

Returns Prometheus text format. Scrape interval: 15s recommended.

---

## Available Metrics

### API Gateway

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `mpc_api_requests_total` | Counter | method, path, status | Total HTTP requests |
| `mpc_api_request_duration_seconds` | Histogram | method, path | Request latency |
| `mpc_keygen_total` | Counter | — | Total keygen ceremonies initiated |
| `mpc_sign_total` | Counter | — | Total signing operations |
| `mpc_broadcast_errors_total` | Counter | — | Failed transaction broadcasts |

### MPC Protocol (future)

| Metric | Type | Description |
|--------|------|-------------|
| `mpc_sign_duration_seconds` | Histogram | End-to-end signing latency |
| `mpc_keygen_duration_seconds` | Histogram | Keygen ceremony duration |
| `mpc_refresh_total` | Counter | Key refresh operations |
| `mpc_transport_messages_total` | Counter | Inter-party messages |
| `mpc_transport_errors_total` | Counter | Transport failures |

### RPC Health

| Metric | Type | Description |
|--------|------|-------------|
| `mpc_rpc_health` | Gauge | 1=healthy, 0=unhealthy per endpoint |
| `mpc_rpc_latency_seconds` | Histogram | RPC call latency |
| `mpc_rpc_failover_total` | Counter | Automatic failovers |

---

## Prometheus Configuration

```yaml
# prometheus.yml
scrape_configs:
  - job_name: 'mpc-wallet-api'
    kubernetes_sd_configs:
      - role: pod
        namespaces:
          names: ['mpc-wallet']
    relabel_configs:
      - source_labels: [__meta_kubernetes_pod_annotation_prometheus_io_scrape]
        action: keep
        regex: true
      - source_labels: [__meta_kubernetes_pod_annotation_prometheus_io_port]
        action: replace
        target_label: __address__
        regex: (.+)
        replacement: $1
    metrics_path: /v1/metrics
    scrape_interval: 15s
```

---

## Key PromQL Queries

### Request Rate (per second)
```promql
rate(mpc_api_requests_total[5m])
```

### P99 Latency
```promql
histogram_quantile(0.99, rate(mpc_api_request_duration_seconds_bucket[5m]))
```

### Error Rate
```promql
sum(rate(mpc_api_requests_total{status=~"5.."}[5m]))
/ sum(rate(mpc_api_requests_total[5m]))
```

### Signing Operations Rate
```promql
rate(mpc_sign_total[5m])
```

### Broadcast Error Rate
```promql
rate(mpc_broadcast_errors_total[5m])
```

---

## Alert Rules

```yaml
# alerts.yaml
groups:
  - name: mpc-wallet
    rules:
      # High error rate
      - alert: MpcHighErrorRate
        expr: |
          sum(rate(mpc_api_requests_total{status=~"5.."}[5m]))
          / sum(rate(mpc_api_requests_total[5m])) > 0.05
        for: 5m
        labels:
          severity: critical
        annotations:
          summary: "MPC API error rate > 5%"
          description: "Error rate is {{ $value | humanizePercentage }}"

      # Signing latency
      - alert: MpcHighSignLatency
        expr: |
          histogram_quantile(0.99,
            rate(mpc_api_request_duration_seconds_bucket{path="/v1/wallets/{id}/sign"}[5m])
          ) > 10
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "MPC signing P99 latency > 10s"

      # Broadcast failures
      - alert: MpcBroadcastErrors
        expr: rate(mpc_broadcast_errors_total[5m]) > 0.1
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "Transaction broadcast errors detected"

      # Node down
      - alert: MpcNodeDown
        expr: up{job="mpc-wallet-api"} == 0
        for: 1m
        labels:
          severity: critical
        annotations:
          summary: "MPC node {{ $labels.instance }} is down"

      # Keygen spike (possible abuse)
      - alert: MpcKeygenSpike
        expr: rate(mpc_keygen_total[5m]) > 10
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "Unusual keygen rate: {{ $value }}/s"
```

---

## Grafana Dashboard

Import the following JSON as a Grafana dashboard.

```json
{
  "dashboard": {
    "title": "MPC Wallet Overview",
    "panels": [
      {
        "title": "Request Rate",
        "type": "timeseries",
        "targets": [
          {"expr": "sum(rate(mpc_api_requests_total[5m])) by (path)"}
        ]
      },
      {
        "title": "P50/P95/P99 Latency",
        "type": "timeseries",
        "targets": [
          {"expr": "histogram_quantile(0.50, rate(mpc_api_request_duration_seconds_bucket[5m]))", "legendFormat": "P50"},
          {"expr": "histogram_quantile(0.95, rate(mpc_api_request_duration_seconds_bucket[5m]))", "legendFormat": "P95"},
          {"expr": "histogram_quantile(0.99, rate(mpc_api_request_duration_seconds_bucket[5m]))", "legendFormat": "P99"}
        ]
      },
      {
        "title": "Error Rate",
        "type": "stat",
        "targets": [
          {"expr": "sum(rate(mpc_api_requests_total{status=~\"5..\"}[5m])) / sum(rate(mpc_api_requests_total[5m]))"}
        ]
      },
      {
        "title": "Signing Operations",
        "type": "timeseries",
        "targets": [
          {"expr": "rate(mpc_sign_total[5m])"}
        ]
      },
      {
        "title": "Keygen Operations",
        "type": "timeseries",
        "targets": [
          {"expr": "rate(mpc_keygen_total[5m])"}
        ]
      },
      {
        "title": "Broadcast Errors",
        "type": "timeseries",
        "targets": [
          {"expr": "rate(mpc_broadcast_errors_total[5m])"}
        ]
      }
    ]
  }
}
```

---

## Structured Logging

The API gateway uses `tracing` with structured JSON output.

```bash
# Set log level
RUST_LOG=mpc_wallet_api=debug,tower_http=info cargo run -p mpc-wallet-api

# Log fields include:
# - request_id
# - method, path, status
# - latency_ms
# - user_id (from JWT)
```

### Log Aggregation

Ship logs to your preferred backend:
- **ELK Stack:** Use Filebeat or Fluentd sidecar
- **Datadog:** Use Datadog agent with container log collection
- **CloudWatch:** Use Fluent Bit with AWS for_log output
