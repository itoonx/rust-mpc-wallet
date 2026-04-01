# MPC Wallet -- Monitoring & Runbooks

Prometheus metrics, health endpoints, alerting rules, and operational runbooks for the MPC Wallet SDK.

---

## Health Endpoints

### API Gateway

| Endpoint | Auth | Description |
|----------|------|-------------|
| `GET /v1/health` | No | Basic health check. Returns `{"status":"healthy","version":"...","chains_supported":50}` |
| `GET /v1/health/live` | No | Liveness probe. Always returns 200 `{"status":"ok"}` |
| `GET /v1/health/ready` | No | Readiness probe. Returns 200 when ready, 503 when degraded. Checks NATS, Redis, Vault component status. |
| `GET /v1/metrics` | **Yes** | Prometheus text format metrics (requires authentication) |

#### Readiness Response

```json
{
  "status": "ready",
  "components": {
    "nats": "connected",
    "redis": "connected",
    "vault": "not_configured"
  }
}
```

Status values per component: `connected`, `disconnected`, `not_configured`.
Overall status is `degraded` (503) when NATS is `disconnected`.

### MPC Node

| Endpoint | Auth | Port | Description |
|----------|------|------|-------------|
| `GET /v1/health` | No | `HEALTH_PORT` (default 9090) | Returns `{"status":"ok","service":"mpc-node","version":"..."}` |
| `GET /v1/metrics` | No | `HEALTH_PORT` (default 9090) | Prometheus text format metrics |

---

## Prometheus Metrics

### Gateway (`/v1/metrics` on port 3000, requires auth)

Uses the `prometheus` crate with `TextEncoder`. All registered Prometheus metrics are exposed.

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `mpc_api_requests_total` | Counter | method, path, status | Total HTTP requests |
| `mpc_api_request_duration_seconds` | Histogram | method, path | Request latency |
| `mpc_keygen_total` | Counter | -- | Total keygen ceremonies initiated |
| `mpc_sign_total` | Counter | -- | Total signing operations |
| `mpc_broadcast_errors_total` | Counter | -- | Failed transaction broadcasts |

### MPC Node (`/v1/metrics` on HEALTH_PORT, default 9090)

| Metric | Type | Description |
|--------|------|-------------|
| `mpc_node_up` | Gauge | `1` if the MPC node is running |
| `mpc_node_party_id` | Gauge | The party ID of this node |
| `mpc_node_key_groups` | Gauge | Number of key groups stored in the encrypted key store |

### RPC Health (future)

| Metric | Type | Description |
|--------|------|-------------|
| `mpc_rpc_health` | Gauge | 1=healthy, 0=unhealthy per endpoint |
| `mpc_rpc_latency_seconds` | Histogram | RPC call latency |
| `mpc_rpc_failover_total` | Counter | Automatic failovers |

---

## Prometheus Configuration

### Kubernetes Service Discovery

```yaml
# prometheus.yml
scrape_configs:
  # Gateway metrics (requires auth token in Authorization header)
  - job_name: 'mpc-wallet-gateway'
    kubernetes_sd_configs:
      - role: pod
        namespaces:
          names: ['mpc-wallet']
    relabel_configs:
      - source_labels: [__meta_kubernetes_pod_label_app]
        action: keep
        regex: mpc-gateway
      - source_labels: [__meta_kubernetes_pod_annotation_prometheus_io_port]
        action: replace
        target_label: __address__
        regex: (.+)
        replacement: $1
    metrics_path: /v1/metrics
    scrape_interval: 15s

  # MPC Node metrics (unauthenticated on HEALTH_PORT)
  - job_name: 'mpc-wallet-nodes'
    kubernetes_sd_configs:
      - role: pod
        namespaces:
          names: ['mpc-wallet']
    relabel_configs:
      - source_labels: [__meta_kubernetes_pod_label_app]
        action: keep
        regex: mpc-node
      - source_labels: [__meta_kubernetes_pod_annotation_prometheus_io_port]
        action: replace
        target_label: __address__
        regex: (.+)
        replacement: $1
    metrics_path: /v1/metrics
    scrape_interval: 15s
```

### Helm Chart Pod Annotations

The Helm chart sets these annotations by default:

```yaml
# Gateway pods
prometheus.io/scrape: "true"
prometheus.io/port: "3000"
prometheus.io/path: /v1/metrics

# Node pods
prometheus.io/scrape: "true"
prometheus.io/port: "3000"
prometheus.io/path: /v1/metrics
```

---

## Key PromQL Queries

### Request Rate

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

### Node Key Group Count

```promql
mpc_node_key_groups
```

### Nodes Online Count

```promql
count(mpc_node_up == 1)
```

---

## Alerting Rules

```yaml
# alerts.yaml
groups:
  - name: mpc-wallet-critical
    rules:
      # MPC Node down
      - alert: MpcNodeDown
        expr: mpc_node_up == 0 or absent(mpc_node_up)
        for: 1m
        labels:
          severity: critical
        annotations:
          summary: "MPC node {{ $labels.instance }} is down"
          description: "Node has been unreachable for more than 1 minute. If threshold nodes are down, signing will fail."
          runbook_url: "#runbook-node-down"

      # Insufficient nodes for threshold signing
      - alert: MpcInsufficientNodes
        expr: count(mpc_node_up == 1) < 2
        for: 1m
        labels:
          severity: critical
        annotations:
          summary: "Fewer than 2 MPC nodes online -- signing unavailable"
          description: "At least t+1 nodes must be online for threshold signing. Current: {{ $value }}"
          runbook_url: "#runbook-node-down"

      # Gateway degraded (NATS disconnected)
      - alert: MpcGatewayDegraded
        expr: up{job="mpc-wallet-gateway"} == 0
        for: 1m
        labels:
          severity: critical
        annotations:
          summary: "MPC API Gateway is down"
          runbook_url: "#runbook-gateway-down"

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
          runbook_url: "#runbook-high-error-rate"

  - name: mpc-wallet-warning
    rules:
      # Node has no stored keys
      - alert: MpcNodeNoKeys
        expr: mpc_node_key_groups == 0
        for: 10m
        labels:
          severity: warning
        annotations:
          summary: "MPC node {{ $labels.instance }} has no key groups stored"
          description: "Node party_id={{ $labels.party_id }} reports 0 key groups. May be newly deployed or key store corrupted."

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

      # Keygen spike (possible abuse)
      - alert: MpcKeygenSpike
        expr: rate(mpc_keygen_total[5m]) > 10
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "Unusual keygen rate: {{ $value }}/s -- possible abuse"
```

---

## Grafana Dashboard

Import the following JSON as a Grafana dashboard:

```json
{
  "dashboard": {
    "title": "MPC Wallet Overview",
    "panels": [
      {
        "title": "Request Rate by Path",
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
        "title": "MPC Nodes Online",
        "type": "stat",
        "targets": [
          {"expr": "count(mpc_node_up == 1)"}
        ]
      },
      {
        "title": "Key Groups per Node",
        "type": "bargauge",
        "targets": [
          {"expr": "mpc_node_key_groups", "legendFormat": "Party {{ party_id }}"}
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

Both the gateway and MPC nodes use `tracing` with configurable output format.

### Configuration

| Variable | Values | Default | Description |
|----------|--------|---------|-------------|
| `RUST_LOG` | filter string | `mpc_wallet_api=info,tower_http=info` (gateway) / `mpc_wallet_node=info` (node) | Log level filter |
| `LOG_FORMAT` | `text`, `json` | `text` | Output format. Use `json` for production log aggregation. |

### Gateway JSON Log Fields

- `request_id` -- unique per request
- `method`, `path`, `status` -- HTTP request metadata
- `latency_ms` -- request duration
- `user_id` -- from JWT claims (if authenticated)
- Secret values are redacted by `RedactingJsonFormat` / `RedactingTextFormat`

### Log Aggregation

Ship logs to your preferred backend:

| Backend | Recommended Sidecar |
|---------|-------------------|
| ELK Stack | Filebeat or Fluentd sidecar |
| Datadog | Datadog agent with container log collection |
| CloudWatch | Fluent Bit with AWS CloudWatch output |
| Loki | Promtail sidecar (pairs well with Grafana) |

---

## Runbooks

### Runbook: Node Down {#runbook-node-down}

**Alert:** `MpcNodeDown` or `MpcInsufficientNodes`

**Impact:** If fewer than threshold+1 nodes are online, signing operations will fail.

**Steps:**

1. Check pod status:
   ```bash
   kubectl get pods -n mpc-wallet -l app=mpc-node
   kubectl describe pod mpc-node-<N> -n mpc-wallet
   ```

2. Check node logs:
   ```bash
   kubectl logs mpc-node-<N> -n mpc-wallet --tail=100
   ```

3. Verify NATS connectivity:
   ```bash
   # Check NATS server
   kubectl get pods -n mpc-wallet -l app=nats
   # Check NATS monitoring
   kubectl port-forward svc/nats 8222:8222 -n mpc-wallet
   curl http://localhost:8222/connz
   ```

4. Check key store directory:
   ```bash
   kubectl exec mpc-node-<N> -n mpc-wallet -- ls -la /data/keys
   ```

5. Verify `GATEWAY_PUBKEY` is set (SEC-025 -- node will not start without it):
   ```bash
   kubectl exec mpc-node-<N> -n mpc-wallet -- env | grep GATEWAY_PUBKEY
   ```

6. If persistent volume is corrupted, restore from backup and initiate key refresh.

### Runbook: Gateway Down {#runbook-gateway-down}

**Alert:** `MpcGatewayDegraded`

**Steps:**

1. Check gateway pod:
   ```bash
   kubectl get pods -n mpc-wallet -l app=mpc-gateway
   kubectl logs mpc-gateway-<hash> -n mpc-wallet --tail=100
   ```

2. Check readiness probe:
   ```bash
   kubectl port-forward svc/mpc-api-gateway 3000:80 -n mpc-wallet
   curl http://localhost:3000/v1/health/ready
   ```

3. If NATS is disconnected (status: `degraded`):
   - Verify NATS is running and `NATS_URL` is correct
   - Check network policies between gateway and NATS pods

4. If Redis is disconnected (when `SESSION_BACKEND=redis`):
   - Verify Redis is running and `REDIS_URL` is correct
   - Check `SESSION_ENCRYPTION_KEY` is set

5. If Vault is unreachable (when `SECRETS_BACKEND=vault`):
   - Check `VAULT_ADDR`, `VAULT_ROLE_ID`, `VAULT_SECRET_ID`
   - Verify Vault seal status

### Runbook: High Error Rate {#runbook-high-error-rate}

**Alert:** `MpcHighErrorRate`

**Steps:**

1. Identify error sources:
   ```bash
   kubectl logs mpc-gateway-<hash> -n mpc-wallet --tail=500 | grep -i error
   ```

2. Check if errors are auth-related (401/403):
   - Verify JWT_SECRET matches between gateway and token issuer
   - Check CLIENT_KEYS_FILE is up to date
   - Check revoked keys list

3. Check if errors are MPC-related (500):
   - Verify all MPC nodes are online
   - Check NATS connectivity
   - Check for rate limiting (SEC-030/031: 1 req/s per group_id)

4. Check resource limits:
   ```bash
   kubectl top pods -n mpc-wallet
   ```

### Runbook: Signing Failure

**Symptoms:** POST `/v1/wallets/{id}/sign` returns 500 or timeout.

**Steps:**

1. Verify minimum threshold nodes are online:
   ```bash
   # Check node count
   kubectl get pods -n mpc-wallet -l app=mpc-node --field-selector=status.phase=Running
   ```

2. Check NATS connectivity between all nodes:
   ```bash
   # NATS connection count should match gateway + all nodes
   curl http://localhost:8222/connz | jq '.num_connections'
   ```

3. Verify `GATEWAY_PUBKEY` is consistent across ALL nodes:
   ```bash
   for i in 0 1 2; do
     echo "Node $i:"
     kubectl exec mpc-node-$i -n mpc-wallet -- env | grep GATEWAY_PUBKEY
   done
   ```

4. Check per-group-id rate limiter (SEC-030/031):
   - If requests for the same group_id arrive faster than 1/second, they are rejected
   - Check node logs for "rate limited" messages

5. Check authorization cache:
   - Duplicate `authorization_id` values are rejected (replay protection)
   - Check node logs for "duplicate authorization" messages

### Runbook: Key Compromise Response

**Severity:** CRITICAL -- follow immediately.

1. **Freeze** the affected wallet:
   ```bash
   curl -X POST https://api.mpc-wallet.example.com/v1/wallets/{id}/freeze \
     -H "Authorization: Bearer <admin-token>"
   ```

2. **Initiate key refresh** (generates new shares, preserves group public key for GG20/CGGMP21):
   ```bash
   curl -X POST https://api.mpc-wallet.example.com/v1/wallets/{id}/refresh \
     -H "Authorization: Bearer <admin-token>"
   ```

3. **Revoke compromised credentials**:
   - Add compromised key IDs to `REVOKED_KEYS_FILE` or `POST /v1/auth/revoke-key`
   - Rotate `NODE_SIGNING_KEY` on affected node
   - Update `NODE_VERIFYING_KEYS_FILE` on gateway

4. **Review audit ledger**:
   ```bash
   # Export evidence pack for forensics
   cargo run -p mpc-wallet-cli -- audit-verify --pack-file ./evidence.json
   ```

5. **Notify security team** and file incident report.

6. If resharing is needed (change threshold or remove compromised node):
   - GG20 reshare preserves group key
   - FROST reshare creates new group key (DEC-008) -- requires address migration

### Runbook: NATS Partitioned

**Symptoms:** Some nodes can communicate but others cannot. Partial signing failures.

1. Check NATS cluster health:
   ```bash
   curl http://localhost:8222/routez   # cluster routes
   curl http://localhost:8222/subsz    # subscription count
   ```

2. Check JetStream status:
   ```bash
   curl http://localhost:8222/jsz
   ```

3. Verify network policies are not blocking NATS cluster ports (4222 client, 6222 cluster).

4. If JetStream is partitioned, messages may be delayed. Check stream lag:
   ```bash
   nats stream info MPC_CONTROL
   ```
