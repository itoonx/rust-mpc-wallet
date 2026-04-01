# MPC Wallet SDK -- Deployment Guide

Production deployment guide for the MPC Wallet SDK. Covers Docker Compose, Helm/Kubernetes, Terraform multi-cloud, and operational checklists.

---

## Architecture Overview

```
                    +-----------------+
                    |   API Gateway   | :3000 (REST API, orchestrator)
                    |  (ZERO shares)  |
                    +--------+--------+
                             |
                    NATS (control channels)
                             |
          +------------------+------------------+
          |                  |                  |
  +-------+-------+ +-------+-------+ +-------+-------+
  |  MPC Node 1   | |  MPC Node 2   | |  MPC Node 3   |
  |  (share 1)    | |  (share 2)    | |  (share 3)    |
  |  :9090 health | |  :9090 health | |  :9090 health |
  +---------------+ +---------------+ +---------------+
```

The gateway holds ZERO key shares (DEC-015). Each MPC node holds exactly 1 share, stored encrypted with AES-256-GCM + Argon2id. Nodes communicate via NATS with Ed25519 signed envelopes. The gateway creates `SignAuthorization` proofs that nodes independently verify before participating in signing (DEC-012).

---

## Quick Start: Docker Compose (Local Development)

```bash
# 1. Clone and build
git clone https://github.com/example/mpc-wallet.git
cd mpc-wallet

# 2. Set environment variables
export JWT_SECRET="your-secret-at-least-32-bytes-long"

# 3. Start the cluster (gateway + 3 nodes + NATS)
docker compose -f infra/docker/docker-compose.yml up -d

# 4. Verify
curl http://localhost:3000/v1/health
# {"success":true,"data":{"status":"healthy","version":"0.1.0","chains_supported":50}}

curl http://localhost:3000/v1/chains | jq '.data.total'
# 50
```

### Local E2E Testing (CI-equivalent)

Runs Vault (dev mode) + Redis + NATS + test runner:

```bash
docker compose -f infra/local/docker-compose.test.yml up --build --abort-on-container-exit
```

---

## Quick Start: Helm Chart

```bash
helm install mpc-wallet ./infra/helm/mpc-wallet \
  --namespace mpc-wallet --create-namespace \
  --set secrets.jwtSecret=<jwt-secret-32-bytes-min> \
  --set secrets.keyStorePassword=<encryption-password> \
  --set secrets.gatewaySigningKey=<ed25519-hex-seed-32-bytes> \
  --set secrets.nodeSigningKeys=<comma-separated-hex-seeds> \
  --set configmap.gatewayPubkey=<ed25519-pubkey-hex-32-bytes>
```

### Helm Values Reference

Key values in `infra/helm/mpc-wallet/values.yaml`:

| Value | Description | Default |
|-------|-------------|---------|
| `gateway.replicas` | Gateway replica count | `1` |
| `gateway.port` | Gateway HTTP port | `3000` |
| `gateway.env.NETWORK` | Chain network | `mainnet` |
| `gateway.env.SESSION_BACKEND` | Session storage type | `memory` |
| `gateway.env.LOG_FORMAT` | Log output format | `json` |
| `node.replicas` | MPC node count (threshold participants) | `3` |
| `node.persistence.enabled` | Enable PVC for key store | `true` |
| `node.persistence.size` | PVC size | `10Gi` |
| `nats.enabled` | Deploy NATS alongside | `true` |
| `nats.jetstream` | Enable JetStream | `true` |
| `redis.enabled` | Deploy Redis alongside | `false` |
| `ingress.enabled` | Enable external ingress | `false` |
| `secrets.jwtSecret` | JWT HMAC secret (REQUIRED) | placeholder |
| `secrets.keyStorePassword` | Key store encryption password (REQUIRED) | placeholder |
| `secrets.gatewaySigningKey` | Gateway Ed25519 signing key hex (REQUIRED) | placeholder |
| `secrets.nodeSigningKeys` | Per-node signing keys, comma-separated hex | `""` |
| `secrets.sessionEncryptionKey` | Session encryption key for Redis | `""` |
| `configmap.gatewayPubkey` | Gateway Ed25519 public key hex (REQUIRED) | `""` |

---

## Kubernetes (Manual Manifests)

### 1. Create namespace and secrets

```bash
kubectl create namespace mpc-wallet

# Use sealed-secrets or external-secrets in production
kubectl create secret generic mpc-secrets \
  --namespace mpc-wallet \
  --from-literal=jwt_secret="$JWT_SECRET" \
  --from-literal=encryption_password="$ENCRYPTION_PASSWORD" \
  --from-literal=gateway_signing_key="$GATEWAY_SIGNING_KEY"
```

### 2. Apply manifests

```bash
kubectl apply -f infra/k8s/configmap.yaml
kubectl apply -f infra/k8s/secrets.yaml
kubectl apply -f infra/k8s/deployment.yaml
kubectl apply -f infra/k8s/service.yaml
kubectl apply -f infra/k8s/ingress.yaml
```

### 3. Verify

```bash
kubectl get pods -n mpc-wallet -w
kubectl port-forward svc/mpc-api-gateway 3000:80 -n mpc-wallet &
curl http://localhost:3000/v1/health
```

### 4. Deploy NATS (if not using managed NATS)

```bash
helm repo add nats https://nats-io.github.io/k8s/helm/charts/
helm install nats nats/nats \
  --namespace mpc-wallet \
  --set jetstream.enabled=true \
  --set jetstream.memStorage.size=256Mi \
  --set jetstream.fileStorage.size=1Gi
```

---

## Terraform (Multi-Cloud)

Deploy MPC nodes across separate cloud providers for maximum security.

```bash
cd infra/terraform

# Copy and customize variables
cp terraform.tfvars.example terraform.tfvars

# AWS only
terraform init
terraform plan -var="enable_aws=true"
terraform apply

# Multi-cloud (AWS + GCP)
terraform apply \
  -var="enable_aws=true" \
  -var="enable_gcp=true" \
  -var="gcp_project_id=my-project"

# All three clouds
terraform apply \
  -var="enable_aws=true" \
  -var="enable_gcp=true" \
  -var="enable_azure=true"
```

Then apply K8s manifests to provisioned clusters:

```bash
# AWS
aws eks update-kubeconfig --name mpc-wallet-production
kubectl apply -f infra/k8s/

# GCP
gcloud container clusters get-credentials mpc-wallet-production
kubectl apply -f infra/k8s/
```

---

## Environment Variables

### API Gateway (`services/api-gateway`)

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `PORT` | No | `3000` | HTTP listen port |
| `JWT_SECRET` | **Yes** | -- | HMAC secret for JWT validation. Minimum 32 bytes. Loaded from Vault if `SECRETS_BACKEND=vault`. |
| `JWT_ISSUER` | No | `mpc-wallet` | Expected `iss` claim in JWTs |
| `JWT_AUDIENCE` | No | `mpc-wallet-api` | Expected `aud` claim in JWTs |
| `NETWORK` | No | `testnet` | Chain network: `mainnet`, `testnet`, `devnet` |
| `RATE_LIMIT_RPS` | No | `100` | Max requests per second per IP. Must be > 0. |
| `CORS_ALLOWED_ORIGINS` | No | `""` (block all) | Comma-separated allowed origins. Wildcard `*` forbidden on mainnet. |
| `SERVER_SIGNING_KEY` | **Yes (mainnet)** | auto-generated | Ed25519 signing key (hex-encoded 32-byte seed). Required on mainnet. |
| `CLIENT_KEYS_FILE` | **Yes (mainnet)** | -- | Path to JSON file of trusted client public keys. Required on mainnet. |
| `REVOKED_KEYS_FILE` | No | -- | Path to JSON file of revoked key IDs |
| `NODE_VERIFYING_KEYS_FILE` | No | -- | Path to JSON file of MPC node Ed25519 public keys (required for keygen/sign) |
| `SESSION_TTL` | No | `3600` | Session TTL in seconds. Minimum 60. |
| `MTLS_SERVICES_FILE` | No | -- | Path to JSON file of mTLS service registry entries |
| `SESSION_BACKEND` | No | `memory` | Session/cache backend: `memory` or `redis` |
| `REDIS_URL` | If Redis | -- | Redis connection URL (`redis://` or `rediss://` for TLS). Required when `SESSION_BACKEND=redis`. |
| `SESSION_ENCRYPTION_KEY` | If Redis | -- | Hex-encoded 32-byte key for ChaCha20-Poly1305 session encryption. Required when `SESSION_BACKEND=redis`. |
| `SECRETS_BACKEND` | No | `env` | Secrets source: `env` or `vault` |
| `NATS_URL` | No | -- | NATS server URL. If not set, MPC keygen/sign operations will fail. |
| `RUST_LOG` | No | `mpc_wallet_api=info,tower_http=info` | Log level filter |
| `LOG_FORMAT` | No | text | Set to `json` for structured JSON log output |

#### Vault Configuration (when `SECRETS_BACKEND=vault`)

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `VAULT_ADDR` | **Yes** | -- | Vault server URL (e.g., `https://vault.internal:8200`) |
| `VAULT_TOKEN` | One of * | -- | Vault token (dev/test) |
| `VAULT_ROLE_ID` | One of * | -- | AppRole role ID (production) |
| `VAULT_SECRET_ID` | One of * | -- | AppRole secret ID (production) |
| `VAULT_MOUNT` | No | `secret` | KV v2 mount path |
| `VAULT_SECRETS_PATH` | No | `mpc-wallet/gateway` | Path within mount |
| `VAULT_REFRESH_INTERVAL` | No | `300` | Secret refresh interval in seconds |

*Either `VAULT_TOKEN` or (`VAULT_ROLE_ID` + `VAULT_SECRET_ID`) must be set.

#### Vault Secrets Keys

When using Vault, the following keys are read from the KV v2 secret:

- `jwt_secret` -- overrides `JWT_SECRET` env var
- `server_signing_key` -- overrides `SERVER_SIGNING_KEY` env var
- `session_encryption_key` -- overrides `SESSION_ENCRYPTION_KEY` env var
- `redis_url` -- overrides `REDIS_URL` env var

### MPC Node (`services/mpc-node`)

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `PARTY_ID` | **Yes** | -- | This node's party ID (1-indexed, must be >= 1) |
| `NATS_URL` | No | `nats://127.0.0.1:4222` | NATS server URL |
| `KEY_STORE_DIR` | No | `/data/keys` | Directory for encrypted key shares. Must exist before startup. |
| `KEY_STORE_PASSWORD` | **Yes** | -- | Password for AES-256-GCM + Argon2id key store encryption. Wrapped in `Zeroizing` (SEC-028). |
| `NODE_SIGNING_KEY` | **Yes** | -- | Hex-encoded 32-byte Ed25519 signing key for signed envelope auth (SEC-007). Wrapped in `Zeroizing` (SEC-029). |
| `GATEWAY_PUBKEY` | **Yes** | -- | Hex-encoded 32-byte Ed25519 public key of the gateway. Nodes verify `SignAuthorization` proofs with this key (DEC-012). Startup fails without it (SEC-025). |
| `HEALTH_PORT` | No | `9090` | HTTP port for health and Prometheus metrics endpoints |
| `AUTH_CACHE_MAX_ENTRIES` | No | `10000` | Max entries in the authorization replay cache. Must be > 0. |
| `RUST_LOG` | No | `mpc_wallet_node=info` | Log level filter |
| `LOG_FORMAT` | No | text | Set to `json` for structured JSON log output |

---

## Key Generation

Generate gateway Ed25519 signing keys:

```bash
# Generate a random 32-byte Ed25519 seed
openssl rand -hex 32
# Output: <gateway-signing-key-hex>

# Derive the public key (for GATEWAY_PUBKEY on nodes)
# Use the gen_gateway_keys example if available:
cargo run -p mpc-wallet-core --example gen_gateway_keys -- ./keys

# Or use the local test keys for development:
cat infra/local/.keys/gateway_signing_seed.hex    # SERVER_SIGNING_KEY
cat infra/local/.keys/gateway_signing_pubkey.hex  # GATEWAY_PUBKEY (for nodes)
```

Generate per-node signing keys:

```bash
# Generate one 32-byte Ed25519 seed per node
for i in 1 2 3; do
  echo "Node $i: $(openssl rand -hex 32)"
done
```

---

## Infrastructure Requirements

| Component | Version | Purpose | Required |
|-----------|---------|---------|----------|
| NATS | 2.10+ | MPC inter-party transport + control channels | Yes |
| Redis | 7+ | Session backend, replay cache, revocation store | Optional (default: in-memory) |
| HashiCorp Vault | 1.15+ | Secrets management (JWT secret, signing keys) | Optional (default: env vars) |
| Rust | 1.82+ | Building from source | Build-time only |
| Docker | 24+ | Container runtime | Deployment |

### NATS Configuration

- JetStream recommended for durable streams and ACLs
- Control channels: `mpc.control.keygen.*`, `mpc.control.sign.*`, `mpc.control.freeze.*`
- All messages are Ed25519 signed (SEC-026)
- Per-party subject isolation supported via JetStream ACLs (Epic E5)

### Redis Configuration (when `SESSION_BACKEND=redis`)

- Sessions encrypted with ChaCha20-Poly1305 before storage
- Replay cache uses `SET NX EX` (atomic, TTL-based)
- Revoked keys stored in Redis SET (SADD/SISMEMBER)
- `SCAN` used instead of `KEYS` (non-blocking)

---

## Production Checklist

### Gateway

- [ ] `NETWORK=mainnet` (enables strict validation)
- [ ] `JWT_SECRET` >= 32 bytes (panic on startup if shorter)
- [ ] `SERVER_SIGNING_KEY` set explicitly (auto-generation disabled on mainnet)
- [ ] `CLIENT_KEYS_FILE` configured (open enrollment disabled on mainnet)
- [ ] `CORS_ALLOWED_ORIGINS` does NOT contain `*` (blocked on mainnet)
- [ ] `NODE_VERIFYING_KEYS_FILE` configured (required for keygen/sign)
- [ ] `NATS_URL` set and NATS reachable
- [ ] `SECRETS_BACKEND=vault` with AppRole auth (not token)
- [ ] `SESSION_BACKEND=redis` for horizontal scaling
- [ ] `SESSION_ENCRYPTION_KEY` set (required for Redis backend)
- [ ] TLS termination configured (ingress or load balancer)
- [ ] `RATE_LIMIT_RPS` tuned for expected traffic
- [ ] `LOG_FORMAT=json` for structured log aggregation

### MPC Nodes

- [ ] `GATEWAY_PUBKEY` set on ALL nodes (startup fails without it, SEC-025)
- [ ] `NODE_SIGNING_KEY` unique per node, public keys registered in gateway's `NODE_VERIFYING_KEYS_FILE`
- [ ] `KEY_STORE_PASSWORD` strong, injected from Vault or cloud secrets manager
- [ ] `KEY_STORE_DIR` on persistent storage (PVC in Kubernetes)
- [ ] Nodes deployed on SEPARATE infrastructure (different availability zones, ideally different cloud providers -- Anyswap lesson)
- [ ] Per-group-id rate limiting active (1 req/s default, SEC-030/031)
- [ ] `HEALTH_PORT` accessible for liveness/readiness probes

### Network

- [ ] NATS mTLS configured (`NatsTlsConfig` in transport layer)
- [ ] No direct access between MPC nodes (all traffic through NATS)
- [ ] Gateway not exposed to public internet without auth
- [ ] Monitoring endpoints scraped by Prometheus (see `docs/MONITORING.md`)

### Audit & Compliance

- [ ] Audit ledger backed up to WORM storage (S3 Object Lock / local append-only)
- [ ] RBAC roles reviewed -- minimize Admin access
- [ ] Key refresh schedule established (periodic re-sharing)
- [ ] Disaster recovery plan tested (`crates/mpc-wallet-core/src/ops/`)
- [ ] `cargo audit` clean (check `.cargo/audit.toml` for mitigated advisories)

---

## Secrets Management (HashiCorp Vault)

### Minimal Production Gateway (no plaintext secrets)

```bash
export SECRETS_BACKEND=vault
export VAULT_ADDR=https://vault.internal:8200
export VAULT_ROLE_ID=<role-id>
export VAULT_SECRET_ID=<secret-id>
```

### Vault Secret Structure

Store at `secret/mpc-wallet/gateway`:

```json
{
  "jwt_secret": "<32+ byte HMAC secret>",
  "server_signing_key": "<hex Ed25519 seed>",
  "session_encryption_key": "<hex 32-byte ChaCha20 key>",
  "redis_url": "rediss://redis.internal:6379"
}
```

### Credential Rotation

The gateway supports automatic Vault secret refresh:

- `VAULT_REFRESH_INTERVAL` (default: 300s) controls polling interval
- `SecretRefresher` background task calls `renew_lease()` and `read_secret_version()`
- See `services/api-gateway/src/vault.rs` for implementation

For MPC nodes, inject `KEY_STORE_PASSWORD` and `NODE_SIGNING_KEY` via Vault sidecar injector or your cloud's native secrets manager (AWS Secrets Manager, GCP Secret Manager, Azure Key Vault).

---

## Upgrading

### Rolling Restart (no key migration)

Gateway is stateless (when using Redis backend) -- restart freely.

MPC nodes maintain state in `KEY_STORE_DIR`. Rolling restarts are safe as long as the persistent volume is preserved.

### Key Refresh (same group key, new shares)

- GG20/CGGMP21: additive re-sharing preserves group public key
- FROST Ed25519: DKG-based refresh preserves group public key
- FROST Secp256k1: additive re-sharing (Taproot compatible)

### Key Resharing (change threshold or add/remove nodes)

- GG20: reshare preserves group key, changes threshold (Epic H2)
- FROST: fresh DKG produces new group key (DEC-008)
