# MPC Wallet — REST API Reference

Base URL: `https://api.example.com`

All responses follow the format:

**Success:**
```json
{
  "success": true,
  "data": { ... }
}
```

**Error:**
```json
{
  "success": false,
  "error": {
    "code": "ERROR_CODE",
    "message": "human-readable description"
  }
}
```

`code` is a machine-readable SCREAMING_SNAKE_CASE constant for programmatic handling.
See [Error Codes](#error-codes) for the full list.

---

## Authentication

Three methods supported — middleware checks in order, uses first match:

### 1. mTLS (Machine → Machine)
```
X-Client-Cert-CN: trading-service.internal
X-Client-Cert-Verified: SUCCESS
```
Set by TLS terminator (nginx/envoy) after verifying client certificate.
Service identity mapped via `MTLS_SERVICES_FILE`.

### 2. Session JWT (App → Server)
```
X-Session-Token: eyJhbGciOiJIUzI1NiJ9...
```
Obtained via the `/v1/auth/hello` → `/v1/auth/verify` handshake flow (see below).
HS256 signed with key-exchange derived key. Per-request, short-lived (2 min).

### 3. Bearer JWT (Human → System)
```
Authorization: Bearer eyJhbGciOiJSUzI1NiIs...
```
Supports RS256/ES256/HS256. JWT claims must include: `sub`, `exp`, `iat`, `iss`.
Optional: `roles` (array), `dept`, `cost_center`, `risk_tier`, `mfa_verified`.

**Middleware priority:** mTLS → Session JWT → Bearer JWT → 401.
If a header is **present** but invalid, auth fails immediately — no fall-through.

> Full protocol specification: `specs/AUTH_SPEC.md` (28 sections)

---

### Roles & Permissions

| Role | GET wallets | POST wallets (keygen) | POST sign | POST freeze/unfreeze | POST revoke-key |
|------|-------------|----------------------|-----------|---------------------|-----------------|
| `viewer` | yes | no | no | no | no |
| `initiator` | yes | yes | yes | no | no |
| `approver` | yes | no | yes | yes | no |
| `admin` | yes | yes | yes | yes | yes |

### Environment Variables Reference

#### Secrets (sensitive — use Vault in production)

| Variable | Required | Description |
|----------|----------|-------------|
| `JWT_SECRET` | yes* | HMAC secret for JWT validation (>= 32 bytes) |
| `SERVER_SIGNING_KEY` | no* (auto-generated) | Hex-encoded 32-byte Ed25519 secret for handshake |
| `SESSION_ENCRYPTION_KEY` | no* | Hex 32-byte KEK for Redis session encryption (ChaCha20-Poly1305) |
| `REDIS_URL` | no* | Redis connection URL (may contain password) |

*These can be loaded from Vault instead of env vars — see below.

> **Production:** Set `SECRETS_BACKEND=vault` to load all secrets from HashiCorp Vault at startup. No plaintext secrets in env vars, config files, or source control.

#### Vault Configuration

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `SECRETS_BACKEND` | no | `env` | `env` (env vars) or `vault` (HashiCorp Vault) |
| `VAULT_ADDR` | if vault | — | Vault server URL (e.g., `https://vault.internal:8200`) |
| `VAULT_TOKEN` | if vault* | — | Vault token (dev/CI) |
| `VAULT_ROLE_ID` | if vault* | — | AppRole role ID (production) |
| `VAULT_SECRET_ID` | if vault* | — | AppRole secret ID (production) |
| `VAULT_MOUNT` | no | `secret` | KV v2 mount path |
| `VAULT_SECRETS_PATH` | no | `mpc-wallet/gateway` | Secret path within mount |

*Either `VAULT_TOKEN` or (`VAULT_ROLE_ID` + `VAULT_SECRET_ID`) must be set.

#### Application Configuration (non-sensitive)

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `CLIENT_KEYS_FILE` | no | — | Path to JSON array of trusted client Ed25519 pubkeys |
| `REVOKED_KEYS_FILE` | no | — | Path to JSON array of revoked key_id strings |
| `MTLS_SERVICES_FILE` | no | — | Path to JSON array of mTLS service entries |
| `SESSION_BACKEND` | no | `memory` | Session backend: `memory` or `redis` |
| `SESSION_TTL` | no | `3600` | Session TTL in seconds |
| `NETWORK` | no | `testnet` | `mainnet`, `testnet`, or `devnet` |
| `PORT` | no | `3000` | HTTP listen port |
| `RATE_LIMIT_RPS` | no | `100` | Max requests/second per IP |
| `NATS_URL` | no | `nats://localhost:4222` | NATS server URL (gateway orchestrator mode) |
| `CORS_ALLOWED_ORIGINS` | no | (permissive) | Comma-separated origins |

### Secrets Management

The gateway has **built-in HashiCorp Vault integration** as the recommended production default. Secrets are fetched at startup — no plaintext secrets needed in the environment.

#### Development / Local

```bash
# OK for local dev only — NEVER in production
export JWT_SECRET=$(openssl rand -hex 32)
export SERVER_SIGNING_KEY=$(openssl rand -hex 32)
```

#### Production — HashiCorp Vault (recommended default)

**1. Write secrets to Vault:**
```bash
vault kv put secret/mpc-wallet/gateway \
  jwt_secret=$(openssl rand -hex 32) \
  server_signing_key=$(openssl rand -hex 32) \
  session_encryption_key=$(openssl rand -hex 32) \
  redis_url="rediss://user:pass@redis.internal:6379"
```

**2. Create AppRole for the gateway:**
```bash
# Policy
vault policy write mpc-gateway - <<EOF
path "secret/data/mpc-wallet/gateway" {
  capabilities = ["read"]
}
EOF

# AppRole
vault auth enable approle
vault write auth/approle/role/mpc-gateway \
  token_policies="mpc-gateway" \
  token_ttl=1h \
  token_max_ttl=4h \
  secret_id_ttl=720h

# Get credentials for deployment
vault read auth/approle/role/mpc-gateway/role-id
vault write -f auth/approle/role/mpc-gateway/secret-id
```

**3. Deploy with Vault:**
```bash
# Minimal production env — no secrets in plaintext
export SECRETS_BACKEND=vault
export VAULT_ADDR=https://vault.internal:8200
export VAULT_ROLE_ID=<from step 2>
export VAULT_SECRET_ID=<from step 2>
export NETWORK=mainnet
export SESSION_BACKEND=redis
```

Or with Vault token (dev/CI):
```bash
export SECRETS_BACKEND=vault
export VAULT_ADDR=http://127.0.0.1:8200
export VAULT_TOKEN=hvs.xxxxxxxxxxxxx
```

**4. Kubernetes deployment:**
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: mpc-gateway
spec:
  template:
    spec:
      containers:
        - name: gateway
          env:
            - name: SECRETS_BACKEND
              value: "vault"
            - name: VAULT_ADDR
              value: "https://vault.internal:8200"
            - name: VAULT_ROLE_ID
              valueFrom:
                secretRef:
                  name: vault-approle
                  key: role_id
            - name: VAULT_SECRET_ID
              valueFrom:
                secretRef:
                  name: vault-approle
                  key: secret_id
            - name: NETWORK
              value: "mainnet"
            - name: SESSION_BACKEND
              value: "redis"
```

**Expected Vault secret structure (KV v2):**
```
secret/data/mpc-wallet/gateway:
  jwt_secret: "a1b2c3d4...64-hex-chars"
  server_signing_key: "e5f6a7b8...64-hex-chars"
  session_encryption_key: "c9d0e1f2...64-hex-chars"
  redis_url: "rediss://user:pass@redis.internal:6379"
```

#### Alternative: Cloud-Native Secrets Managers

If you don't use Vault, inject secrets via your cloud platform's native tools:

| Platform | Approach |
|----------|----------|
| **AWS** | Secrets Manager → ECS task definition `secrets` / EKS CSI driver |
| **GCP** | Secret Manager → workload identity mount |
| **Azure** | Key Vault → managed identity injection |
| **Kubernetes** | External Secrets Operator syncing from any backend → `Secret` → env |

#### KMS/HSM for Key Material (recommended for high-security)

For the highest security level, signing keys should never leave the HSM boundary:

| Secret | KMS/HSM Integration | Status |
|--------|---------------------|--------|
| `SERVER_SIGNING_KEY` | AWS KMS `Sign` API (Ed25519) — key never exported | `KmsSigner` trait ready, stub impl |
| `SESSION_ENCRYPTION_KEY` | AWS KMS `GenerateDataKey` — envelope encryption | `KeyEncryptionProvider` trait ready |
| `JWT_SECRET` | Secrets Manager with auto-rotation | Use cloud-native rotation |

The gateway supports trait-based signer backends (`AuthSigner`):
- **`LocalSigner`** — Ed25519 key in memory (current default)
- **`KmsSigner`** — delegates signing to AWS KMS (key never leaves HSM)

```rust
// config selects backend at startup
let signer: Arc<dyn AuthSigner> = match config.signer_backend {
    SignerBackend::Local => Arc::new(LocalSigner::new(key)),
    SignerBackend::Kms   => Arc::new(KmsSigner::new(kms_key_id)),
};
```

> See `specs/REDIS_KMS_MIGRATION_SPEC.md` for full KMS/HSM migration plan.

#### What NOT to do

- **`export JWT_SECRET=...` in `.bashrc` or `.env` files** — survives in shell history, process listing (`/proc/*/environ`), and crash dumps
- **Plaintext in config files** (`api-keys.json`, `config.toml`) — readable by any process with file access, often committed to git by accident
- **Docker `--env` or `docker-compose.yml` environment** — visible in `docker inspect`, stored in image layers
- **Kubernetes `ConfigMap`** — not encrypted at rest, visible to anyone with namespace read access
- **Hardcoded in source code** — obvious but still happens

---

## Auth Endpoints (no auth required)

### POST /v1/auth/hello

Initiate key-exchange handshake. Client sends ephemeral X25519 pubkey + Ed25519 key ID.

**Request:**
```json
{
  "protocol_version": "mpc-wallet-auth-v1",
  "supported_kex": ["x25519"],
  "supported_sig": ["ed25519"],
  "client_ephemeral_pubkey": "c8a1c6b3...a4f2e1d9",
  "client_nonce": "5f3a2e9c...1b7d4a8f",
  "timestamp": 1710768000,
  "client_key_id": "a1b2c3d4e5f6g7h8"
}
```

| Field | Type | Description |
|-------|------|-------------|
| `protocol_version` | string | Must be `"mpc-wallet-auth-v1"` |
| `supported_kex` | array | ECDH algorithms, must include `"x25519"` |
| `supported_sig` | array | Signature algorithms, must include `"ed25519"` |
| `client_ephemeral_pubkey` | hex | X25519 public key (32 bytes) |
| `client_nonce` | hex | Random nonce (32 bytes) |
| `timestamp` | u64 | UNIX seconds, server enforces ±30s drift |
| `client_key_id` | hex | First 8 bytes of client's Ed25519 pubkey |

**Response (200):**
```json
{
  "success": true,
  "data": {
    "protocol_version": "mpc-wallet-auth-v1",
    "selected_kex": "x25519",
    "selected_sig": "ed25519",
    "selected_aead": "chacha20-poly1305",
    "server_ephemeral_pubkey": "3f7a1e2b...9c4d5f6a",
    "server_nonce": "8e2c4d7a...1f3b5c9e",
    "server_challenge": "1a2b3c4d...5e6f7a8b",
    "timestamp": 1710768001,
    "server_key_id": "b2c3d4e5f6g7h8i9",
    "server_signature": "ea3f1c9b...2d7e5a4f"
  }
}
```

### POST /v1/auth/verify

Complete handshake — client proves identity via Ed25519 signature over transcript hash.

**Request:**
```json
{
  "server_challenge": "1a2b3c4d...5e6f7a8b",
  "client_signature": "f3e8c1a9...2b7d4e6c",
  "client_static_pubkey": "d5e6f7a8...b1c2d3e4"
}
```

| Field | Type | Description |
|-------|------|-------------|
| `server_challenge` | hex | Echo of server's challenge from `/hello` |
| `client_signature` | hex | Ed25519 signature over transcript hash (64 bytes) |
| `client_static_pubkey` | hex | Client's long-lived Ed25519 public key (32 bytes) |

**Response (200):**
```json
{
  "success": true,
  "data": {
    "session_id": "a1b2c3d4e5f6g7h8",
    "expires_at": 1710771600,
    "session_token": "a1b2c3d4e5f6g7h8",
    "key_fingerprint": "4a5b6c7d8e9f0a1b"
  }
}
```

Use the returned `session_token` in subsequent requests via `X-Session-Token` header.
Default TTL: 3600 seconds (1 hour).

### POST /v1/auth/refresh-session

Extend session TTL before expiry.

**Request:**
```json
{
  "session_token": "a1b2c3d4e5f6g7h8"
}
```

**Response (200):**
```json
{
  "success": true,
  "data": {
    "session_id": "a1b2c3d4e5f6g7h8",
    "expires_at": 1710775200,
    "session_token": "a1b2c3d4e5f6g7h8"
  }
}
```

### GET /v1/auth/revoked-keys

List revoked key IDs (clients should check before handshake).

**Response (200):**
```json
{
  "success": true,
  "data": ["key_id_1", "key_id_2"]
}
```

### POST /v1/auth/revoke-key

Dynamically revoke a client key. The key is immediately added to the revocation set — no restart required.

**Request:**
```json
{
  "key_id": "a1b2c3d4e5f6g7h8"
}
```

**Response (200):**
```json
{
  "success": true,
  "data": {
    "key_id": "a1b2c3d4e5f6g7h8",
    "revoked": true,
    "was_new": true
  }
}
```

`was_new` is `false` if the key was already revoked.

### Auth Error Handling

All auth errors return generic `"authentication failed"` — no details leaked to prevent enumeration.

| Status | Cause |
|--------|-------|
| 400 | Malformed message |
| 401 | Invalid/expired session, signature failure, timestamp drift, revoked key |
| 429 | Rate limit exceeded (handshake: 10 req/sec per key_id) |
| 503 | Session store or pending handshakes cache full |

**Rate limiting:** Handshake endpoints (`/hello`) are rate-limited at 10 requests/second per `client_key_id` using a token-bucket algorithm.

---

## Public Endpoints (no auth required)

### GET /v1/health

Health check.

**Response:**
```json
{
  "success": true,
  "data": {
    "status": "healthy",
    "version": "0.1.0",
    "chains_supported": 50
  }
}
```

### GET /v1/metrics

Prometheus metrics export (text/plain).

**Metrics:**
- `mpc_api_requests_total{method, path, status}` — request counter
- `mpc_api_request_duration_seconds{method, path}` — latency histogram
- `mpc_keygen_total` — keygen operations
- `mpc_sign_total` — sign operations
- `mpc_broadcast_errors_total` — broadcast failures

### GET /v1/chains

List all 50 supported chains.

**Response:**
```json
{
  "success": true,
  "data": {
    "chains": [
      {"name": "ethereum", "display_name": "Ethereum", "category": "evm"},
      {"name": "bitcoin-mainnet", "display_name": "Bitcoin", "category": "utxo"},
      {"name": "solana", "display_name": "Solana", "category": "solana"}
    ],
    "total": 50
  }
}
```

---

## Protected Endpoints (auth required)

### POST /v1/wallets

Create a new MPC wallet (initiates keygen ceremony).

**Request:**
```json
{
  "label": "Treasury Wallet",
  "scheme": "gg20-ecdsa",
  "threshold": 2,
  "total_parties": 3
}
```

**Supported schemes:** `gg20-ecdsa`, `frost-ed25519`, `frost-secp256k1-tr`, `sr25519-threshold`, `stark-threshold`, `bls12-381-threshold`

**Response (201 Created):**
```json
{
  "success": true,
  "data": {
    "id": "550e8400-e29b-41d4-a716-446655440000",
    "label": "Treasury Wallet",
    "scheme": "gg20-ecdsa",
    "threshold": 2,
    "total_parties": 3,
    "created_at": 1710700000
  }
}
```

### GET /v1/wallets

List all wallets.

**Response:**
```json
{
  "success": true,
  "data": {
    "wallets": [...]
  }
}
```

### GET /v1/wallets/:id

Get wallet details with derived addresses.

**Response:**
```json
{
  "success": true,
  "data": {
    "id": "550e8400...",
    "label": "Treasury Wallet",
    "scheme": "gg20-ecdsa",
    "threshold": 2,
    "total_parties": 3,
    "created_at": 1710700000,
    "addresses": [
      {"chain": "ethereum", "address": "0x1234..."},
      {"chain": "polygon", "address": "0x1234..."}
    ]
  }
}
```

### POST /v1/wallets/:id/sign

Sign a raw message using the MPC protocol.

**Request:**
```json
{
  "message": "deadbeefcafebabe..."
}
```
`message` is hex-encoded bytes.

**Response:**
```json
{
  "success": true,
  "data": {
    "signature": {
      "r": "0x...",
      "s": "0x...",
      "recovery_id": 0
    },
    "scheme": "gg20-ecdsa"
  }
}
```

### POST /v1/wallets/:id/transactions

Build, sign, and broadcast a transaction (all-in-one).

**Request:**
```json
{
  "chain": "ethereum",
  "to": "0xRecipient...",
  "value": "1000000000000000000",
  "data": null,
  "extra": {
    "gas_limit": 21000,
    "max_fee_per_gas": "30000000000"
  }
}
```

**Response:**
```json
{
  "success": true,
  "data": {
    "tx_hash": "0xabc...",
    "chain": "ethereum",
    "status": "broadcast",
    "explorer_url": "https://etherscan.io/tx/0xabc..."
  }
}
```

### POST /v1/wallets/:id/simulate

Simulate a transaction for risk assessment (pre-sign).

**Request:**
```json
{
  "chain": "ethereum",
  "to": "0xContract...",
  "value": "0",
  "data": "0xa9059cbb..."
}
```

**Response:**
```json
{
  "success": true,
  "data": {
    "success": true,
    "gas_used": 52000,
    "risk_score": 25,
    "risk_flags": ["proxy_detected"]
  }
}
```

### POST /v1/wallets/:id/refresh

Proactive key refresh — generate new shares, preserve group public key.

**Response:**
```json
{
  "success": true,
  "data": {
    "wallet_id": "550e8400...",
    "status": "refreshed"
  }
}
```

### POST /v1/wallets/:id/freeze

Freeze a wallet — block all signing operations.

**Response:**
```json
{
  "success": true,
  "data": {
    "wallet_id": "550e8400...",
    "status": "frozen"
  }
}
```

### POST /v1/wallets/:id/unfreeze

Unfreeze a wallet — re-enable signing.

**Response:**
```json
{
  "success": true,
  "data": {
    "wallet_id": "550e8400...",
    "status": "active"
  }
}
```

### GET /v1/chains/:chain/address/:id

Derive a chain-specific address from a wallet's group public key.

**Response:**
```json
{
  "success": true,
  "data": {
    "wallet_id": "550e8400...",
    "chain": "ethereum",
    "address": "0x742d35Cc6634C0532925a3b844Bc9..."
  }
}
```

---

## Error Response Format

All errors return a structured JSON response with a machine-readable `code` and human-readable `message`:

```json
{
  "success": false,
  "error": {
    "code": "NOT_FOUND",
    "message": "wallet 550e8400 not found"
  }
}
```

### Error Codes

| Code | HTTP Status | Description |
|------|-------------|-------------|
| `AUTH_FAILED` | 401 | Authentication failed (invalid/expired token, revoked key) |
| `AUTH_RATE_LIMITED` | 429 | Rate limit exceeded |
| `PERMISSION_DENIED` | 403 | Insufficient RBAC permissions |
| `MFA_REQUIRED` | 403 | MFA verification required for this operation |
| `INVALID_INPUT` | 400 | Invalid request parameters (bad hex, wrong format) |
| `INVALID_CONFIG` | 400 | Invalid configuration (threshold > parties, etc.) |
| `NOT_FOUND` | 404 | Resource not found (wallet, session) |
| `POLICY_DENIED` | 422 | Policy check failed (velocity limit, policy not loaded) |
| `APPROVAL_REQUIRED` | 422 | Insufficient approval quorum |
| `SESSION_ERROR` | 400 | Session state error (duplicate, invalid transition) |
| `KEY_FROZEN` | 422 | Wallet is frozen — signing blocked |
| `PROTOCOL_ERROR` | 500 | MPC protocol failure |
| `CRYPTO_ERROR` | 500 | Cryptographic operation failed |
| `SERIALIZATION_ERROR` | 400 | Encoding/decoding error |
| `INTERNAL_ERROR` | 500 | Internal server error |

### Error Response Examples

**Authentication failure (401):**
```json
{
  "success": false,
  "error": {
    "code": "AUTH_FAILED",
    "message": "authentication failed"
  }
}
```

**Permission denied (403):**
```json
{
  "success": false,
  "error": {
    "code": "PERMISSION_DENIED",
    "message": "insufficient permissions"
  }
}
```

**Invalid input (400):**
```json
{
  "success": false,
  "error": {
    "code": "INVALID_INPUT",
    "message": "invalid hex message: Invalid character 'z' at position 0"
  }
}
```

**Wallet not found (404):**
```json
{
  "success": false,
  "error": {
    "code": "NOT_FOUND",
    "message": "wallet 550e8400 not found"
  }
}
```

**Wallet frozen (422):**
```json
{
  "success": false,
  "error": {
    "code": "KEY_FROZEN",
    "message": "key group frozen: wallet 550e8400 is frozen"
  }
}
```

**Simulation failed (500):**
```json
{
  "success": false,
  "error": {
    "code": "PROTOCOL_ERROR",
    "message": "simulation failed: policy denied: daily velocity limit exceeded"
  }
}
```

### HTTP Status Codes

| HTTP Status | Meaning |
|-------------|---------|
| 200 | Success |
| 201 | Created (wallet, etc.) |
| 400 | Bad request — `INVALID_INPUT`, `INVALID_CONFIG`, `SESSION_ERROR`, `SERIALIZATION_ERROR` |
| 401 | Unauthorized — `AUTH_FAILED` |
| 403 | Forbidden — `PERMISSION_DENIED`, `MFA_REQUIRED` |
| 404 | Not found — `NOT_FOUND` |
| 422 | Unprocessable — `POLICY_DENIED`, `APPROVAL_REQUIRED`, `KEY_FROZEN`, `CRYPTO_ERROR` (EVM low-S) |
| 429 | Rate limit exceeded — `AUTH_RATE_LIMITED` |
| 500 | Internal error — `PROTOCOL_ERROR`, `CRYPTO_ERROR`, `INTERNAL_ERROR` |

> **Security note:** Auth errors always return generic `"authentication failed"` — no details leaked to prevent enumeration.

---

## Rate Limits

Default: 100 requests/second per IP. Handshake: 10 req/sec per `client_key_id`.

Configure via `RATE_LIMIT_RPS` environment variable.
