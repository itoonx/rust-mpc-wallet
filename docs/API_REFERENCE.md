# MPC Wallet — REST API Reference

Base URL: `https://api.example.com`

All responses follow the format:
```json
{
  "success": true|false,
  "data": { ... },
  "error": "message (only when success=false)"
}
```

---

## Authentication

Three methods supported — middleware checks in order, uses first match:

### 1. Session Token (key-exchange handshake)
```
X-Session-Token: <session_token>
```
Obtained via the `/v1/auth/hello` → `/v1/auth/verify` handshake flow (see below).
Provides mutual authentication with forward secrecy (X25519 ECDH + Ed25519).

### 2. API Key (service-to-service)
```
X-API-Key: sk_prod_abcdef1234567890
```

### 3. JWT Bearer Token (user-facing)
```
Authorization: Bearer eyJhbGciOiJSUzI1NiIs...
```
Supports RS256/ES256/HS256. JWT claims must include: `sub`, `exp`, `iat`, `iss`.
Optional: `roles` (array), `dept`, `cost_center`, `risk_tier`, `mfa_verified`.

**Middleware priority:** `X-Session-Token` → `X-API-Key` → `Authorization: Bearer` → 401.

> Full protocol specification: `specs/AUTH_SPEC.md` (28 sections, 1,067 lines)

---

## Getting API Keys

API keys are provisioned by the server operator, not self-service. They are configured at startup via environment variables or a JSON file, then hashed with HMAC-SHA256 — the raw key is never stored.

### Method 1: JSON File (recommended for production)

Set the `API_KEYS_FILE` environment variable to a JSON file path:

```bash
export API_KEYS_FILE=/etc/mpc-wallet/api-keys.json
```

**File format** — array of key objects:

```json
[
  {
    "key": "sk_prod_a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6",
    "label": "trading-service",
    "role": "initiator",
    "allowed_wallets": ["550e8400-e29b-41d4-a716-446655440000"],
    "allowed_chains": ["ethereum", "polygon", "arbitrum"],
    "expires_at": 1742000000
  },
  {
    "key": "sk_prod_q7r8s9t0u1v2w3x4y5z6a7b8c9d0e1f2",
    "label": "monitoring-dashboard",
    "role": "viewer",
    "allowed_wallets": null,
    "allowed_chains": null,
    "expires_at": null
  },
  {
    "key": "sk_prod_g3h4i5j6k7l8m9n0o1p2q3r4s5t6u7v8",
    "label": "ops-admin",
    "role": "admin",
    "allowed_wallets": null,
    "allowed_chains": null,
    "expires_at": null
  }
]
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `key` | string | yes | Raw API key secret. Use a cryptographically random string (>= 32 chars). Only used at startup to compute HMAC hash — never stored in plaintext. |
| `label` | string | yes | Human-readable name for audit logs (e.g., `"trading-service"`, `"ops-admin"`). |
| `role` | string | yes | Maximum permission level: `admin`, `initiator`, `approver`, or `viewer`. |
| `allowed_wallets` | string[] or null | no | Restrict this key to specific wallet IDs. `null` = all wallets. |
| `allowed_chains` | string[] or null | no | Restrict to specific chains. `null` = all chains. |
| `expires_at` | u64 or null | no | UNIX timestamp (seconds). After this time the key is rejected. `null` = no expiry. |

### Method 2: Environment Variable (simple / dev)

Set comma-separated keys via `API_KEYS` — all get `viewer` role:

```bash
export API_KEYS=sk_dev_abc123,sk_dev_xyz789
```

### Generating a Secure Key

```bash
# Generate a 32-byte random key (recommended)
openssl rand -hex 32
# → e.g., 7f3a9c2b1d4e5f6a8b0c9d7e2f1a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a

# Or with prefix for readability
echo "sk_prod_$(openssl rand -hex 24)"
# → e.g., sk_prod_a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2w3x4
```

### Roles & Permissions

| Role | GET wallets | POST wallets (keygen) | POST sign | POST freeze/unfreeze | POST revoke-key |
|------|-------------|----------------------|-----------|---------------------|-----------------|
| `viewer` | yes | no | no | no | no |
| `initiator` | yes | yes | yes | no | no |
| `approver` | yes | no | yes | yes | no |
| `admin` | yes | yes | yes | yes | yes |

### Using an API Key

**GET requests** — header only:

```bash
curl -H "X-API-Key: sk_prod_a1b2c3..." \
  https://api.example.com/v1/wallets
```

**POST requests** — header + HMAC signature required:

```bash
TIMESTAMP=$(date +%s)
BODY='{"label":"My Wallet","scheme":"gg20-ecdsa","threshold":2,"total_parties":3}'
BODY_HASH=$(echo -n "$BODY" | sha256sum | cut -d' ' -f1)
HMAC_INPUT="${TIMESTAMP}.POST./v1/wallets.${BODY_HASH}"
SIGNATURE=$(echo -n "$HMAC_INPUT" | openssl dgst -sha256 -hmac "sk_prod_a1b2c3..." -hex | cut -d' ' -f2)

curl -X POST \
  -H "X-API-Key: sk_prod_a1b2c3..." \
  -H "X-Signature: v1=${SIGNATURE}" \
  -H "X-Timestamp: ${TIMESTAMP}" \
  -H "Content-Type: application/json" \
  -d "$BODY" \
  https://api.example.com/v1/wallets
```

**HMAC signature format:** `v1=<hex(HMAC-SHA256(api_key, "{timestamp}.{METHOD}.{path}.{sha256(body)}"))>`

The signature binds the timestamp, HTTP method, path, and body hash — preventing replay, path tampering, and body modification.

### Self-Service API Key Management (user-facing)

For user-facing applications, API keys can be created, listed, and deleted via REST endpoints.
All endpoints require **admin** role.

#### POST /v1/api-keys — Create a new key

The raw key is returned **once** in the response. It is never stored — only the HMAC-SHA256 hash is kept. If the caller loses the key, they must create a new one.

**Request:**
```json
{
  "label": "my-trading-bot",
  "role": "initiator",
  "allowed_wallets": ["550e8400-e29b-41d4-a716-446655440000"],
  "allowed_chains": ["ethereum", "polygon"],
  "expires_at": 1742000000
}
```

**Response (201 Created):**
```json
{
  "success": true,
  "data": {
    "key_id": "vxk_a1b2c3d4e5f6g7h8",
    "raw_key": "sk_initiator_7f3a9c2b1d4e5f6a8b0c9d7e2f1a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a",
    "label": "my-trading-bot",
    "role": "initiator",
    "created_at": 1710768000,
    "expires_at": 1742000000
  }
}
```

#### GET /v1/api-keys — List all keys (metadata only)

Returns labels, roles, origins, and expiry — never raw keys or hashes.

```json
{
  "success": true,
  "data": {
    "keys": [
      {
        "key_id": "vxk_static_0",
        "label": "ops-admin",
        "role": "Admin",
        "origin": "static",
        "created_by": "config",
        "created_at": 1710768000,
        "revoked": false
      },
      {
        "key_id": "vxk_a1b2c3d4e5f6g7h8",
        "label": "my-trading-bot",
        "role": "Initiator",
        "origin": "dynamic",
        "created_by": "api-key:ops-admin",
        "created_at": 1710768100,
        "revoked": false
      }
    ],
    "total": 2,
    "active": 2
  }
}
```

#### GET /v1/api-keys/:id — Get a single key

Returns metadata for a specific key by `key_id`.

#### DELETE /v1/api-keys/:id — Delete a key

Permanently removes the key. Returns 404 if the key doesn't exist.

```json
{
  "success": true,
  "data": {
    "key_id": "vxk_a1b2c3d4e5f6g7h8",
    "deleted": true
  }
}
```

### Security Notes

- Raw keys are **never stored** on the server — only HMAC-SHA256 hashes (both static and dynamic).
- Key verification uses **constant-time comparison** (`subtle::ConstantTimeEq`) to prevent timing attacks.
- Dynamic keys show the raw key **once** at creation — it cannot be retrieved afterward.
- Expired keys are **immediately rejected** — no grace period.
- Static keys (service-to-service): rotate by updating the config file and restarting.
- Dynamic keys (user-facing): create a new key via API, migrate clients, then delete the old key via API — **no restart needed**.
- Keep `API_KEYS_FILE` with restrictive file permissions (`chmod 600`).

### Environment Variables Reference

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `JWT_SECRET` | yes | — | HMAC secret for JWT validation + API key hashing (>= 32 bytes) |
| `API_KEYS_FILE` | no | — | Path to JSON array of API key configs |
| `API_KEYS` | no | — | Legacy: comma-separated keys (all get viewer role) |
| `SERVER_SIGNING_KEY` | no | auto-generated | Hex-encoded 32-byte Ed25519 secret for handshake |
| `CLIENT_KEYS_FILE` | no | — | Path to JSON array of trusted client Ed25519 pubkeys |
| `REVOKED_KEYS_FILE` | no | — | Path to JSON array of revoked key_id strings |
| `NETWORK` | no | `testnet` | `mainnet`, `testnet`, or `devnet` |
| `PORT` | no | `3000` | HTTP listen port |
| `RATE_LIMIT_RPS` | no | `100` | Max requests/second per IP |
| `CORS_ALLOWED_ORIGINS` | no | (permissive) | Comma-separated origins |

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

## Error Codes

| HTTP Status | Meaning |
|-------------|---------|
| 200 | Success |
| 201 | Created (wallet, etc.) |
| 400 | Bad request (invalid chain, scheme, params) |
| 401 | Unauthorized (missing/invalid auth) |
| 403 | Forbidden (wallet frozen, insufficient role) |
| 404 | Not found (wallet ID doesn't exist) |
| 422 | Unprocessable (simulation failed) |
| 429 | Rate limit exceeded |
| 500 | Internal server error |

---

## Rate Limits

Default: 100 requests/second per IP.

Configure via `RATE_LIMIT_RPS` environment variable or per-API-key limits in production.
