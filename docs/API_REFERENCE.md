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

Two methods supported — middleware selects based on header present:

### API Key (service-to-service)
```
X-API-Key: your-api-key
```

### JWT Bearer Token (user-facing)
```
Authorization: Bearer eyJhbGciOiJIUzI1NiIs...
```

JWT claims must include: `sub`, `exp`, `iat`, `iss`.
Optional: `roles` (array), `dept`, `cost_center`, `risk_tier`, `mfa_verified`.

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
