# MPC Wallet SDK -- Quick Start Guide

This guide walks you through authenticating with the API gateway, creating a threshold MPC wallet, and signing your first transaction.

## Prerequisites

- A running API gateway instance (see [docs/DEPLOYMENT.md](DEPLOYMENT.md))
- An Ed25519 keypair registered with the gateway admin (for Session JWT auth)
- `curl` or any HTTP client

## Base URL

All endpoints are prefixed with `/v1`. Replace `GATEWAY` with your gateway host throughout this guide.

```
https://GATEWAY/v1/...
```

## Authentication

The gateway supports three authentication methods, evaluated in priority order:

1. **mTLS** -- machine-to-machine (TLS client certificate)
2. **Session JWT** -- application-to-server (X25519 key exchange + HS256 JWT)
3. **Bearer JWT** -- human-to-system (RS256/ES256 from IdP like Auth0/Okta)

If a credential header is present but invalid, authentication fails immediately -- there is no fall-through to the next method.

### Option 1: Session JWT (recommended for applications)

**Step 1 -- Generate an Ed25519 keypair:**

```bash
cargo run -p mpc-wallet-core --example gen_gateway_keys -- ./keys
```

This creates `./keys/client.pub` and `./keys/client.key`.

**Step 2 -- Register the public key** with the gateway admin (out of band).

**Step 3 -- Perform the handshake:**

```bash
# ClientHello -- initiate key exchange
curl -X POST https://GATEWAY/v1/auth/hello \
  -H "Content-Type: application/json" \
  -d '{
    "protocol_version": "mpc-wallet-auth-v1",
    "client_key_id": "<your-key-id>",
    "client_ephemeral_pubkey": "<x25519-public-hex>",
    "client_static_pubkey": "<ed25519-public-hex>",
    "client_nonce": "<random-32-bytes-hex>",
    "key_exchange": "X25519",
    "signature_algorithm": "Ed25519",
    "aead_algorithm": "ChaCha20Poly1305"
  }'

# Response includes server_challenge
```

```bash
# ClientAuth -- sign the transcript to prove identity
curl -X POST https://GATEWAY/v1/auth/verify \
  -H "Content-Type: application/json" \
  -d '{
    "server_challenge": "<from-server-hello>",
    "client_static_pubkey": "<ed25519-public-hex>",
    "client_signature": "<ed25519-signature-of-transcript>"
  }'

# Response:
# {
#   "success": true,
#   "data": {
#     "session_id": "...",
#     "session_token": "<jwt>",
#     "expires_at": 1714000000,
#     "key_fingerprint": "a1b2c3d4..."
#   }
# }
```

**Step 4 -- Use the session token** for all subsequent requests:

```bash
curl -H "X-Session-Token: <jwt>" https://GATEWAY/v1/wallets
```

**Refresh the session** before it expires:

```bash
curl -X POST https://GATEWAY/v1/auth/refresh-session \
  -H "Content-Type: application/json" \
  -d '{"session_token": "<jwt>"}'
```

### Option 2: Bearer JWT (for admin/supervisor users)

Use your identity provider (Auth0, Okta, etc.) to obtain a JWT, then pass it as a Bearer token:

```bash
curl -H "Authorization: Bearer <jwt>" https://GATEWAY/v1/wallets
```

The gateway validates RS256/ES256 signatures and extracts roles from JWT claims.

### Option 3: mTLS (for service-to-service)

Configure your HTTP client with a TLS client certificate registered in the gateway's `MtlsServiceRegistry`. The TLS terminator sets `X-Client-Cert-*` headers after verifying the certificate.

## Health Check

Verify the gateway is running before making authenticated requests:

```bash
# Basic health
curl https://GATEWAY/v1/health
# {"success":true,"data":{"status":"healthy","version":"0.1.0","chains_supported":50}}

# Liveness probe (Kubernetes)
curl https://GATEWAY/v1/health/live

# Readiness probe (checks NATS, Redis, Vault connectivity)
curl https://GATEWAY/v1/health/ready
```

## Create a Wallet

Requires **Admin** role with **MFA verified**.

```bash
curl -X POST https://GATEWAY/v1/wallets \
  -H "X-Session-Token: <jwt>" \
  -H "Content-Type: application/json" \
  -d '{
    "label": "treasury-eth",
    "scheme": "cggmp21-secp256k1",
    "threshold": 2,
    "total_parties": 3
  }'

# Response (201 Created):
# {
#   "success": true,
#   "data": {
#     "id": "a1b2c3d4-...",
#     "label": "treasury-eth",
#     "scheme": "cggmp21-secp256k1",
#     "threshold": 2,
#     "total_parties": 3,
#     "created_at": 1714000000
#   }
# }
```

The gateway orchestrates distributed key generation across MPC nodes via NATS. The gateway itself holds zero key shares (DEC-015).

## List and Inspect Wallets

```bash
# List all wallets
curl -H "X-Session-Token: <jwt>" https://GATEWAY/v1/wallets

# Get wallet details with derived addresses
curl -H "X-Session-Token: <jwt>" https://GATEWAY/v1/wallets/<wallet-id>
```

The detail endpoint automatically derives addresses for chains compatible with the wallet's signing scheme.

## Sign a Message

Requires **Initiator** or **Admin** role.

```bash
curl -X POST https://GATEWAY/v1/wallets/<wallet-id>/sign \
  -H "X-Session-Token: <jwt>" \
  -H "Content-Type: application/json" \
  -d '{
    "message": "<hex-encoded-message-or-tx-hash>"
  }'

# Response:
# {
#   "success": true,
#   "data": {
#     "signature": {"r": "0x...", "s": "0x...", "recovery_id": 0},
#     "scheme": "gg20-ecdsa"
#   }
# }
```

The gateway builds a `SignAuthorization` proof (DEC-012) that each MPC node independently verifies before participating in the signing protocol.

## Derive a Chain Address

```bash
curl -H "X-Session-Token: <jwt>" \
  https://GATEWAY/v1/chains/ethereum/address/<wallet-id>

# Response:
# {"success":true,"data":{"wallet_id":"...","chain":"ethereum","address":"0x..."}}
```

## Simulate a Transaction

Pre-sign risk assessment. Requires **Viewer** or higher role.

```bash
curl -X POST https://GATEWAY/v1/wallets/<wallet-id>/simulate \
  -H "X-Session-Token: <jwt>" \
  -H "Content-Type: application/json" \
  -d '{
    "chain": "ethereum",
    "to": "0xRecipientAddress",
    "value": "1000000000000000000",
    "data": null
  }'

# Response:
# {
#   "success": true,
#   "data": {
#     "success": true,
#     "gas_used": 21000,
#     "risk_score": 15,
#     "risk_flags": []
#   }
# }
```

## Freeze / Unfreeze a Wallet

Emergency controls. Requires **Admin** role with **MFA verified**.

```bash
# Freeze -- blocks all signing operations
curl -X POST https://GATEWAY/v1/wallets/<wallet-id>/freeze \
  -H "X-Session-Token: <jwt>"

# Unfreeze
curl -X POST https://GATEWAY/v1/wallets/<wallet-id>/unfreeze \
  -H "X-Session-Token: <jwt>"
```

## Revoke a Client Key

Admin-only. Immediately invalidates a client key and terminates its active sessions.

```bash
curl -X POST https://GATEWAY/v1/auth/revoke-key \
  -H "X-Session-Token: <jwt>" \
  -H "Content-Type: application/json" \
  -d '{"key_id": "<client-key-id>"}'
```

## List Supported Chains

No authentication required.

```bash
curl https://GATEWAY/v1/chains

# Returns all 50 supported chains with category and display name.
```

## Supported Protocols

| Protocol | Curve | Chains |
|----------|-------|--------|
| `cggmp21-secp256k1` | secp256k1 | EVM (Ethereum, Polygon, BSC, Arbitrum, ...), Bitcoin (legacy), TRON, Cosmos |
| `gg20-ecdsa` | secp256k1 | EVM, Bitcoin (legacy), TRON, Cosmos |
| `frost-ed25519` | Ed25519 | Solana, Sui, Aptos, TON |
| `frost-secp256k1-tr` | secp256k1 | Bitcoin Taproot |
| `bls12-381` | BLS12-381 | Filecoin, ETH validators |
| `sr25519` | Ristretto255 | Polkadot, Kusama, Substrate chains |
| `stark` | Stark curve | StarkNet |

## RBAC Roles

| Role | Capabilities |
|------|-------------|
| **Viewer** | List wallets, list chains, simulate transactions |
| **Initiator** | Everything Viewer can do + sign messages, create transactions |
| **Approver** | Everything Viewer can do + approve signing requests |
| **Admin** | All operations including create/freeze/unfreeze wallets, revoke keys (requires MFA for sensitive ops) |

## Rate Limits

- Handshake endpoints (`/v1/auth/hello`): 10 requests/second per `client_key_id`
- Protected endpoints: subject to per-client rate limiting
- MPC node keygen/sign handlers: per-group-id rate limiting

Contact your gateway admin for higher limits.

## Error Handling

All errors return structured JSON:

```json
{
  "success": false,
  "error": {
    "code": "AUTH_FAILED",
    "message": "token expired"
  }
}
```

See [docs/ERROR_CODES.md](ERROR_CODES.md) for the complete error catalog.

## OpenAPI Specification

The gateway serves its OpenAPI 3.1 spec at:

```
GET /v1/api-docs/openapi.json
```

You can import this into Swagger UI, Postman, or any OpenAPI-compatible tool.

## Prometheus Metrics

Available at `/v1/metrics` (requires authentication):

```bash
curl -H "X-Session-Token: <jwt>" https://GATEWAY/v1/metrics
```

## Next Steps

- [DEPLOYMENT.md](DEPLOYMENT.md) -- Production deployment with NATS, Redis, Vault
- [ERROR_CODES.md](ERROR_CODES.md) -- Complete error code reference
- [API_REFERENCE.md](API_REFERENCE.md) -- Full API endpoint documentation
- [SECURITY_FINDINGS.md](SECURITY_FINDINGS.md) -- Security audit status
- [CRYPTOGRAPHY.md](CRYPTOGRAPHY.md) -- Protocol implementation details
