# MPC Wallet API -- Error Codes

All API errors return a structured JSON envelope:

```json
{
  "success": false,
  "error": {
    "code": "ERROR_CODE",
    "message": "Human-readable description"
  }
}
```

The `code` field is a machine-readable `SCREAMING_SNAKE_CASE` string. The `message` field contains a human-readable description suitable for logging but not for programmatic branching.

---

## Error Code Reference

### Authentication Errors

| Code | HTTP Status | Description | Common Causes |
|------|-------------|-------------|---------------|
| `AUTH_FAILED` | 401 Unauthorized | Authentication failed | Invalid/expired session token, bad handshake signature, revoked client key, replay detected, unknown client on mainnet |
| `AUTH_RATE_LIMITED` | 429 Too Many Requests | Rate limit exceeded | More than 10 handshake requests/second per `client_key_id`, or per-client request rate exceeded |

### Permission Errors

| Code | HTTP Status | Description | Common Causes |
|------|-------------|-------------|---------------|
| `PERMISSION_DENIED` | 403 Forbidden | Insufficient role or permissions | Viewer attempting to sign, non-admin attempting freeze/unfreeze/revoke, risk tier check failed, RBAC role mismatch |
| `MFA_REQUIRED` | 403 Forbidden | Operation requires MFA verification | Admin operations (create wallet, freeze, unfreeze) require `mfa_verified=true` in the auth context |

### Validation Errors

| Code | HTTP Status | Description | Common Causes |
|------|-------------|-------------|---------------|
| `INVALID_INPUT` | 400 Bad Request | Input parameter validation failed | Invalid hex in message field, unsupported chain name, malformed address, missing required field, password not provided |
| `INVALID_CONFIG` | 400 Bad Request | Configuration parameter is invalid | `threshold > total_parties`, unsupported threshold/party combination, invalid scheme name |

### Resource Errors

| Code | HTTP Status | Description | Common Causes |
|------|-------------|-------------|---------------|
| `NOT_FOUND` | 404 Not Found | Requested resource does not exist | Unknown wallet ID, key group not in store |

### Business Logic Errors

| Code | HTTP Status | Description | Common Causes |
|------|-------------|-------------|---------------|
| `POLICY_DENIED` | 422 Unprocessable Entity | Signing policy check failed | No policy loaded (FR-B5 "no policy = no sign"), velocity limit exceeded, policy rule evaluation rejected the request |
| `APPROVAL_REQUIRED` | 422 Unprocessable Entity | Approval quorum not met | Insufficient approvals, separation-of-duty violation, approval hold period not elapsed |
| `SESSION_ERROR` | 400 Bad Request | Session management error | Duplicate `tx_fingerprint` (idempotency conflict), invalid session state transition |
| `KEY_FROZEN` | 422 Unprocessable Entity | Wallet/key group is frozen | Attempting to sign with a frozen wallet; unfreeze it first via `POST /v1/wallets/{id}/unfreeze` |

### Cryptographic / Protocol Errors

| Code | HTTP Status | Description | Common Causes |
|------|-------------|-------------|---------------|
| `PROTOCOL_ERROR` | 500 Internal Server Error | MPC protocol round failed | Timeout during distributed keygen/sign, MPC node unreachable, identifiable abort detected cheating party, simulation failed |
| `CRYPTO_ERROR` | 500 Internal Server Error | Low-level cryptographic operation failed | Signature verification failed, EC arithmetic error, EVM high-S violation (EIP-2), AES-GCM decryption failure |
| `SERIALIZATION_ERROR` | 400 Bad Request | Encoding/decoding failure | Malformed protocol message, BCS encoding error, JSON deserialization failure, version mismatch in stored data |

### Infrastructure Errors

| Code | HTTP Status | Description | Common Causes |
|------|-------------|-------------|---------------|
| `INTERNAL_ERROR` | 500 Internal Server Error | Unexpected server-side failure | NATS transport error, key store I/O error, audit ledger failure, Redis connection lost, Vault unavailable |

---

## CoreError to API Error Mapping

The gateway automatically converts internal `CoreError` variants to `ApiError` responses. This table shows the exact mapping:

| CoreError Variant | API Error Code | HTTP Status |
|-------------------|---------------|-------------|
| `Unauthorized(msg)` | `PERMISSION_DENIED` | 403 |
| `InvalidInput(msg)` | `INVALID_INPUT` | 400 |
| `PasswordRequired(msg)` | `INVALID_INPUT` | 400 |
| `InvalidConfig(msg)` | `INVALID_CONFIG` | 400 |
| `NotFound(msg)` | `NOT_FOUND` | 404 |
| `PolicyRequired(msg)` | `POLICY_DENIED` | 422 |
| `ApprovalRequired(msg)` | `APPROVAL_REQUIRED` | 422 |
| `SessionError(msg)` | `SESSION_ERROR` | 400 |
| `KeyFrozen(msg)` | `KEY_FROZEN` | 422 |
| `Serialization(msg)` | `SERIALIZATION_ERROR` | 400 |
| `EvmLowS(msg)` | `CRYPTO_ERROR` | 422 |
| `Protocol(msg)` | `PROTOCOL_ERROR` | 500 |
| `Crypto(msg)` | `CRYPTO_ERROR` | 500 |
| `Encryption(msg)` | `CRYPTO_ERROR` | 500 |
| `Transport(msg)` | `INTERNAL_ERROR` | 500 |
| `KeyStore(msg)` | `INTERNAL_ERROR` | 500 |
| `AuditError(msg)` | `INTERNAL_ERROR` | 500 |
| `Other(msg)` | `INTERNAL_ERROR` | 500 |

---

## Error Handling Best Practices

### Client-side retry logic

- **4xx errors** -- Do not retry. Fix the request (correct input, obtain proper auth, wait for approval).
- **429 (rate limited)** -- Back off exponentially. Default rate: 10 req/s per client key.
- **500 `PROTOCOL_ERROR`** -- May be retried. MPC signing rounds can fail due to transient network issues between nodes.
- **500 `INTERNAL_ERROR`** -- May be retried with backoff. Indicates infrastructure issues (NATS/Redis/Vault).

### Distinguishing auth failures

The gateway intentionally returns a generic `AUTH_FAILED` for all authentication failures (invalid token, expired session, revoked key, replay detected). This is a security measure to avoid leaking information about which specific check failed. Check gateway logs (with appropriate access) for detailed diagnostics.

### Frozen wallet recovery

If you receive `KEY_FROZEN`, the wallet has been frozen by an admin (emergency procedure). Contact your organization's admin to unfreeze. The admin must have MFA verified to perform the unfreeze operation.

---

## Source Reference

- Error types: `services/api-gateway/src/errors.rs`
- Core errors: `crates/mpc-wallet-core/src/error.rs`
- Auth middleware: `services/api-gateway/src/middleware/auth.rs`
- OpenAPI spec: `GET /v1/api-docs/openapi.json`
