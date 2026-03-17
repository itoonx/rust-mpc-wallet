# Auth System Security Audit Report

**Scope:** `services/api-gateway/src/auth/`, routes, middleware
**Date:** 2026-03-17
**Method:** Code review + 53 automated attack tests
**Test file:** `services/api-gateway/tests/auth_security_audit.rs`

---

## Executive Summary

The auth system is **well-designed** with proper cryptographic foundations. No critical vulnerabilities found that allow authentication bypass. The protocol correctly implements mutual authentication, forward secrecy, and transcript binding.

**53 security tests pass** covering: replay attacks, signature forgery, key confusion, session hijacking, HMAC bypass, auth method confusion, revocation enforcement, malformed input, and information leakage.

Key findings are operational/hardening gaps, not protocol breaks.

---

## Findings

### SEV-HIGH: No Rate Limiting on Auth Endpoints

**Location:** `routes/auth.rs` — `/v1/auth/hello`, `/v1/auth/verify`
**Issue:** Rate limiter middleware exists (`middleware/rate_limit.rs`) but is **not wired** to auth endpoints. An attacker can flood handshake endpoints without throttling.
**Impact:** DoS via handshake flooding, brute-force key enumeration (theoretical — 256-bit keys are infeasible to brute-force, but resource exhaustion is real).
**Recommendation:** Wire `rate_limit_middleware` to auth routes. Spec requires 10 req/min per IP, 5/min per key_id on handshake endpoints.

### SEV-HIGH: SessionStore Has No Size Limit

**Location:** `auth/session.rs` — `SessionStore`
**Issue:** `HashMap<String, AuthenticatedSession>` is unbounded. No background task prunes expired sessions. `prune_expired()` is only called manually.
**Impact:** Memory exhaustion over time if attacker creates thousands of sessions (each handshake produces a stored session). In production with sustained traffic, this leaks memory.
**Recommendation:** Add either:
1. Background `tokio::spawn` task that calls `prune_expired()` every 60s, or
2. Size cap on `store()` that rejects new sessions when count exceeds limit + triggers prune.

### SEV-MEDIUM: Client Registry Is Optional (Open Enrollment)

**Location:** `routes/auth.rs:142-158`
**Issue:** If `CLIENT_KEYS_FILE` is not set, `client_registry.keys` is empty, and the trusted-client check is **skipped entirely**. Any Ed25519 key can authenticate.
**Impact:** In production without CLIENT_KEYS_FILE, the system operates in "open enrollment" mode — any client with a valid Ed25519 key pair can establish a session. This may be intentional for dev/test but dangerous in production.
**Recommendation:** Log a WARN at startup if registry is empty in mainnet mode. Consider making it required for mainnet.

### SEV-MEDIUM: Revocation Is Static (No Hot-Reload)

**Location:** `state.rs:302-311`
**Issue:** Revoked keys are loaded from file at startup. No API endpoint to add revocations dynamically. Revoking a compromised key requires a restart.
**Impact:** Incident response is slow — if a client key is compromised, the operator must update the file and restart the service.
**Recommendation:** Add `POST /v1/admin/revoke-key` endpoint (admin-only) that dynamically adds to the revoked set.

### SEV-MEDIUM: Auth Method Confusion — Invalid Session Falls Through

**Location:** `middleware/auth.rs:22-50`
**Issue:** When `X-Session-Token` header is present but the session is invalid/expired, the middleware returns 401 immediately — this is correct. However, if the header value fails `to_str()` (non-UTF8), the `and_then` chain returns `None`, and the middleware **falls through to try API key auth**.

```rust
if let Some(session_id) = headers.get("x-session-token").and_then(|v| v.to_str().ok()) {
```

**Impact:** An attacker who sends a non-UTF8 `X-Session-Token` header along with a valid `X-API-Key` can bypass the "session token takes priority" guarantee. Low severity because the API key must still be valid.
**Recommendation:** Check for header presence separately from parsing:
```rust
if headers.contains_key("x-session-token") {
    // Must validate session — don't fall through
}
```

### SEV-LOW: HMAC Replay Window (30 seconds)

**Location:** `middleware/hmac.rs:110`
**Issue:** Within the 30-second validity window, the same HMAC-signed request can be replayed multiple times. No per-request nonce or sequence number.
**Impact:** Low — idempotency at the handler level (tx_fingerprint, session manager) prevents duplicate actions. But not all endpoints may have idempotency guards.
**Recommendation:** Acceptable for now. Document that handlers must implement idempotency.

### SEV-LOW: All-Zeros X25519 Ephemeral Key Accepted

**Location:** `auth/handshake.rs:87-91`
**Issue:** The server validates key length (32 bytes) but does not reject the all-zeros public key, which is a low-order point in Curve25519. The DH shared secret will be all-zeros.
**Impact:** Very low — the handshake will produce a degenerate shared secret, but authentication still requires a valid Ed25519 signature. An attacker gains nothing because they'd need to sign the transcript with a valid static key.
**Recommendation:** Optional — add `if client_eph == [0u8; 32] { return Err(...) }` for defense-in-depth.

### SEV-LOW: Session TTL Not Configurable

**Location:** `auth/types.rs:16`
**Issue:** `DEFAULT_SESSION_TTL_SECS = 3600` is hardcoded. Operators cannot reduce it for sensitive deployments.
**Recommendation:** Make configurable via environment variable `SESSION_TTL_SECS`.

### SEV-INFO: Protocol Downgrade Returns 422 Instead of 401

**Location:** `routes/auth.rs` + serde deserialization
**Issue:** When a client sends an unknown algorithm enum variant (e.g., `"p256-ecdh"`), Axum's JSON deserialization fails with 422 Unprocessable Entity before the handler runs. The handler would return 401 for `NoCommonAlgorithm`.
**Impact:** None — the request is rejected. But the different status code could leak information about the parsing stage.
**Recommendation:** Add a custom JSON extractor rejection handler that returns 401 for auth endpoints.

---

## Verified Security Properties

| Property | Status | Test |
|----------|--------|------|
| Forward secrecy (unique keys per session) | PASS | `test_forward_secrecy_unique_keys_per_session` |
| Mutual authentication (Ed25519 transcript) | PASS | `test_e2e_client_server_key_agreement` |
| Replay protection (nonce) | PASS | `test_replay_same_nonce_rejected` |
| Replay protection (challenge consumed) | PASS | `test_replay_verify_with_consumed_challenge` |
| Timestamp drift enforcement | PASS | `test_handshake_timestamp_31s_in_past_rejected` |
| Signature forgery rejected | PASS | `test_verify_with_forged_signature` |
| Key substitution rejected | PASS | `test_verify_with_different_key_signature` |
| Key ID spoofing rejected | PASS | `test_key_id_spoofing_rejected` |
| Session revocation works | PASS | `test_session_revocation` |
| Expired session rejected | PASS | `test_expired_session_rejected` |
| HMAC body tamper detected | PASS | `test_hmac_body_tamper_detected` |
| HMAC path tamper detected | PASS | `test_hmac_path_tamper_detected` |
| HMAC cross-key usage rejected | PASS | `test_hmac_wrong_api_key` |
| Constant-time API key comparison | PASS | `test_api_key_constant_time_comparison` |
| Generic error messages (no info leak) | PASS | `test_error_messages_are_generic` |
| Revoked key blocked at hello | PASS | `test_revoked_key_cannot_handshake` |
| Revoked key revokes session on refresh | PASS | `test_session_refresh_revokes_on_key_revocation` |
| Auth priority (session > API key > JWT) | PASS | `test_session_token_takes_priority_over_api_key` |
| Invalid session doesn't fall through | PASS | `test_invalid_session_does_not_fall_through_to_api_key` |
| Concurrent handshakes isolated | PASS | `test_concurrent_handshakes_independent` |
| Multiple sessions per client | PASS | `test_same_client_multiple_sessions` |

---

## Test Coverage Summary

| Category | Count |
|----------|-------|
| Happy path (E2E) | 3 |
| Replay attacks | 4 |
| Timestamp manipulation | 3 |
| Signature forgery | 5 |
| Key confusion / identity | 4 |
| Session lifecycle | 6 |
| Protocol downgrade | 2 |
| Malformed input | 6 |
| HMAC bypass | 5 |
| Auth method confusion | 3 |
| Revocation enforcement | 3 |
| DoS / resource | 2 |
| Information leakage | 3 |
| Concurrency | 2 |
| API key specific | 2 |
| **Total** | **53** |
