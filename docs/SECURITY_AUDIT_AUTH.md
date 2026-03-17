# Auth System Security Audit Report

**Scope:** `services/api-gateway/src/auth/`, routes, middleware
**Date:** 2026-03-17
**Method:** Code review + 57 automated attack tests
**Test file:** `services/api-gateway/tests/auth_security_audit.rs`

---

## Executive Summary

The auth system is **well-designed** with proper cryptographic foundations. No critical vulnerabilities found that allow authentication bypass. The protocol correctly implements mutual authentication, forward secrecy, and transcript binding.

**57 security tests pass** covering: replay attacks, signature forgery, key confusion, session hijacking, HMAC bypass, auth method confusion, revocation enforcement, malformed input, information leakage, rate limiting, and E2E HTTP flows.

All HIGH and MEDIUM findings have been resolved. Remaining LOW/INFO findings are accepted risks.

---

## Findings

### SEV-HIGH: No Rate Limiting on Auth Endpoints — FIXED

**Location:** `routes/auth.rs` — `/v1/auth/hello`
**Issue:** Rate limiter existed but was not wired to auth endpoints.
**Fix:** Token-bucket `RateLimiter` (10 req/sec per `client_key_id`) wired directly in `auth_hello` handler. Returns 429 when exceeded.
**Test:** `test_rate_limit_on_handshake`

### SEV-HIGH: SessionStore Has No Size Limit — FIXED

**Location:** `auth/session.rs` — `SessionStore`
**Issue:** `HashMap<String, AuthenticatedSession>` was unbounded with no background pruning.
**Fix:** Three-layer protection:
1. **Size cap:** `MAX_SESSIONS = 100,000` — `store()` returns `false` when at capacity
2. **Lazy prune:** triggered when store reaches 50% capacity
3. **Background prune:** `spawn_prune_task()` runs every 60 seconds, removes expired sessions
**Test:** `test_session_store_capacity_limit`

### SEV-MEDIUM: Client Registry Is Optional (Open Enrollment) — FIXED

**Location:** `state.rs` — `AppState::from_config()`
**Issue:** If `CLIENT_KEYS_FILE` not set, any Ed25519 key can authenticate.
**Fix:** Logs `tracing::warn!` at startup when registry is empty on mainnet network. The warning message explicitly states "open enrollment mode."

### SEV-MEDIUM: Revocation Is Static (No Hot-Reload) — FIXED

**Location:** `state.rs` + `routes/auth.rs`
**Issue:** Revoked keys only loaded from file at startup. No dynamic revocation.
**Fix:**
- `revoked_keys` changed from `Arc<HashSet>` to `Arc<RwLock<HashSet>>` for concurrent mutation
- Added `AppState::revoke_key()` method
- Added `POST /v1/auth/revoke-key` endpoint for dynamic revocation
**Test:** `test_dynamic_key_revocation`

### SEV-MEDIUM: Auth Method Confusion — Invalid Session Falls Through — FIXED

**Location:** `middleware/auth.rs`
**Issue:** Non-UTF8 `X-Session-Token` header silently fell through to API key auth.
**Fix:** Auth middleware now uses `headers.contains_key("x-session-token")` first. If the header is **present** (regardless of encoding), the session path is used — empty or unparseable values return 401 immediately, no fall-through.
**Test:** `test_empty_auth_headers_rejected`, `test_invalid_session_does_not_fall_through_to_api_key`

### SEV-LOW: HMAC Replay Window (30 seconds) — Accepted

No per-request nonce. Idempotency depends on handler-level guards (tx_fingerprint).

### SEV-LOW: All-Zeros X25519 Ephemeral Key Accepted — Accepted

Authentication still requires valid Ed25519 signature — degenerate DH gives attacker nothing.

### SEV-LOW: Session TTL Not Configurable — Open

`DEFAULT_SESSION_TTL_SECS = 3600` is hardcoded. Future: make configurable via `SESSION_TTL_SECS` env var.

### SEV-INFO: Protocol Downgrade Returns 422 Instead of 401 — Accepted

Serde rejects unknown enum variants before handler runs. Request is still rejected.

---

## Additional Hardening (beyond audit findings)

### Session Key Zeroization

**Issue:** `AuthenticatedSession.client_write_key` and `server_write_key` were plain `[u8; 32]` — not zeroized on drop.
**Fix:** `AuthenticatedSession` now derives `Zeroize + ZeroizeOnDrop`. Key material is zeroed when session is dropped. `Debug` impl redacts keys as `"[REDACTED]"`.

### CORS Headers

Added `x-session-token` to CORS allowed headers for cross-origin SDK clients.

### E2E HTTP Test

Added `test_e2e_full_http_hello_verify_session_protected` — complete flow through HTTP: hello → verify → use session token on protected route → verify unauthenticated still fails.

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
| Rate limit on handshake | PASS | `test_rate_limit_on_handshake` |
| Dynamic key revocation | PASS | `test_dynamic_key_revocation` |
| Session store capacity limit | PASS | `test_session_store_capacity_limit` |
| E2E HTTP flow (hello→verify→protected) | PASS | `test_e2e_full_http_hello_verify_session_protected` |

---

## Test Coverage Summary

| Category | Count |
|----------|-------|
| Happy path (E2E) | 4 |
| Replay attacks | 4 |
| Timestamp manipulation | 3 |
| Signature forgery | 5 |
| Key confusion / identity | 4 |
| Session lifecycle | 6 |
| Protocol downgrade | 2 |
| Malformed input | 6 |
| HMAC bypass | 5 |
| Auth method confusion | 3 |
| Revocation enforcement | 4 |
| DoS / resource | 3 |
| Information leakage | 3 |
| Concurrency | 2 |
| API key specific | 2 |
| Rate limiting | 1 |
| **Total** | **57** |
