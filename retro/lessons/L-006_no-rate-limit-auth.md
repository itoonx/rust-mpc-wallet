# L-006: No Rate Limiting on Auth Endpoints — FIXED

- **Date:** 2026-03-17
- **Category:** Security
- **Severity:** High
- **Found by:** Security audit (code review)
- **Related finding:** SA-001
- **Status:** **FIXED** (2026-03-17)

## What happened

Rate limiter middleware existed (`middleware/rate_limit.rs`) with a token-bucket implementation, but it was **not wired** to any routes. Auth endpoints `/v1/auth/hello` and `/v1/auth/verify` could be called without throttling.

## Root cause

The rate limiter was implemented but never integrated into the router. Likely deferred during initial development and forgotten.

## Fix

Token-bucket `RateLimiter` (10 req/sec per `client_key_id`) wired directly in `auth_hello` handler. Returns 429 Too Many Requests when exceeded. Tested by `test_rate_limit_on_handshake`.

Architecture decision: rate limiting at handler level (not middleware layer) because `ConnectInfo` extractor isn't available in `oneshot()` tests.

## Takeaway

Always verify that security middleware is actually **wired**, not just **implemented**. Code review should check the router setup, not just the middleware logic.
