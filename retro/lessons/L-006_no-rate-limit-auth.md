# L-006: No Rate Limiting on Auth Endpoints

- **Date:** 2026-03-17
- **Category:** Security
- **Severity:** High
- **Found by:** Security audit (code review)
- **Related finding:** SA-001

## What happened

Rate limiter middleware exists (`middleware/rate_limit.rs`) with a token-bucket implementation, but it is **not wired** to any routes. Auth endpoints `/v1/auth/hello` and `/v1/auth/verify` can be called without throttling.

## Root cause

The rate limiter was implemented but never integrated into the router in `build_router()`. Likely deferred during initial development and forgotten.

## Fix

Not yet fixed. Need to add rate limiter layer to auth routes:
```rust
let auth_routes = Router::new()
    .route("/v1/auth/hello", post(routes::auth::auth_hello))
    .route("/v1/auth/verify", post(routes::auth::auth_verify))
    // ... other routes
    .layer(rate_limit_layer)  // <-- ADD THIS
    .with_state(auth_state);
```

Spec requires: 10 req/min per IP on handshake, 5/min per key_id.

## Takeaway

Always verify that security middleware is actually **wired**, not just **implemented**. Code review should check the router setup, not just the middleware logic. A test like "send 20 rapid handshakes, verify later ones are throttled" would catch this.
