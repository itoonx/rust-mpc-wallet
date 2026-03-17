# DEC-011: Auth Production Hardening Architecture

- **Date:** 2026-03-17
- **Status:** Decided
- **Context:** Security audit (AUTH-AUDIT-001) found 2 HIGH and 3 MEDIUM findings blocking production. Need to resolve all without breaking existing tests or API contracts.

## Decisions Made

### Rate Limiting
- **Approach:** Per-key_id token-bucket in handler (not middleware layer)
- **Why not middleware:** `ConnectInfo` extractor requires `into_make_service_with_connect_info`, which isn't available in `oneshot()` tests. Handler-level rate limiting is testable without real TCP.
- **Config:** 10 req/sec per key_id (token bucket refills continuously)

### SessionStore Hardening
- **Size cap:** `MAX_SESSIONS = 100,000` — `store()` returns `false` at capacity
- **Lazy prune:** triggers at 50% capacity on every `store()` call
- **Background prune:** `spawn_prune_task()` runs `prune_expired()` every 60 seconds
- **Why three layers:** Lazy prune handles steady-state load; background prune catches idle expiration; size cap is the hard DoS limit

### Dynamic Revocation
- **Approach:** `revoked_keys` changed from `Arc<HashSet>` to `Arc<RwLock<HashSet>>`
- **Endpoint:** `POST /v1/auth/revoke-key` — adds key_id to set immediately
- **Impact:** `is_key_revoked()` is now async (acquires read lock). All callers updated to `.await`.

### Session Key Zeroization
- **Approach:** `AuthenticatedSession` derives `Zeroize + ZeroizeOnDrop`
- **Trade-off:** `ZeroizeOnDrop` implements `Drop`, which prevents `..struct_update` syntax. Callers must clone fields explicitly.
- **Debug:** Custom `Debug` impl redacts `client_write_key` and `server_write_key` as `"[REDACTED]"`.

### Auth Middleware (non-UTF8 fix)
- **Approach:** Check `headers.contains_key("x-session-token")` first (presence-based), then parse value. Empty or unparseable values return 401 immediately.
- **Why:** Original `.and_then(|v| v.to_str().ok())` pattern conflated "header absent" with "header present but malformed."

## Consequences
- `SessionStore::store()` now returns `bool` — callers must handle capacity rejection
- `is_key_revoked()` is now `async` — all call sites need `.await`
- Integration tests construct `revoked_keys` with `Arc::new(RwLock::new(set))`
- `AuthenticatedSession` struct updates require explicit field construction (no `..session` shorthand)
