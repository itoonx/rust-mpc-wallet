# L-005: SessionStore Has No Size Limit

- **Date:** 2026-03-17
- **Category:** Security
- **Severity:** High
- **Found by:** Security audit (code review + auth_security_audit.rs)
- **Related finding:** SA-002

## What happened

`SessionStore` uses `HashMap<String, AuthenticatedSession>` with no size limit. No background task prunes expired sessions. `prune_expired()` exists but is never called automatically.

## Root cause

Initial implementation focused on correctness (store/get/revoke semantics) without considering operational scaling. The comment "Production deployments should back this with Redis" acknowledged the limitation but didn't add a safety net.

## Fix

Not yet fixed. Options:
1. `tokio::spawn` background task calling `prune_expired()` every 60s
2. Size cap on `store()` — reject new sessions when count > MAX + trigger prune
3. Both (belt and suspenders)

## Takeaway

Any in-memory cache without a size bound is a DoS vector. Always add:
- A maximum size (reject or evict when full)
- A background cleanup task for time-based expiry
- Metrics to monitor cache size in production
