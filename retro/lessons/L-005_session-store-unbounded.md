# L-005: SessionStore Has No Size Limit — FIXED

- **Date:** 2026-03-17
- **Category:** Security
- **Severity:** High
- **Found by:** Security audit (code review + auth_security_audit.rs)
- **Related finding:** SA-002
- **Status:** **FIXED** (2026-03-17)

## What happened

`SessionStore` used `HashMap<String, AuthenticatedSession>` with no size limit. No background task pruned expired sessions. `prune_expired()` existed but was never called automatically.

## Root cause

Initial implementation focused on correctness (store/get/revoke semantics) without considering operational scaling.

## Fix

Three-layer protection:
1. **Size cap:** `MAX_SESSIONS = 100,000` — `store()` returns `false` at capacity
2. **Lazy prune:** triggered at 50% capacity on every `store()` call
3. **Background prune:** `spawn_prune_task()` runs every 60 seconds

## Takeaway

Any in-memory cache without a size bound is a DoS vector. Always add: a maximum size, a background cleanup task, and metrics to monitor size.
