# L-004: Non-UTF8 Header Bypasses Auth Priority — FIXED

- **Date:** 2026-03-17
- **Category:** Security
- **Severity:** Medium
- **Found by:** Security audit (auth_security_audit.rs)
- **Related finding:** SA-005
- **Status:** **FIXED** (2026-03-17)

## What happened

The auth middleware checks headers in priority order: `X-Session-Token` → `X-API-Key` → `Authorization: Bearer`. However, it used `.and_then(|v| v.to_str().ok())` to extract the session token value. If the header contained non-UTF8 bytes, `to_str()` returned `None`, and the middleware silently fell through to try API key auth.

## Root cause

The `if let Some(session_id) = headers.get("x-session-token").and_then(|v| v.to_str().ok())` pattern conflated "header not present" with "header present but unparseable".

## Fix

Changed to presence-based check:
```rust
if headers.contains_key("x-session-token") {
    let session_id = headers.get("x-session-token")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    // Empty/unparseable → 401 immediately, no fall-through
}
```

## Takeaway

When implementing auth priority chains, check for header **presence** separately from header **parsing**. A malformed auth header should fail immediately, not silently skip to the next auth method.
