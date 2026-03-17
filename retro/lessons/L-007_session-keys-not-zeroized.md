# L-007: Session Key Material Not Zeroized on Drop

- **Date:** 2026-03-17
- **Category:** Security
- **Severity:** High
- **Found by:** Security audit (code review)

## What happened

`AuthenticatedSession.client_write_key` and `server_write_key` were plain `[u8; 32]` arrays. When the struct was dropped, the 32-byte session keys remained in memory until the allocator reused the pages.

## Root cause

Same pattern as SEC-004 (KeyShare.share_data not zeroized). The `zeroize` crate was already in the workspace and used for KeyShare, but wasn't applied to the newer session key types.

## Fix

Added `#[derive(Zeroize, ZeroizeOnDrop)]` to `AuthenticatedSession`. Also added a custom `Debug` impl that redacts key material as `"[REDACTED]"`.

**Trade-off:** `ZeroizeOnDrop` implements `Drop`, which prevents Rust's `..struct_update` syntax. All struct updates must explicitly copy each field.

## Takeaway

Every time new key material is introduced (session keys, ECDH shared secrets, HKDF outputs), immediately check: is it `Zeroize`? Is `Debug` redacted? This should be part of the PR checklist for any crypto-related code. Same lesson as L-002 — zeroize ALL secret bytes, not just the ones you remember.
