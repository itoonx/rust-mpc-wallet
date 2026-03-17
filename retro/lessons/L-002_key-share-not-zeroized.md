# L-002: KeyShare.share_data Vec<u8> Not Zeroized

- **Date:** 2026-03-15
- **Category:** Security
- **Severity:** High
- **Found by:** R6 during Sprint 3 audit
- **Related finding:** SEC-004

## What happened

`KeyShare.share_data` was stored as a plain `Vec<u8>`. When the struct was dropped, the secret bytes remained in memory until the allocator reused the pages. A memory dump could recover key shares.

## Root cause

Standard Rust `Vec<u8>` does not zero memory on drop. The `zeroize` crate was available in the workspace but not applied to this field.

## Fix

Sprint 4: Changed `share_data` to `Zeroizing<Vec<u8>>`. Also added a manual `Debug` impl that redacts share_data as `"[REDACTED]"` (SEC-015).

## Takeaway

All secret key material must use `Zeroizing<T>` wrappers. Never store cryptographic secrets in plain `Vec<u8>` or `String`. This applies to: key shares, passwords, ECDH shared secrets, derived session keys, HMAC keys.
