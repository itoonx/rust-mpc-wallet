# DEC-010: Split api-gateway into lib + bin

- **Date:** 2026-03-17
- **Status:** Decided
- **Context:** Need to write integration tests for the auth system. Rust integration tests (in `tests/`) require a library crate — they cannot import from a binary crate.
- **Options:**
  1. Keep all tests in `main.rs` `#[cfg(test)]` — works but tests are tightly coupled to binary
  2. Split into `lib.rs` (public modules) + `main.rs` (entry point) — standard Rust pattern
- **Decision:** Option 2. Created `src/lib.rs` with all public modules and `build_router()`. `main.rs` just calls library functions.
- **Consequences:**
  - Integration tests in `tests/auth_security_audit.rs` can `use mpc_wallet_api::*`
  - Internal modules (`config`, `middleware`, `state`, etc.) are now `pub`
  - `hmac_key` field in AppState changed from private to public for test access
  - `AppConfig::for_test()` changed from `#[cfg(test)]` to `#[doc(hidden)]`
  - Added `Default` impls for `ClientKeyRegistry`, `ReplayCache`, `Metrics` (clippy requirement after pub visibility)
