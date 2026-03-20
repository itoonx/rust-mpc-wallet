# Session Retro — Sprint 28: Paillier Performance Fix

**Date:** 2026-03-20
**Duration:** ~1 session
**Branch:** `dev`

---

## What Was Done

### Problem
`num-bigint` (pure Rust) was catastrophically slow for Paillier safe prime generation:
- 512-bit safe prime: **8+ min** per keypair (should be ~100ms)
- 3 parties × keygen = 25+ minutes per test
- Caused heap corruption under heavy concurrent allocation
- CI Build & Test ballooned to 19 min (was 2.5 min)
- All timeouts had to be inflated (30s→300s, 60s→300s, 10min→20min)
- Paillier ZK proofs were **skipped** in protocol tests (dummy keys)

### Solution
1. **Replaced `num-bigint` prime gen with `glass_pumpkin`** — pure Rust, Apache-2.0, ~200ms for 512-bit safe prime
2. **Added `test_keypair()`** — cached 512-bit keypair via `std::sync::LazyLock`, reused across all tests
3. **Removed all skip hacks** — `skip_real_paillier`, `skip_gg20_paillier`, `skip_refresh_paillier` eliminated from cggmp21.rs and gg20.rs
4. **Reverted inflated timeouts** — SignedEnvelope TTL 300s→30s, E2E deadlines 300s→60s, CI timeout 20min→10min

### Files Modified
| File | Change |
|------|--------|
| `Cargo.toml` | Added `glass_pumpkin = "1"` |
| `crates/mpc-wallet-core/Cargo.toml` | Added `glass_pumpkin` |
| `crates/mpc-wallet-core/src/paillier/keygen.rs` | `generate_safe_prime()` uses glass_pumpkin, added `test_keypair()` |
| `crates/mpc-wallet-core/src/protocol/cggmp21.rs` | Removed skip hacks (keygen + refresh), uses `test_keypair()` |
| `crates/mpc-wallet-core/src/protocol/gg20.rs` | Removed skip hack, uses `test_keypair()` |
| `crates/mpc-wallet-core/src/transport/signed_envelope.rs` | TTL 300s → 30s |
| `crates/mpc-wallet-core/tests/e2e/distributed.rs` | Deadlines 300s → 60s |
| `.github/workflows/ci.yml` | E2E timeout 20min → 10min |

---

## Results

| Metric | Before | After |
|--------|--------|-------|
| 512-bit safe prime | 8+ min | ~200ms |
| Test run (full workspace) | ~19 min | ~2.5 min |
| Total tests | 793 | 801 |
| Clippy | clean | clean |
| SignedEnvelope TTL | 300s (inflated) | 30s (original) |
| E2E keygen deadline | 300s (inflated) | 60s (original) |
| CI E2E timeout | 20min (inflated) | 10min (original) |
| Heap corruption (--test-threads=4) | yes | no |
| Paillier ZK proofs in tests | skipped (dummy keys) | **real keys, fully verified** |

---

## Decisions Made

### DEC: Use `glass_pumpkin` over `rug`/GMP
- **Why not `rug`/GMP:** Requires system C library (libgmp-dev), complicates CI/Docker/cross-compilation, LGPL license
- **Why `glass_pumpkin`:** Pure Rust, no C deps, Apache-2.0/MIT, uses Baillie-PSW test, ~200ms for 512-bit safe prime
- **Trade-off:** 1024-bit safe prime takes ~10s (vs ~100ms with GMP), acceptable for production keygen which happens rarely

### DEC: `test_keypair()` via LazyLock (not lazy_static)
- `std::sync::LazyLock` is stabilized in Rust 1.80+, no extra dependency needed
- Already used throughout the codebase (paillier/mod.rs, zk_proofs.rs, mta.rs)

### DEC: Keep `is_probable_prime()` for `is_prime()` public API
- `is_prime()` is used by ZK proof verification code
- Could switch to `glass_pumpkin::safe_prime::check()` later, but Miller-Rabin is fine for verification

---

## Lessons Learned

### L-018: Don't Inflate Timeouts to Work Around Slow Algorithms
The correct fix for "algorithm is too slow" is to fix the algorithm, not inflate every timeout in the system. Inflated timeouts mask real bugs and make CI unreliable.

### L-019: Pure Rust != Production Grade Without Benchmarking
`num-bigint` is a perfectly fine BigUint library, but its modpow is not optimized for repeated primality testing. The lesson: always benchmark crypto operations before assuming they're fast enough.

### L-020: Skip Hacks Accumulate Technical Debt Fast
The `skip_real_paillier` pattern meant tests were passing without actually testing the Paillier proof flow. This created a false sense of security — the proofs could have been broken and no test would catch it.

---

## What Went Well
- Single-session fix: identified problem, chose solution, implemented, verified
- 801 tests pass including all Paillier ZK proofs (previously skipped)
- No heap corruption with `--test-threads=4`
- `glass_pumpkin` API was a drop-in replacement for `generate_safe_prime()`

## What Could Be Improved
- Should have benchmarked `num-bigint` safe prime gen before using it in Sprint 27a
- The skip hacks should never have been introduced — `test_keypair()` pattern was always available
- `glass_pumpkin` uses `rand_core` 0.10 while project uses `rand` 0.8 — had to use `new()` instead of `from_rng()`. Consider upgrading `rand` in future.

## Next Steps
- Wire real Paillier MtA into CGGMP21 pre-signing (`has_real_paillier = false` at cggmp21.rs:1093)
- R6 audit before merge to main
- Consider upgrading `rand` 0.8 → 0.9+ to align with `glass_pumpkin`'s `rand_core` 0.10
