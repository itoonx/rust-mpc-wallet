# Session Retrospective — Auth System Build

**Dates:** 2026-03-17 ~ 2026-03-18
**Scope:** Complete auth system for Vaultex MPC Wallet API Gateway
**Commits:** ~30
**Net lines:** +5,000
**Release:** v0.2.0

---

## 1. What We Built (Timeline)

### Day 1 — 2026-03-17: Foundation + Hardening

| Order | Deliverable | Key Detail |
|-------|-------------|------------|
| 1 | Auth security audit | 53 initial tests, refined to 46 passing; produced AUTH-AUDIT-001 findings report |
| 2 | Production hardening | Token-bucket rate limiter, session cap (10k default), Zeroize+ZeroizeOnDrop on session keys, dynamic key revocation via RwLock |
| 3 | API key store | Built `ApiKeyStore` with hashed keys + RBAC scopes |
| 4 | Sign Authorization | `SignAuthorization` — Ed25519-signed proof; MPC nodes independently verify before participating (DEC-012) |
| 5 | Encrypted request context | `EncryptedRequestContext` for audit trail; `SignTimeline` for tracking sign flow stages |
| 6 | Session JWT | HS256 JWT signed with key-exchange derived key; per-request session binding |
| 7 | Auth gap analysis + fixes | Revoke-key endpoint behind auth; configurable SESSION_TTL; mainnet safety checklist |

### Day 2 — 2026-03-18: mTLS, Simplification, Redis

| Order | Deliverable | Key Detail |
|-------|-------------|------------|
| 8 | mTLS for service-to-service | `MtlsServiceRegistry` + `MtlsIdentity`; cert CN extraction; highest auth priority |
| 9 | Remove API keys (DEC-013) | Deleted 3 files; simplified to 3 auth methods (mTLS > Session JWT > Bearer JWT) |
| 10 | Redis + KMS/HSM traits (DEC-014) | `SessionBackend`, `ReplayCacheBackend`, `RevocationBackend` traits; `BackendType` enum config |
| 11 | Real Redis integration | `RedisSessionBackend` with ChaCha20-Poly1305 encrypted sessions; `ConnectionManager` pooling; SCAN (not KEYS) |
| 12 | Docs sync | All markdown updated to reflect 3-method auth, Redis backends, no API keys |
| 13 | 3x /simplify reviews | Caught `block_on()` in async, legacy dual storage, KEYS command, dead code |

### Files Created (~15 new Rust files)

```
services/api-gateway/src/auth/session_jwt.rs
services/api-gateway/src/auth/session.rs
services/api-gateway/src/auth/session_redis.rs
services/api-gateway/src/auth/redis_backend.rs
services/api-gateway/src/auth/mtls.rs
services/api-gateway/src/auth/signer.rs
services/api-gateway/src/auth/kms_signer.rs
services/api-gateway/src/auth/client.rs
services/api-gateway/src/middleware/rate_limit.rs
services/api-gateway/src/config.rs
services/api-gateway/tests/auth_security_audit.rs
crates/mpc-wallet-core/src/protocol/sign_authorization.rs
specs/AUTH_SPEC.md
specs/SIGN_AUTHORIZATION_SPEC.md
specs/REDIS_KMS_MIGRATION_SPEC.md
```

### Files Deleted (3 — API key system)

```
services/api-gateway/src/auth/api_key.rs
services/api-gateway/src/auth/api_key_store.rs
services/api-gateway/src/middleware/api_key.rs    (or equivalent)
```

---

## 2. What Went Well

### Security-first methodology
Every feature followed the **audit > fix > verify** cycle. The initial security audit (AUTH-AUDIT-001) found real issues — non-UTF8 header bypass, unbounded session store, missing rate limits, unzeroized keys — and all were fixed before moving to new features.

### /simplify reviews caught real production issues
Three review passes caught approximately 10 real issues:
- **`block_on()` in async middleware** — would deadlock the Tokio runtime under load
- **Legacy dual storage** — old in-memory path still active after Redis backend was added
- **`KEYS *` command** — blocks Redis single-thread on large datasets; replaced with `SCAN`
- **Dead code** from removed API key system still lingering

### Trait-based architecture
`SessionBackend`, `ReplayCacheBackend`, `RevocationBackend`, `AuthSigner`, `KeyEncryptionProvider` — all trait-based. Swapping from in-memory to Redis required zero changes to middleware or route handlers. KMS/HSM can be added the same way.

### Clear auth method separation
Each method serves exactly one use case:
- **mTLS** = machine-to-machine (service-to-service, highest trust)
- **Session JWT** = app-to-server (key-exchange derived, forward secrecy)
- **Bearer JWT** = human-to-system (IdP-issued, standard OAuth2)

### Forward secrecy from day 1
X25519 ephemeral key exchange with HKDF derivation. Session keys use `Zeroize + ZeroizeOnDrop`. Compromise of a future key doesn't expose past sessions.

---

## 3. What We'd Do Differently

### API key system was built then completely removed
Built `ApiKeyStore` with hashed keys, RBAC scopes, and middleware on day 1 — then removed the entire subsystem on day 2 (DEC-013). mTLS covers the same use case (service-to-service auth) with stronger security guarantees. **Lesson:** Evaluate whether a simpler, stronger mechanism already covers the use case before building a new auth method.

### Cross-verify (IP/UA matching) was added then removed
IP address and User-Agent binding for sessions sounded good in theory but caused problems with proxies, load balancers, and mobile clients switching networks. **Lesson:** Session binding should use cryptographic proof (the key-exchange derived key), not network metadata.

### block_on() in async middleware wasn't caught until /simplify
This would have caused deadlocks under production load. It compiled and passed tests because the test runtime had enough threads. **Lesson:** Run `/simplify` after every major feature merge, not just at the end.

### KEYS command shipped and caught in review
Redis `KEYS *` is O(n) and blocks the single-threaded Redis server. Shipped in the initial Redis integration, caught in the third `/simplify` pass. **Lesson:** Default to `SCAN` for any Redis enumeration; treat `KEYS` as a code review red flag.

---

## 4. Key Decisions Made

| ID | Decision | Rationale |
|----|----------|-----------|
| DEC-010 | Split api-gateway into `lib.rs` + `main.rs` | Integration tests need access to `build_router()` without starting the binary |
| DEC-011 | Auth production hardening architecture | Rate limit + session cap + dynamic revocation + zeroize — defense in depth |
| DEC-012 | MPC node independent verification (`SignAuthorization`) | Gateway is single point of trust; nodes must verify proof before participating in signing |
| DEC-013 | Remove API keys, simplify to 3 auth methods | mTLS is strictly stronger for service-to-service; API keys add attack surface without adding capability |
| DEC-014 | Redis + KMS/HSM trait-based migration | Trait backends enable in-memory for dev, Redis for staging/prod, HSM for high-security — same code path |

### Design patterns that emerged
- **Priority chain with fail-fast:** If a header is present but invalid, auth fails immediately — no fall-through to weaker methods
- **Encrypted-at-rest sessions:** ChaCha20-Poly1305 with a KEK before Redis storage — Redis compromise doesn't expose session data
- **`BackendType` enum config:** `Memory` or `Redis` selected via `SESSION_BACKEND` env var; no string parsing in business logic

---

## 5. Metrics

| Metric | Value |
|--------|-------|
| Duration | 2 days |
| Commits | ~30 |
| Tests (before) | 325 |
| Tests (after) | 472 (+147) |
| Net lines added | ~5,000 |
| New Rust files | ~15 |
| Deleted files | 3 (API key system) |
| /simplify reviews | 3 |
| Issues caught by /simplify | ~10 |
| Security findings (new) | 4 (L-004 through L-007, all fixed) |
| Architectural decisions | 5 (DEC-010 through DEC-014) |
| Release | v0.2.0 |

---

## 6. Open Items / Next Steps

### Production readiness

| Item | Priority | Detail |
|------|----------|--------|
| Wire KmsSigner to AWS KMS | High | `KmsSigner` is a stub returning `Unimplemented`; needs real `aws-sdk-kms` calls |
| Wire HSM key wrapping | High | `KeyEncryptionProvider` trait ready; needs PKCS#11 or CloudHSM backend |
| Deploy Redis | High | `RedisSessionBackend` tested locally; needs prod Redis with TLS + auth |
| TLS termination config | Medium | nginx/envoy config for mTLS certificate validation at the edge |
| Monitoring + alerting | Medium | Auth failure rates, session counts, rate limit hits — Prometheus metrics |

### Integration

| Item | Priority | Detail |
|------|----------|--------|
| Gateway-to-MPC-node sign flow | High | `SignAuthorization` is built but the gateway-to-node transport is still stubbed |
| End-to-end auth integration test | Medium | Full flow: mTLS handshake > sign request > MPC node verification |
| Load testing | Medium | Verify rate limiter and session cap under sustained traffic |

### Cleanup

| Item | Priority | Detail |
|------|----------|--------|
| Remove any remaining API key references | Low | Grep for `api_key` / `ApiKey` across all docs and comments |
| Consolidate session TTL defaults | Low | Currently set in multiple places; should be single source of truth |

---

## Appendix: Security Findings from This Session

| ID | Severity | Title | Status |
|----|----------|-------|--------|
| L-004 | Medium | Non-UTF8 header bypasses auth priority chain | Fixed (Sprint 13) |
| L-005 | High | SessionStore has no size limit (memory exhaustion) | Fixed (Sprint 13) |
| L-006 | High | No rate limiting on auth endpoints (brute force) | Fixed (Sprint 13) |
| L-007 | High | Session key material not zeroized on drop | Fixed (Sprint 13) |

Full audit report: [AUTH-AUDIT-001](security/AUTH-AUDIT-001.md)
