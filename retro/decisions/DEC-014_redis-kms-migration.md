# DEC-014: Redis + KMS/HSM Migration

- **Date:** 2026-03-18
- **Status:** Decided + Phase 1-2 implemented
- **Context:** All auth state was in-memory — sessions, replay cache, revoked keys lost on restart. Server signing key in env var, not HSM. Horizontal scaling impossible.

## Decision

Trait-based backend architecture with pluggable implementations:

| Component | Trait | In-Memory | Redis |
|-----------|-------|-----------|-------|
| Sessions | `SessionBackend` | `InMemoryBackend` | `RedisSessionBackend` (encrypted) |
| Replay cache | `ReplayCacheBackend` | `InMemoryReplayBackend` | `RedisReplayBackend` (SET NX EX) |
| Revoked keys | `RevocationBackend` | `InMemoryRevocationBackend` | `RedisRevocationBackend` (SET) |
| Signing | `AuthSigner` | `LocalSigner` | `KmsSigner` (stub) |
| Key wrapping | `KeyEncryptionProvider` | `LocalKeyEncryption` | Future HSM |

## Key Design Choices

- **Session keys encrypted** before Redis storage (ChaCha20-Poly1305, Zeroizing KEK)
- **SCAN** instead of KEYS for Redis queries (non-blocking)
- **BackendType enum** (Memory | Redis) instead of string config
- **`from_config()` is async** to support Redis connection at startup
- Config: `SESSION_BACKEND=redis`, `REDIS_URL`, `SESSION_ENCRYPTION_KEY`

## Consequences

- All backends swappable via config — no code changes needed
- In-memory remains default for dev/test
- Redis required for horizontal scaling in production
- KMS/HSM integration ready via trait stubs
