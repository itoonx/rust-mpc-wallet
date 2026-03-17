# AUTH-AUDIT-001: Auth System Security Audit

- **Date:** 2026-03-17
- **Scope:** `services/api-gateway/src/auth/`, routes, middleware, HMAC
- **Method:** Code review + 57 automated attack tests
- **Full report:** `docs/SECURITY_AUDIT_AUTH.md`
- **Test file:** `services/api-gateway/tests/auth_security_audit.rs`

## Summary

No critical vulnerabilities. Protocol correctly implements mutual authentication, forward secrecy, and transcript binding. All HIGH and MEDIUM findings resolved.

57 security tests pass covering 16 attack categories.

## Findings

| Sev | ID | Finding | Status |
|-----|----|---------|--------|
| HIGH | SA-001 | No rate limiting on auth endpoints | **FIXED** — token-bucket 10 req/sec per key_id |
| HIGH | SA-002 | SessionStore unbounded | **FIXED** — 100k cap + lazy prune + background prune (60s) |
| MED | SA-003 | Client registry optional (open enrollment) | **FIXED** — WARN log on mainnet |
| MED | SA-004 | Revocation static only (requires restart) | **FIXED** — `POST /v1/auth/revoke-key` + RwLock |
| MED | SA-005 | Non-UTF8 header bypasses auth priority | **FIXED** — presence-based check, no fall-through |
| LOW | SA-006 | HMAC 30s replay window | Accepted |
| LOW | SA-007 | All-zeros X25519 ephemeral key accepted | Accepted |
| LOW | SA-008 | Session TTL hardcoded at 3600s | Open (low priority) |
| INFO | SA-009 | Unknown algorithm enum → 422 not 401 | Accepted |

## Additional Hardening

| Item | Status |
|------|--------|
| Session key zeroization (Zeroize+ZeroizeOnDrop) | **FIXED** |
| Session Debug redacts key material | **FIXED** |
| CORS x-session-token header | **FIXED** |
| E2E HTTP test (hello→verify→protected) | **ADDED** |
