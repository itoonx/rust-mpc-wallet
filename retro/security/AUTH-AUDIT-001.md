# AUTH-AUDIT-001: Auth System Security Audit

- **Date:** 2026-03-17
- **Scope:** `services/api-gateway/src/auth/`, routes, middleware, HMAC
- **Method:** Code review + 53 automated attack tests
- **Full report:** `docs/SECURITY_AUDIT_AUTH.md`
- **Test file:** `services/api-gateway/tests/auth_security_audit.rs`

## Summary

No critical vulnerabilities found that allow authentication bypass. Protocol correctly implements mutual authentication, forward secrecy, and transcript binding.

53 security tests pass covering 15 attack categories.

## Findings

| Sev | ID | Finding | Status |
|-----|----|---------|--------|
| HIGH | SA-001 | No rate limiting on auth endpoints | Open |
| HIGH | SA-002 | SessionStore unbounded (no size limit, no background prune) | Open |
| MED | SA-003 | Client registry optional (open enrollment without CLIENT_KEYS_FILE) | Open |
| MED | SA-004 | Revocation static only (no hot-reload, requires restart) | Open |
| MED | SA-005 | Non-UTF8 X-Session-Token header bypasses auth priority check | Open |
| LOW | SA-006 | HMAC 30s replay window (no per-request nonce) | Accepted |
| LOW | SA-007 | All-zeros X25519 ephemeral key accepted | Accepted |
| LOW | SA-008 | Session TTL hardcoded at 3600s | Open |
| INFO | SA-009 | Unknown algorithm enum → 422 instead of 401 | Accepted |

## Verified Properties

- Forward secrecy (unique ephemeral keys per session)
- Mutual authentication (Ed25519 transcript signatures)
- Replay protection (nonce cache + challenge consumption)
- Timestamp drift enforcement (±30s)
- Signature forgery/substitution rejected
- Key ID spoofing rejected
- HMAC body/path tamper detected
- Constant-time API key comparison
- Generic error messages (no info leak)
- Session revocation and expiry work correctly
- Concurrent handshakes are isolated

## Recommendations (Priority Order)

1. Wire rate limiter to `/v1/auth/hello` and `/v1/auth/verify`
2. Add background session pruning task or size cap
3. Log WARN at startup if client registry empty on mainnet
4. Add `POST /v1/admin/revoke-key` for dynamic revocation
5. Fix non-UTF8 header edge case in auth middleware
