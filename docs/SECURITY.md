# Security

## Threat Model

Vaultex assumes **honest-but-curious** adversaries:

- Any `t-1` parties can collude without compromising the key
- The coordinator (Party 1 in GG20) holds the ephemeral nonce `k`
- Transport is authenticated (SignedEnvelope) and encrypted (ECDH + TLS)

## Cryptographic Hardening

| Layer | Algorithm | Parameters |
|-------|-----------|-----------|
| Key Derivation | Argon2id | 64 MiB / 3 iterations / 4 parallelism |
| Encryption at Rest | AES-256-GCM | 32-byte random salt, 12-byte random nonce |
| Encryption in Transit | ChaCha20-Poly1305 | Per-session X25519 ECDH + HKDF-SHA256 |
| Message Authentication | Ed25519 SignedEnvelope | Monotonic seq_no + 30s TTL |
| Transport | rustls mTLS | TLS 1.2+, mutual certificate auth |
| Memory | Zeroizing | All key material wiped on drop |

## Findings Summary (as of v0.1.0)

| Severity | Resolved | Open |
|----------|----------|------|
| CRITICAL | 4 | 0 |
| HIGH | 8 | 0 |
| MEDIUM/LOW | ~15 | Non-blocking |

### CRITICAL (all resolved)

| ID | Issue | Resolution | Sprint |
|----|-------|-----------|--------|
| SEC-001 | GG20 reconstructed full private key | Gated behind feature flag; real distributed ECDSA | S2 |
| SEC-002 | Hardcoded demo-password | Interactive rpassword prompt | S2 |
| SEC-003 | NatsTransport all todo stubs | Real async-nats implementation | S3 |
| SEC-011 | Sui tx was JSON stub | Full BCS encoding | S2 |

### HIGH (all resolved)

| ID | Issue | Resolution | Sprint |
|----|-------|-----------|--------|
| SEC-004 | KeyShare not zeroized | Zeroizing root fix | S4 |
| SEC-005 | Password not zeroized | Zeroizing String | S3 |
| SEC-006 | Weak Argon2 params | 64MiB/3t/4p | S3 |
| SEC-007 | Unauthenticated messages | SignedEnvelope Ed25519 + seq_no | S6 |
| SEC-009 | Taproot empty script_pubkey | Require prev_script_pubkey | S5 |
| SEC-012 | EVM high-S not normalized | Auto-normalize via n-s | S6 |
| SEC-015 | Debug leaks share bytes | Manual Debug with REDACTED | S4 |
| SEC-016 | Bitcoin unwrap panic | Proper error propagation | S5 |

Full findings log with details: [SECURITY_FINDINGS.md](SECURITY_FINDINGS.md)

## Responsible Disclosure

Found a vulnerability? Please email the maintainer directly. Do **not** open a public issue for security bugs.
