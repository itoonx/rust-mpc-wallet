# MPC Wallet SDK -- Audit Scope

> Maintained by R6 Security | Last updated: 2026-04-01

This document defines what is in-scope and out-of-scope for security audits of the Vaultex MPC Wallet SDK. All line counts are as of the latest `dev` branch.

## In-Scope (Critical Priority)

### Cryptographic Core (crates/mpc-wallet-core/src/)

| File | Lines | Description |
|------|-------|-------------|
| `protocol/cggmp21.rs` | 3,955 | CGGMP21 threshold ECDSA: keygen (Feldman VSS, Schnorr PoK, commit-reveal), pre-signing (MtA with real Paillier, Chi_i Schnorr PoK), online 1-round signing, identifiable abort |
| `protocol/gg20.rs` | 1,896 | GG20 threshold ECDSA: distributed MtA signing, key refresh, key resharing |
| `protocol/stark.rs` | 1,592 | Stark threshold ECDSA: Feldman VSS over Stark field, MtA-based pre-signing, PiLogStarStark + PiAffgStark ZK proofs |
| `protocol/frost_ed25519.rs` | 487 | FROST threshold Schnorr for Ed25519 (keygen, signing, refresh) |
| `protocol/frost_secp256k1.rs` | 544 | FROST threshold Schnorr for Secp256k1/Taproot (keygen, signing, refresh) |
| `paillier/zk_proofs.rs` | 3,262 | All ZK proofs: Pimod (Blum integer), Pifac (no small factor), Pienc (range), PiAffg (MtA correctness), PiLogstar (DL consistency), Stark variants (PiLogStarStark, PiAffgStark) |
| `paillier/keygen.rs` | 436 | Safe prime generation, 2048-bit minimum enforcement (SEC-054), keypair_for_protocol() |
| `paillier/mta.rs` | 433 | Multiplicative-to-Additive sub-protocol with real Paillier encryption |
| `paillier/mod.rs` | 329 | Paillier encrypt/decrypt/homomorphic operations |
| `transport/signed_envelope.rs` | 289 | Ed25519 SignedEnvelope: message authentication, monotonic seq_no, TTL expiry |
| `key_store/encrypted.rs` | 508 | AES-256-GCM + Argon2id (64MiB/3t/4p) key share encryption at rest |
| `protocol/sign_authorization.rs` | 679 | SignAuthorization: Ed25519-signed gateway proof, MPC node independent verification |

### Services (services/)

| File | Lines | Description |
|------|-------|-------------|
| `api-gateway/src/auth/handshake.rs` | -- | Server-side X25519 + Ed25519 handshake state machine |
| `api-gateway/src/auth/session.rs` | -- | SessionBackend trait, InMemoryBackend, SessionStore facade |
| `api-gateway/src/auth/session_redis.rs` | -- | Redis session backend with ChaCha20-Poly1305 encryption |
| `api-gateway/src/auth/session_jwt.rs` | -- | Session JWT creation and verification (HS256) |
| `api-gateway/src/auth/mtls.rs` | -- | mTLS service registry and identity extraction |
| `api-gateway/src/auth/types.rs` | -- | AuthenticatedSession (Zeroize + ZeroizeOnDrop), transcript hashing |
| `api-gateway/src/middleware/auth.rs` | -- | 3-method auth middleware (mTLS -> Session JWT -> Bearer JWT), fail-fast on present-but-invalid |
| `api-gateway/src/middleware/rate_limit.rs` | -- | Token-bucket rate limiter (per-key) |
| `mpc-node/src/main.rs` | 1,413 | MPC node: NATS handlers, per-group-id rate limiting, signed message unwrapping, GATEWAY_PUBKEY validation |

### Critical Security Properties to Verify

1. **No full key reconstruction** -- the complete private key `x = sum(x_i)` is NEVER computed anywhere in any protocol path.
2. **Gateway holds zero shares** -- MpcOrchestrator has no WalletStore, no key material (DEC-015).
3. **ZK proofs mandatory** -- Pimod, Pifac verified for all peers during keygen; Pienc, PiAffg, PiLogstar verified during pre-signing. No conditional bypass.
4. **Legacy share rejection** -- `has_real_paillier` check rejects legacy shares unconditionally in pre-signing (no simulated MtA fallback).
5. **Nonce single-use** -- PreSignature `used` flag + FilePreSignatureStore mark-before-use with fsync.
6. **Identifiable abort soundness** -- Chi_i Schnorr PoK prevents framing; K_i points stored for abort verification.
7. **TSSHOCK hardening** -- All Fiat-Shamir hashes use length-prefixed encoding; session_id + prover_index bound into challenges.
8. **Control plane authentication** -- All control messages Ed25519-signed; unsigned paths deleted.
9. **Secret zeroization** -- All secret scalars, Paillier keys, passwords, session keys use Zeroize/ZeroizeOnDrop.
10. **Auth fail-fast** -- Present-but-invalid credentials cause immediate rejection, no fallthrough to next method.

## Out-of-Scope

| Component | Reason |
|-----------|--------|
| `crates/mpc-wallet-chains/` | Chain adapters (tx building, address derivation). Application logic, not cryptographic security. Low-S normalization (SEC-012) and Taproot sighash (SEC-009) fixes already audited. |
| `crates/mpc-wallet-cli/` | Demo CLI only. Not shipped in production. |
| `services/api-gateway/src/routes/` | HTTP route handlers. Application logic, not crypto. Auth middleware (in-scope) protects all routes. |
| `docs/`, `specs/`, `retro/` | Documentation and specifications. No executable code. |
| `infra/`, `scripts/`, `.github/` | Deployment tooling and CI configuration. |
| Third-party dependencies | Covered by `cargo audit` with 6 suppressed advisories for unmaintained transitive deps (see `.cargo/audit.toml`). |
| SGX enclave integration | Prototype only (MockEnclaveProvider). Not production-hardened. |
| KMS signer | Stub only (KmsSigner placeholder). Ed25519 signing stays local per DEC-016. |

## Audit Logistics

| Item | Value |
|------|-------|
| Language | Rust 1.93+ |
| Build | `cargo build --workspace` |
| Test | `cargo test --workspace` (919 tests pass, 45 ignored/E2E) |
| Lint | `cargo clippy --workspace -- -D warnings` (0 warnings) |
| Format | `cargo fmt --all -- --check` (clean) |
| Dependency audit | `cargo audit` (clean, 6 suppressed transitive advisories) |
| Security findings | 68 total (SEC-001 through SEC-060), all resolved |
| Open CRITICAL/HIGH | 0 |

## Audit History

| Date | Scope | Auditor | Result |
|------|-------|---------|--------|
| Sprint 16 | DEC-015 gateway/node split | R6 | APPROVED (SEC-025..031 filed) |
| Sprint 17-18 | Security hardening + control plane | R6 | APPROVED (all Sprint 17 checklist verified) |
| Sprint 21 | CGGMP21 integration | R6 | APPROVED (2 MEDIUM, 3 LOW, 5 INFO) |
| Sprint 23 | SGX prototype | R6 | APPROVED |
| Sprint 29 | TSSHOCK + PiAffg EC binding | R6 | 5 MEDIUM resolved |
| Sprint 30 | All P1/P2 findings closure | R6 | All 68 findings resolved |
| Sprint 31 | Chi_i Schnorr PoK + Stark threshold | R6 | Current review |
