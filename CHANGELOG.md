# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.3.0] - 2026-03-19 (Sprint 17: Security Hardening)

### Fixed

- SEC-008: GG20 secret scalars explicitly zeroized in keygen, sign, refresh, reshare (R1)
- SEC-013: FROST protocols validate `from` field against expected signer set (R1)
- SEC-014: `LocalTransport` gated behind `#[cfg(any(test, feature = "demo"))]` feature flag (R2)
- SEC-017: Solana tx builder validates `from` address matches signing pubkey (R3c)
- SEC-019: `quinn-proto` confirmed at patched 0.11.14 + `cargo update` applied (R0)
- SEC-023: Sui invalid hex validation test added (R3d)
- SEC-025: `GATEWAY_PUBKEY` mandatory in mpc-node — startup rejects without it (R2)

### Added

- `authorization_id` field in SignAuthorization for replay deduplication (R1)
- 10 security regression tests covering all Sprint 17 fixes (R5)

### Changed

- `async-nats` audit documented as mitigated (SEC-018) — `rustls-pemfile` transitive dep tracked (R2)
- Test count: 507 -> 540 (33 new tests)

## [0.2.0] - 2026-03-18 (Sprint 16: NATS Control Plane + Chain Tests)

### Added

- FROST Ed25519 keygen over NATS with broadcast fix in `nats.rs` (R1)
- Request-Reply control plane for orchestrator, mpc-node, and RPC modules (R2)
- 14 new chain simulation tests: Substrate, TON, TRON, Monero (R3)
- Real `SignAuthorization` wired in gateway sign route — gateway creates Ed25519-signed proof (R4)
- All E2E tests re-enabled in CI with request-reply pattern (R5)

### Security

- DEC-015 security audit by R6 — APPROVED verdict
- SEC-025 through SEC-031 filed (3 MEDIUM, 4 LOW, 2 INFO)
- No CRITICAL or HIGH findings in production architecture

### Fixed

- NATS URL parsing fix for connection reliability (R2)

## [0.1.0] - 2026-03-16

### Added

**Core MPC Protocols**
- GG20 threshold ECDSA — distributed signing without key reconstruction
- FROST Ed25519 — threshold EdDSA for Solana/Sui
- FROST Secp256k1-Taproot — threshold Schnorr for Bitcoin
- Key refresh for all 3 protocols (proactive share rotation)
- Key resharing — change threshold, add/remove parties (GG20 + FROST)

**Chain Support**
- EVM: Ethereum, Polygon, BSC — EIP-1559 transactions, EIP-55 addresses
- Bitcoin: Mainnet, Testnet — Taproot (P2TR), BIP-340 Schnorr
- Solana: Legacy + v0 versioned transactions with Address Lookup Tables
- Sui: Full BCS encoding with intent prefix
- Transaction simulation with risk scoring for all 4 chains
- ChainRegistry — unified provider factory

**Enterprise Controls**
- RBAC: initiator / approver / admin roles
- ABAC: department, cost center, risk tier from JWT claims
- MFA: step-up enforcement for admin actions
- Policy engine: allowlists, per-tx limits, daily velocity, signed bundles
- Policy templates: Exchange, Treasury, Custodian presets
- Approval workflow: M-of-N quorum, maker/checker/approver SoD
- Audit ledger: hash-chained, Ed25519 signed, evidence pack export

**Transport & Security**
- NATS transport with async-nats
- mTLS with rustls — mutual certificate authentication
- Per-session ECDH (X25519) + ChaCha20-Poly1305 encryption
- SignedEnvelope: Ed25519 + monotonic seq_no + TTL replay protection
- JetStream configuration + per-party ACL
- Encrypted key store: AES-256-GCM + Argon2id (64MiB/3t/4p)
- All key material wrapped in `Zeroizing<Vec<u8>>`

**Identity & Access**
- JWT validation: RS256, ES256, HS256
- ABAC attributes from JWT claims
- MFA step-up for admin operations

**Operations**
- Multi-cloud node distribution constraints
- Quorum risk assessment from node health
- RPC failover pool with priority ordering
- Chaos test framework (KillParty, NetworkPartition, DelayMessages)
- Disaster recovery plan generation

**CLI**
- `keygen` — generate distributed keys (GG20, FROST)
- `sign` — threshold signing
- `export-address` — derive chain addresses
- `list-keys` — show stored key groups
- `simulate` — pre-sign risk assessment
- `audit-verify` — verify audit trail integrity
- VAULTEX ASCII banner on startup

**Infrastructure**
- CI pipeline: fmt + clippy + test + audit
- 233 tests passing
- Zero CRITICAL/HIGH security findings
- Interactive demo script (`scripts/demo.sh`)

### Security

- SEC-001: GG20 key reconstruction → gated behind feature flag
- SEC-002: Hardcoded password → interactive rpassword prompt
- SEC-003: Transport stubs → real async-nats implementation
- SEC-004: KeyShare not zeroized → `Zeroizing<Vec<u8>>`
- SEC-005: Password not zeroized → `Zeroizing<String>`
- SEC-006: Weak Argon2 → 64MiB/3t/4p
- SEC-007: Unauthenticated messages → SignedEnvelope Ed25519
- SEC-009: Taproot empty script_pubkey → require prev_script_pubkey
- SEC-012: EVM high-S → auto-normalize via n-s
- SEC-015: Debug leaks share bytes → manual Debug with `[REDACTED]`
- SEC-016: Bitcoin unwrap → proper error propagation

[Unreleased]: https://github.com/itoonx/vaultex-mpc-rust/compare/v0.3.0...HEAD
[0.3.0]: https://github.com/itoonx/vaultex-mpc-rust/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/itoonx/vaultex-mpc-rust/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/itoonx/vaultex-mpc-rust/releases/tag/v0.1.0
