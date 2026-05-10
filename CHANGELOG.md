# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.6.0] - 2026-05-10 (Sprint 44–45: First cross-chain token transfer — EVM ERC-20)

### Added

- **Sprint 44** — Cross-chain token transfer schema (`TokenIdentifier`) at chain-crate level,
  research + design only (no chain wire-up)
- **Sprint 45** — EVM ERC-20 token transfer support; first live USDC-Sepolia MPC broadcast
  `0x23ab51bde4db9e737f0f6039c21bf418f68147d230f9100119715643ceb090a9`
  (0.1 USDC self-transfer, 40,707 gas, sepolia-test wallet)
- `crates/mpc-wallet-chains/src/token.rs` — `TokenIdentifier` schema implementation
- `crates/mpc-wallet-chains/src/evm/erc20.rs` — ERC-20 ABI encoder, validated byte-equal
  against viem-pinned reference vector
- `build_evm_transaction` detects `extra["token"]` and rewrites `to`/`value`/`data` for ERC-20
- `eth_estimateGas` helper in `evm/rpc_client.rs`; token spec threaded into
  `fetch_presign_extras` for dynamic `gas_limit`
- CLI `--token <shorthand>` flag (e.g. `erc20:0x...`) and `--token-json` escape hatch
- New retro lesson L-018 (EVM `gas_limit` must be dynamic via `eth_estimateGas` —
  "simulate first, sign second" applies to all chains with per-tx exec caps)

### Fixed

- EVM ERC-20 broadcasts no longer rejected for out-of-gas: dynamic `gas_limit` via
  `eth_estimateGas` replaces the static EOA-floor 21k that worked only for plain ETH transfers (L-018)

### Changed

- Test count: 941 → 951 (+10 from `token.rs` + `erc20.rs`)

### Security

- No new findings. All 68 prior findings remain RESOLVED.

## [0.5.0] - 2026-05-10 (Sprint 38–43: Live testnet MPC broadcasts on 6 chains)

### Added

- **Sprint 38** — First live Sepolia MPC broadcast (GG20 ECDSA over real Ethereum testnet)
- **Sprint 39** — First live Solana devnet MPC broadcast (FROST-Ed25519, real signed transaction)
- **Sprint 40** — First live Bitcoin testnet broadcast (P2WPKH + GG20 ECDSA)
- **Sprint 41** — First live Sui testnet broadcast (FROST-Ed25519, real `TransactionData::V1`)
- **Sprint 42** — First live Aptos testnet broadcast (FROST-Ed25519, real `RawTransaction`)
- **Sprint 43** — First live TRON Shasta MPC broadcast (GG20 ECDSA, hand-rolled protobuf `Transaction.raw`)
- TRON: hand-rolled Protobuf encoder for `Transaction.raw` (`TransferContract`), validated
  byte-equal against tronweb reference vector (`scripts/tron-ref-vector.mjs`)
- TRON: `TronRpcClient` with `get_now_block`, `get_balance`, and tronweb-shape `broadcast`
- TRON: `send.rs` Tron arm — balance preflight, `fetch_presign_extras`, sig recovery
  verification, explorer URL output
- Persisted funded testnet wallets under `~/.mpc-wallet/testnet/`; CLI `--wallet <name>`
  to reuse share sets across E2E runs (L-013)
- New retro lessons L-011..L-017 covering live-broadcast quirks per chain

### Fixed

- Aptos: BCS field order in `RawTransaction`, missing `RAW_TRANSACTION_SALT` domain
  prefix on signing message, minimum gas floor enforcement (L-016)
- Sui: BCS variant tag for `TransactionData::V1` was missing in hand-rolled encoder (L-015)
- TRON: omit `fee_limit` for plain `TransferContract`, encode `v` as `27 + parity` (L-017)

### Changed

- Bitcoin live path uses GG20 ECDSA + P2WPKH; FROST-Taproot tweak parked behind
  feature flag pending BIP-341 even-Y handling at keygen time (L-014)
- Test count: 970 → 941 (test reorganization across chain integration suites)

### Security

- No new findings. All 68 prior findings remain RESOLVED.

## [0.4.0] - 2026-05 (Sprint 32–37: Audit prep, HD wallet, SDK)

### Added

- BIP32 HD wallet derivation for secp256k1 MPC protocols — GG20 and CGGMP21 (Sprint 36)
- OpenAPI spec auto-generated from router via `utoipa` → `docs/openapi.json` (Sprint 37)
- SDK quickstart guide `docs/SDK_QUICKSTART.md` (Sprint 37)
- Error code catalog `docs/ERROR_CODES.md` (Sprint 37)
- Helm chart for full stack (gateway, mpc-nodes, NATS, Redis) under `infra/helm/mpc-wallet/` (Sprint 34)
- mpc-node `/health` endpoint and Prometheus metrics (Sprint 34)
- Threat model `docs/THREAT_MODEL.md`, audit scope `docs/AUDIT_SCOPE.md`, SBOM `docs/SBOM.txt` (Sprint 35)
- CVE-2025-66016 verification doc (Sprint 35)
- Benchmark baseline for all 7 protocols + CI benchmark gate (Sprint 32–33)
- Protocol common module to share helpers across protocols (Sprint 33)
- mpc-node test coverage 0 → 35 tests (Sprint 33)

### Changed

- Test count: 882 → 970 (+88 across new HD, SDK, audit-prep, mpc-node tests)

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

[Unreleased]: https://github.com/itoonx/vaultex-mpc-rust/compare/v0.6.0...HEAD
[0.6.0]: https://github.com/itoonx/vaultex-mpc-rust/compare/v0.5.0...v0.6.0
[0.5.0]: https://github.com/itoonx/vaultex-mpc-rust/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/itoonx/vaultex-mpc-rust/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/itoonx/vaultex-mpc-rust/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/itoonx/vaultex-mpc-rust/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/itoonx/vaultex-mpc-rust/releases/tag/v0.1.0
