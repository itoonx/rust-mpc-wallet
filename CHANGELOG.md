# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.9.0] - 2026-05-10 (Sprint 48: TRON TRC-20 token transfer)

### Added

- **TRON TRC-20 token transfer** — `TriggerSmartContract` (ContractType=31) added
  alongside the existing `TransferContract` (ContractType=1) in `tron/proto.rs`.
  New encoders: `encode_trigger_smart_contract`, `encode_any_trigger`, and
  `encode_contract_envelope` (generalizes the prior contract wrapper). Constants
  `CONTRACT_TYPE_TRANSFER=1` and `CONTRACT_TYPE_TRIGGER_SMART_CONTRACT=31` are
  now exposed.
- `build_trc20_transfer_raw_data` one-shot helper that builds a TRC-20 raw
  transaction with a **mandatory `fee_limit`** — TVM contract calls require
  it on the wire (opposite of L-017's native-transfer omission rule).
- `tron/tx.rs::encode_trc20_transfer_calldata` — emits the 68-byte ABI payload:
  selector `0xa9059cbb` + 32-byte padded recipient (`hash160`, dropping the
  TRON `0x41` prefix) + 32-byte big-endian amount.
- `build_tron_transaction` now dispatches `TokenIdentifier::Tron` to the
  TRC-20 path with `fee_limit` defaulting to 100 TRX (100_000_000 sun).
- `decode_contract_to_json` dispatches on contract type and decodes
  `TriggerSmartContract` bodies into the broadcast JSON shape used by node
  RPC endpoints.
- CLI `presign` branches by contract type: TRC-20 auto-injects
  `fee_limit = 100_000_000` sun in the printed raw-data preview; native
  TRX continues to omit `fee_limit` per L-017.
- **Reference vector test** — 211-byte tronweb reference pinned byte-equal in
  `tron::proto::tests::proto_matches_tronweb_trc20_reference`.
- **Live TRON Shasta MPC broadcast** of a TRC-20 transfer:
  tx `0x54a73460ea78e5558ce78471e72600c68cc88a428dd76f2a47aa7a5e527fc296`
  — 0.0001 USDT (community testnet `TG3XXyExBkPp9nzdajDZsozEu4BkaSJozs`)
  self-transfer signed via GG20 ECDSA from MPC key shares.

### Changed

- Test count: **957 → 958** (`+1` TRC-20 tronweb reference vector).
- Token Transfer Coverage table: TRON TRC-20 promoted from `PLANNED` to `LIVE`.

### Notes

- No new retro lessons — the TRC-20 path worked first try by leveraging
  L-017 (native TRON `fee_limit` omission rule) and inverting it for TVM
  contract calls.
- No new security findings; all 68 prior findings remain RESOLVED.

## [0.8.0] - 2026-05-10 (Sprint 47: Aptos Fungible Asset `primary_fungible_store::transfer`)

### Added

- **Aptos Fungible Asset (FA) transfer** — `EntryFunction::primary_fungible_store_transfer`
  + `RawTransaction::new_fungible_asset_transfer`. Wire format: type arg is always
  `0x1::fungible_asset::Metadata`; args = `[Object<Metadata>, recipient, amount]`.
  The Metadata Object **address** replaces `Coin<T>`'s type-system identity — same
  logical asset, different on-chain identity model from the legacy `Coin<T>` path.
- **Live Aptos testnet broadcast** validating the FA path: tx
  `0xb3a41e3339db31111b8613442d895ffe2fc15615bd8624a821d52bc72b8f76f8` — native APT
  routed through `primary_fungible_store::transfer` at canonical metadata `0xa`.
- **`parse_aptos_address_padded`** address parser for short-form framework constants
  (e.g. `0xa`); left-pads to 32 bytes. Sender/recipient still use strict 64-char hex
  to catch copy-truncation bugs.
- 265-byte BCS reference vector pinned via `@aptos-labs/ts-sdk` in
  `aptos::types::tests::bcs_matches_aptos_sdk_fa_reference`.
- New retro lesson **L-019** (Aptos has two address conventions — strict for derived
  addresses, short-form tolerated for framework constants; needs split parser).

### Changed

- Test count: 956 → 957 (+1 FA reference vector).

### Security

- No new findings. All 68 prior findings remain RESOLVED.

## [0.7.0] - 2026-05-10 (Sprint 46: Sui `Coin<T>` + Aptos legacy `0x1::coin::transfer<T>`)

### Added

- **Sui `Coin<T>` PTB transfer** — `ProgrammableTransaction::transfer_coin` and
  `TransactionData::new_transfer_coin`. Source coin is an `Input::Object` (object_ref)
  feeding `SplitCoins`, not the implicit `GasCoin`. Wire format does **not** encode
  the type parameter `T` — validators infer it from the object's on-chain type.
  296-byte BCS output byte-equal to `@mysten/sui`. Live broadcast deferred until
  a non-SUI testnet token can be funded.
- **Aptos legacy `0x1::coin::transfer<T>`** — `EntryFunction::coin_transfer` +
  `RawTransaction::new_coin_transfer` + `StructTag::parse` helper for canonical
  `0xADDR::module::Name` parsing. 211-byte BCS byte-equal to `@aptos-labs/ts-sdk`.
- **Live Aptos testnet broadcast** validating the `<AptosCoin>` path (native APT
  via the legacy coin module): tx
  `0x72c2e3b599d55a0df9d15d55e7b77022f2163e9120acc3ca9d60c8c7adbe7892`.
- **CLI shorthand** for both new paths: `--token sui-coin:0x...::module::Type`
  and `--token aptos-coin:0x...::module::Type`. Flow unchanged through the
  `TokenIdentifier` schema introduced in Sprint 44.
- **`SuiRpcClient::get_owned_coins`** now takes a `coin_type` filter so callers
  can fetch object refs for a specific `Coin<T>` instead of only SUI.
- 5 new tests (956 total, was 951): 1 Sui Coin reference vector,
  1 Aptos Coin reference vector, 3 `StructTag::parse` tests.

### Notes

- No new retro lessons — both implementations worked first try by leveraging
  L-015 (Sui hand-rolled BCS shape), L-016 (Aptos auth/signing-message order),
  and L-018 (simulate-first dynamic gas / fee).
- No new security findings; all 68 prior findings remain RESOLVED.
- Aptos Fungible Asset (`primary_fungible_store`) path remains planned for a
  later sprint and is not yet wired.

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

[Unreleased]: https://github.com/itoonx/vaultex-mpc-rust/compare/v0.8.0...HEAD
[0.8.0]: https://github.com/itoonx/vaultex-mpc-rust/compare/v0.7.0...v0.8.0
[0.7.0]: https://github.com/itoonx/vaultex-mpc-rust/compare/v0.6.0...v0.7.0
[0.6.0]: https://github.com/itoonx/vaultex-mpc-rust/compare/v0.5.0...v0.6.0
[0.5.0]: https://github.com/itoonx/vaultex-mpc-rust/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/itoonx/vaultex-mpc-rust/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/itoonx/vaultex-mpc-rust/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/itoonx/vaultex-mpc-rust/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/itoonx/vaultex-mpc-rust/releases/tag/v0.1.0
