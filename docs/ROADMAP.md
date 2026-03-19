# MPC Wallet SDK (Vaultex) — Product Roadmap

> **Owner:** R7 PM Agent
> **Created:** 2026-03-19
> **Status:** Active — Sprint 18 onward (Sprint 16-17 COMPLETE)
> **Goal:** Build the best open-source MPC wallet SDK for enterprise custody — stronger security than Fireblocks, more flexible than Cobo, more transparent than ZenGo.

---

## Table of Contents

1. [Competitive Analysis](#1-competitive-analysis)
2. [Security Principles](#2-security-principles-mpc-specific)
3. [Feature Gap Analysis](#3-feature-gap-analysis)
4. [Milestones](#4-milestones)
5. [Agent Assignment Matrix](#5-agent-assignment-matrix)
6. [Sprint Mapping](#6-sprint-mapping)
7. [Success Metrics](#7-success-metrics)

---

## 1. Competitive Analysis

### 1.1 Fireblocks

**What they offer:**
- MPC-CMP protocol (CGGMP21 variant) — 1 round for signing, 6x faster than GG20
- Policy engine with multi-level approval workflows, time-locks, velocity limits, address whitelisting
- DeFi access layer (WalletConnect, dApp browser, contract interaction)
- Staking orchestration (ETH 2.0, Cosmos, Polkadot native staking)
- Tokenization engine (ERC-20/ERC-721 issuance and management)
- Transaction Acceleration Manager (gas optimization, fee bumping)
- Comprehensive webhook/callback system for async transaction lifecycle
- SOC 2 Type II certified, ISO 27001
- 50+ blockchain integrations with native token support
- Network-level key isolation (Intel SGX enclaves)

**What we should learn:**
- MPC-CMP (CGGMP21) is the next-generation protocol — our GG20 is one generation behind
- Policy engine depth: Fireblocks supports nested conditional policies (if chain=ETH AND amount>$10K THEN require 3-of-5 approval)
- SGX enclave isolation for key shares is a hardware-level defense we lack
- Transaction lifecycle webhooks are essential for enterprise integrations

### 1.2 Cobo

**What they offer:**
- Hybrid model: MPC wallet + smart contract wallet (Cobo Safe, built on Safe/Gnosis)
- Role-based access with granular permissions per vault per chain
- Cobo Argus: on-chain access control for DeFi interactions (transaction-level ACL)
- Smart contract co-management: multi-sig + MPC for double-layer security
- Risk engine with pre-transaction simulation (dry-run on forked state)
- Gas station: automated gas management across chains
- Organization hierarchy: multi-team, multi-vault, per-team policies
- SOC 2 Type II certified

**What we should learn:**
- Smart contract wallet hybrid: combining MPC key management with on-chain multi-sig adds a second independent security layer
- Organization hierarchy model: enterprises need team/department/organization scoping, not flat user lists
- Gas station pattern: automated gas management is a key operational feature
- On-chain access control (Argus) is a unique defense-in-depth approach

### 1.3 ZenGo

**What they offer:**
- 3-party MPC (device share + server share + recovery share)
- Biometric recovery: face map as authentication factor for share recovery
- Web3 firewall (ClearSign): real-time transaction screening against known scam contracts
- MPC refresh on every transaction (proactive security rotation)
- No seed phrase model: user never sees or manages mnemonic words
- Built-in dApp browser with transaction simulation
- SOC 2 Type II certified

**What we should learn:**
- Proactive key refresh on every transaction is an aggressive but effective rotation strategy
- Web3 firewall / transaction screening against threat intelligence feeds
- Biometric-bound recovery eliminates the seed phrase attack surface
- Consumer-grade UX with enterprise-grade security — the SDK should enable both

### 1.4 Fordefi

**What they offer:**
- Institutional MPC with hardware-isolated key shares (secure enclaves)
- Real-time risk engine: pre-sign simulation with contract analysis
- Multi-chain DeFi access with protocol-aware transaction building
- Granular policy engine: per-vault, per-chain, per-asset, per-user policies
- Automated compliance reporting (AML/KYT integration)
- Address book with verification and whitelisting workflows
- API-first architecture (programmatic wallet management)

**What we should learn:**
- Hardware enclave isolation (HSM/SGX) for key shares at rest and during computation
- AML/KYT integration: enterprise custody requires compliance hooks
- Address book with verification workflows (known-address whitelisting)
- Protocol-aware transaction building: understanding DeFi protocol semantics, not just raw tx encoding

### 1.5 Dfns

**What they offer:**
- MPC TSS with programmable key delegation (delegated signing authority)
- Programmable wallets: server-side logic for automated signing workflows
- Key delegation: temporary signing authority with expiration and scope limits
- Multi-tenant architecture: one deployment serves multiple organizations
- Webhooks and event streams for transaction lifecycle
- SDK-first approach: TypeScript, Python, Go SDKs alongside REST API
- Passkey-based authentication (WebAuthn/FIDO2)

**What we should learn:**
- Key delegation is a powerful pattern: temporary, scoped signing authority without sharing key material
- Multi-tenant architecture: enterprise customers need isolated tenants within shared infrastructure
- Passkey/WebAuthn integration: modern authentication beyond JWT
- Programmable wallets: allow customers to embed signing logic as code (serverless-style)

---

## 2. Security Principles (MPC-Specific)

These principles are non-negotiable and guide ALL future development decisions.

### P1: Key Share Isolation (DEC-015)
**Status:** IMPLEMENTED

No single process, machine, or operator holds more than one key share. Gateway holds zero shares. Each MPC node holds exactly one share in an encrypted store (AES-256-GCM + Argon2id). Network-level separation between nodes is enforced at the transport layer.

### P2: Zero-Knowledge of Full Key (SEC-001)
**Status:** IMPLEMENTED

The full private key is NEVER reconstructed — not during keygen, not during signing, not during refresh, not during reshare. All protocols use distributed computation (additive shares for GG20, threshold Schnorr for FROST) where each party contributes a partial result without learning the secret.

### P3: Independent Node Verification (DEC-012)
**Status:** IMPLEMENTED

Each MPC node independently verifies `SignAuthorization` proofs before participating in any signing ceremony. A compromised gateway cannot unilaterally trigger signing — nodes check: gateway signature validity, message hash binding, policy passage, approval quorum, and timestamp freshness (2-minute TTL).

### P4: Defense in Depth
**Status:** PARTIAL — needs additional layers

Security does not depend on any single control. Every layer assumes the layer above it may be compromised:
- **Transport:** mTLS + SignedEnvelope + per-session encryption (IMPLEMENTED)
- **Storage:** AES-256-GCM + Argon2id + Zeroizing memory (IMPLEMENTED)
- **Protocol:** Threshold computation without reconstruction (IMPLEMENTED)
- **Application:** Policy engine + approval quorum + RBAC (IMPLEMENTED)
- **Hardware:** HSM/SGX enclave isolation (NOT YET — Milestone 3)
- **Network:** NATS JetStream ACL + subject isolation (IMPLEMENTED)
- **Monitoring:** Tamper-evident audit ledger (IMPLEMENTED), real-time alerting (NOT YET — Milestone 5)

### P5: Cryptographic Agility
**Status:** IMPLEMENTED

Support multiple signature schemes through the `MpcProtocol` trait:
- GG20 ECDSA (secp256k1) — EVM, Bitcoin legacy, TRON, Cosmos
- FROST Schnorr (secp256k1) — Bitcoin Taproot
- FROST Ed25519 — Solana, Sui, Aptos, Substrate, TON
- BLS12-381, SR25519, STARK — additional schemes available
- Key refresh and reshare for GG20 and both FROST variants

Future: MPC-CMP (CGGMP21) upgrade path for 1-round signing.

### P6: Audit Trail Immutability
**Status:** IMPLEMENTED

Hash-chained, Ed25519-signed audit ledger records every key operation (keygen, sign, refresh, freeze). Evidence packs are exportable and verifiable. WORM storage configuration available (S3 Object Lock + local append-only). Every entry links to the previous via SHA-256 chain — tampering breaks the chain detectably.

### P7: Disaster Recovery Without Key Reconstruction
**Status:** IMPLEMENTED

DR plan uses key resharing (GG20 additive reshare preserves group key, FROST fresh DKG generates new group key). Emergency freeze propagates to all nodes via NATS control channel. Multi-cloud distribution with quorum risk assessment ensures no single cloud failure loses quorum. At no point during recovery is the full key assembled.

### P8: Least Privilege Signing
**Status:** PARTIAL — needs expansion

Every signing operation requires explicit authorization through the full chain: authentication (mTLS/JWT) -> RBAC check -> policy evaluation -> approval quorum -> SignAuthorization proof -> node-level verification. Future: key delegation with scoped, time-limited authority (Milestone 4).

---

## 3. Feature Gap Analysis

### 3.1 Feature Comparison Matrix

| Feature | Vaultex (Current) | Fireblocks | Cobo | ZenGo | Fordefi | Dfns | Priority |
|---------|-------------------|------------|------|-------|---------|------|----------|
| MPC keygen (distributed) | GG20 + FROST | MPC-CMP | MPC | 3-party MPC | MPC TSS | MPC TSS | HAVE |
| MPC signing (no reconstruction) | GG20 additive + FROST | MPC-CMP (1-round) | MPC | MPC | MPC TSS | MPC TSS | HAVE |
| Key refresh | GG20 + FROST refresh | Yes | Yes | Every tx | Yes | Yes | HAVE |
| Key resharing | GG20 + FROST reshare | Yes | Yes | N/A | Yes | Yes | HAVE |
| Multi-chain (50+) | 50 chains | 50+ | 40+ | 15+ | 30+ | 40+ | HAVE |
| Policy engine | Rules + velocity + templates | Advanced nested | Role-based | Basic | Granular | Programmable | HAVE (basic) |
| Approval workflows | Ed25519 quorum + SoD | Multi-level | Multi-level | N/A | Multi-level | Webhooks | HAVE (basic) |
| Auth (mTLS + JWT) | 3-method auth | mTLS + API | mTLS + API | OAuth | mTLS + API | Passkeys | HAVE |
| RBAC | Roles + guards | Granular | Granular | Basic | Granular | Delegated | HAVE (basic) |
| ABAC | Dept/cost_center/risk | Advanced | Advanced | N/A | Advanced | N/A | HAVE (basic) |
| Audit ledger | Hash-chained + signed | SOC 2 compliant | SOC 2 | Basic | Compliance | Event stream | HAVE |
| Transaction simulation | EVM/BTC/SOL/SUI risk scoring | Advanced fork sim | Fork sim | ClearSign | Real-time sim | Basic | HAVE (basic) |
| **MPC-CMP (CGGMP21)** | NO | YES | Partial | NO | YES | YES | **MUST HAVE** |
| **HSM/SGX enclave** | Stub only | Intel SGX | HSM | N/A | Secure enclave | HSM | **MUST HAVE** |
| **Real-time tx screening** | NO | YES | Partial | Web3 firewall | YES | Partial | **MUST HAVE** |
| **DeFi access layer** | NO | YES | Argus | dApp browser | YES | Partial | **MUST HAVE** |
| **Key delegation** | NO | NO | NO | NO | NO | YES | **MUST HAVE** |
| **Multi-tenant** | NO | YES | YES | N/A | YES | YES | **MUST HAVE** |
| **Webhooks/events** | NO | YES | YES | N/A | YES | YES | **MUST HAVE** |
| **Gas management** | NO | YES | Gas station | Auto | YES | Basic | **NICE TO HAVE** |
| **AML/KYT hooks** | NO | YES | YES | NO | YES | Partial | **NICE TO HAVE** |
| **Passkey/WebAuthn** | NO | NO | NO | NO | NO | YES | **NICE TO HAVE** |
| **Smart contract wallet hybrid** | NO | NO | Cobo Safe | NO | NO | NO | **NICE TO HAVE** |
| **Staking orchestration** | NO | YES | YES | NO | YES | NO | **FUTURE** |
| **Tokenization engine** | NO | YES | NO | NO | NO | NO | **FUTURE** |
| **On-chain access control** | NO | NO | Argus | NO | NO | NO | **FUTURE** |

### 3.2 Priority Summary

**MUST HAVE (blocks enterprise adoption):**
1. MPC-CMP / CGGMP21 protocol upgrade — 1-round signing, malicious-secure
2. HSM/SGX integration — hardware-isolated key shares
3. Real-time transaction screening — threat intelligence + contract analysis
4. DeFi protocol access layer — safe DeFi interaction patterns
5. Key delegation — scoped, time-limited signing authority
6. Multi-tenant architecture — isolated organizations in shared infrastructure
7. Webhook/event system — async transaction lifecycle notifications

**NICE TO HAVE (differentiators):**
1. Gas management automation — cross-chain gas station
2. AML/KYT compliance hooks — Chainalysis/Elliptic integration points
3. Passkey/WebAuthn authentication — passwordless auth
4. Smart contract wallet hybrid — MPC + on-chain multi-sig

**FUTURE (post-launch):**
1. Staking orchestration — native staking across PoS chains
2. Tokenization engine — ERC-20/ERC-721 issuance
3. On-chain access control — DeFi-level transaction ACL

---

## 4. Milestones

### Milestone 1: Security Hardening & Remaining Findings (Sprint 17-18)

**Goal:** Close all open MEDIUM/LOW security findings, harden control plane messaging, upgrade dependency vulnerabilities.

**Exit Criteria:**
- [x] SEC-008: GG20 simulation-mode scalar explicitly zeroized (gated behind feature flag) -- Sprint 17, commit `58671b5`
- [x] SEC-013: FROST protocols validate `from` field against cryptographic sender identity (piggybacks on SignedEnvelope) -- Sprint 17, commit `1503b68`
- [x] SEC-014: `LocalTransport` gated behind `#[cfg(any(test, feature = "demo"))]` feature flag -- Sprint 17, commit `c0e5c68`
- [x] SEC-017: Solana tx builder validates `from` address matches signing pubkey -- Sprint 17, commit `dc5488a`
- [x] SEC-018: `async-nats` upgraded to version without `rustls-pemfile` unmaintained dependency -- Sprint 17, mitigated (documented)
- [x] SEC-019: `quinn-proto` upgraded to >= 0.11.14 (DoS fix) or patched via `[patch.crates-io]` -- Sprint 17, already at 0.11.14
- [x] SEC-023: Sui address validation test for invalid hex characters added -- Sprint 17, commit `0e95ad3`
- [x] GATEWAY_PUBKEY environment variable mandatory (not optional) — nodes reject startup without it -- Sprint 17, commit `8f298df`
- [ ] Control plane messages (keygen/sign/freeze) include Ed25519 signature from gateway
- [x] SignAuthorization includes replay protection: nonce + node-side deduplication cache -- Sprint 17, `authorization_id` field added
- [x] All 507+ existing tests continue to pass -- 540 tests pass as of Sprint 17
- [ ] `cargo audit` clean without `.cargo/audit.toml` ignores (all dependencies current)

**Risk:** Dependency upgrades may introduce breaking API changes. Mitigated by running full test suite after each upgrade.

---

### Milestone 2: MPC-CMP Protocol Upgrade (Sprint 19-21)

**Goal:** Implement CGGMP21 (MPC-CMP) as the primary ECDSA signing protocol, reducing signing rounds from 5+ (GG20) to 1 (pre-signing + online phase).

**Exit Criteria:**
- [ ] `crates/mpc-wallet-core/src/protocol/cggmp21.rs` — full CGGMP21 implementation
- [ ] Pre-signing phase: parties generate pre-signature shares offline (can be batched)
- [ ] Online signing phase: 1 round to produce final signature from pre-shares
- [ ] Keygen: 3-round DKG with Paillier modulus proofs and range proofs
- [ ] Auxiliary info generation: Pedersen commitment parameters + Paillier keys
- [ ] Malicious-secure: identifiable abort — protocol identifies and excludes cheating party
- [ ] Key refresh compatible with CGGMP21 shares (not just GG20 additive refresh)
- [ ] `MpcProtocol` trait: new `CryptoScheme::Cggmp21Secp256k1` variant
- [ ] All 50 chains that use secp256k1 ECDSA work with both GG20 and CGGMP21
- [ ] Benchmark: signing latency < 200ms for 2-of-3 (vs current GG20 ~500ms)
- [ ] 30+ protocol-level tests (keygen, sign, refresh, abort identification, threshold subsets)
- [ ] R6 audit: APPROVED verdict on protocol correctness
- [ ] External cryptographic review engaged (or report produced for external auditors)

**Risk:** CGGMP21 is significantly more complex than GG20 (Paillier + range proofs). May require 3 sprints. The `multi-party-ecdsa` crate dependency may conflict with existing `k256` version.

---

### Milestone 3: HSM/SGX Integration & Hardware Key Isolation (Sprint 22-23)

**Goal:** Key shares protected at the hardware level — HSM for encryption keys, SGX enclaves for signing computation.

**Exit Criteria:**
- [ ] `KmsSigner` implementation: real AWS KMS integration (not stub) for gateway signing key
- [ ] `KeyEncryptionProvider` HSM backend: key encryption keys stored in HSM (AWS CloudHSM or Azure Managed HSM)
- [ ] Key share encryption key (KEK) never leaves HSM — encrypt/decrypt operations via PKCS#11 or cloud KMS API
- [ ] SGX enclave design document: defines what runs inside the enclave (signing computation) vs outside (transport, orchestration)
- [ ] SGX prototype: MPC signing round executes inside SGX enclave using Gramine or Teaclave
- [ ] Attestation verification: nodes verify each other's enclave attestation reports before protocol start
- [ ] Key share at-rest encryption: option for HSM-wrapped AES keys (in addition to Argon2id-derived keys)
- [ ] Vault integration enhanced: dynamic secrets rotation for NATS credentials, Redis passwords
- [ ] Tests: HSM mock tests (unit) + real HSM integration tests (E2E, `#[ignore]`)
- [ ] `SECRETS_BACKEND=hsm` configuration option alongside existing `vault` and `env`

**Risk:** SGX is being deprecated by Intel in favor of TDX. Design should be enclave-agnostic (Gramine abstraction layer). Cloud KMS adds latency per crypto operation (~5-20ms).

---

### Milestone 4: Policy Engine v2 & Key Delegation (Sprint 24-26)

**Goal:** Enterprise-grade policy engine with nested conditional rules, key delegation for automated signing, and organizational hierarchy.

**Exit Criteria:**
- [ ] **Nested policy rules:** AND/OR/NOT combinators for policy conditions
  ```
  IF chain = ETH AND amount > $10,000 THEN require 3-of-5 approval
  IF chain = SOL AND destination NOT IN whitelist THEN DENY
  IF time NOT IN business_hours AND amount > $1,000 THEN require MFA
  ```
- [ ] **Policy DSL:** JSON/YAML policy definition language with schema validation
- [ ] **Policy versioning:** policies are versioned and signed (extends existing signed_bundle)
- [ ] **Key delegation:** `DelegationToken` struct — time-limited, scope-limited signing authority
  - Scoped by: chain, max amount, destination whitelist, expiration time
  - Signed by delegator's Ed25519 key
  - MPC nodes verify delegation token alongside SignAuthorization
- [ ] **Organization hierarchy:** Organization -> Team -> Vault -> Key Group
  - Each level inherits and can restrict parent policies
  - Team-scoped RBAC: team admin, team operator, team viewer roles
- [ ] **Spending limits:** per-key, per-team, per-organization daily/weekly/monthly velocity limits
- [ ] **Address whitelist:** verified destination addresses per vault with approval workflow for additions
- [ ] **Time-based rules:** business hours enforcement, cooldown periods between operations
- [ ] **Webhook notifications:** POST to configured URL on policy evaluation (approve/deny/pending)
- [ ] 50+ policy engine tests covering all rule combinators and edge cases
- [ ] Policy migration tool: upgrade v1 policies to v2 format

**Risk:** Policy DSL complexity. Keep the language simple (no Turing-completeness). Evaluate existing policy engines (OPA/Rego) before building custom.

---

### Milestone 5: DeFi Access Layer & Transaction Screening (Sprint 27-29)

**Goal:** Safe DeFi interaction with real-time threat intelligence, protocol-aware transaction building, and contract analysis.

**Exit Criteria:**
- [ ] **Transaction screening service:** pluggable threat intelligence backend
  - Interface: `TransactionScreener` trait with `screen(tx) -> ScreeningResult`
  - Built-in: known scam address database (community-maintained list)
  - Pluggable: Chainalysis KYT, Elliptic, TRM Labs adapter interfaces
  - Screening runs BEFORE policy evaluation — blocked tx never reaches MPC nodes
- [ ] **Contract analysis:** EVM contract interaction decoder
  - Decode function selectors and parameters for known protocols (Uniswap, Aave, Compound, Curve)
  - Risk scoring: unknown contracts scored higher than verified protocols
  - Proxy contract detection (EIP-1967, EIP-1822) with implementation verification
- [ ] **DeFi protocol adapters:** safe transaction builders for common DeFi operations
  - Swap: Uniswap V2/V3, SushiSwap, 1inch
  - Lending: Aave V3, Compound V3
  - Staking: Lido, Rocket Pool, native ETH staking
  - Each adapter: build_tx() + simulate() + human-readable description
- [ ] **Simulation enhancement:** fork-state simulation for EVM transactions
  - Simulate on forked mainnet state (via `eth_call` with state overrides)
  - Report: token balance changes, gas estimate, revert reason, approval changes
- [ ] **Gas management:** gas price oracle integration
  - EVM: EIP-1559 base fee + priority fee estimation
  - Fee bumping: automatic gas price increase for stuck transactions
  - Cross-chain gas abstraction: unified gas estimation API across chains
- [ ] 40+ tests covering screening, protocol decoding, simulation, and gas estimation

**Risk:** DeFi protocols change frequently. Protocol adapters need versioning and regular updates. Threat intelligence feeds are third-party dependencies with SLA/cost implications.

---

### Milestone 6: Multi-Tenant & Webhook Infrastructure (Sprint 30-31)

**Goal:** Production multi-tenant deployment with isolated organizations, webhook event system, and operational tooling.

**Exit Criteria:**
- [ ] **Multi-tenant data isolation:**
  - Tenant ID propagated through all API calls (header or JWT claim)
  - NATS subject isolation: `{tenant_id}.mpc.control.*` per organization
  - Key store isolation: per-tenant encryption keys (tenant KEK wrapping)
  - Redis key namespacing: `{tenant_id}:session:*` prefix
  - Audit ledger: per-tenant log streams
- [ ] **Webhook event system:**
  - Events: `tx.pending`, `tx.signed`, `tx.broadcast`, `tx.confirmed`, `tx.failed`
  - Events: `key.created`, `key.refreshed`, `key.frozen`, `key.reshared`
  - Events: `policy.violated`, `approval.required`, `approval.received`
  - Delivery: at-least-once with retry (exponential backoff, max 5 retries)
  - Webhook registration API: `POST /v1/webhooks` with URL + secret + event filter
  - Webhook signatures: HMAC-SHA256 of payload for verification
- [ ] **Tenant management API:**
  - `POST /v1/tenants` — create organization
  - `GET /v1/tenants/{id}/usage` — key count, sign operations, storage
  - `PUT /v1/tenants/{id}/limits` — rate limits, key limits, policy overrides
- [ ] **Operational dashboard data:**
  - Prometheus metrics exported: keygen latency, sign latency, active sessions, policy evaluations
  - Structured JSON logging with tenant_id, request_id, trace_id
  - Health endpoints: `/health`, `/ready` with dependency checks (NATS, Redis, Vault)
- [ ] 30+ tests covering tenant isolation, webhook delivery, and metrics export

**Risk:** Multi-tenancy is an architectural change that touches every layer. Must be designed as a cross-cutting concern, not bolted on. Webhook delivery guarantees require a durable queue (consider JetStream).

---

### Milestone 7: Compliance & External Audit Preparation (Sprint 32-33)

**Goal:** Prepare for SOC 2 Type II certification and external cryptographic audit. Document all controls, produce evidence artifacts, engage auditors.

**Exit Criteria:**
- [ ] **SOC 2 control mapping:** all Trust Service Criteria mapped to Vaultex controls
  - CC6.1 (logical access): auth system (mTLS + JWT + RBAC) documented
  - CC6.6 (encryption): key share encryption (AES-256-GCM + Argon2id) documented
  - CC7.2 (monitoring): audit ledger + alerting documented
  - CC8.1 (change management): git workflow + R6 gate + CI pipeline documented
- [ ] **Cryptographic audit package:**
  - Protocol specifications: GG20, CGGMP21, FROST Ed25519, FROST Secp256k1
  - Security proofs: references to published papers for each protocol
  - Implementation notes: deviations from papers, custom optimizations
  - Test vectors: deterministic test cases for protocol correctness verification
- [ ] **Penetration test preparation:**
  - Threat model document: STRIDE analysis of all components
  - Attack surface map: all API endpoints, NATS channels, storage paths
  - Known limitations: documented trade-offs and accepted risks
- [ ] **Compliance hooks implemented:**
  - AML/KYT integration point: `ComplianceScreener` trait with mock implementation
  - Transaction reporting: exportable transaction log in regulatory format
  - Data retention policy: configurable audit log retention with secure deletion
- [ ] **Documentation:**
  - Security whitepaper (public): architecture, threat model, protocol choices
  - Deployment hardening guide: production configuration checklist
  - Incident response playbook: key compromise, node failure, protocol abort scenarios
- [ ] External audit firm engaged (NCC Group, Trail of Bits, or equivalent)
- [ ] All MEDIUM/LOW security findings from SEC-* log resolved or documented as accepted risk

**Risk:** SOC 2 Type II requires 6-12 months of operational evidence collection. The audit preparation milestone produces the controls and documentation; the actual certification is a separate timeline.

---

### Milestone 8: Production Launch (Sprint 34-35)

**Goal:** GA release of the SDK with full documentation, SDK packages published, and reference deployment operational.

**Exit Criteria:**
- [ ] **SDK published:** `mpc-wallet-core` and `mpc-wallet-chains` on crates.io
- [ ] **API stability:** all public traits and types marked with stability guarantees (semver)
- [ ] **SDK documentation:**
  - API reference (rustdoc) published to docs.rs
  - Integration guide: step-by-step for Rust consumers
  - REST API reference: OpenAPI 3.0 spec for gateway endpoints
  - Client SDKs: TypeScript and Python wrappers (calling REST API)
- [ ] **Reference deployment:**
  - Docker Compose: 3-node MPC cluster + gateway + NATS + Redis + Vault
  - Kubernetes Helm chart: production deployment with HSM, monitoring, alerting
  - Terraform modules: AWS + GCP multi-cloud node distribution
- [ ] **Performance baselines published:**
  - Keygen (2-of-3): < 500ms (GG20), < 300ms (CGGMP21), < 200ms (FROST)
  - Signing (2-of-3): < 200ms (GG20), < 100ms (CGGMP21), < 50ms (FROST)
  - Key refresh: < 1s
  - Throughput: > 100 sign operations/second sustained
- [ ] **Load testing:** 1000 concurrent signing sessions without degradation
- [ ] **Chaos testing:** node failure, network partition, NATS outage — all with graceful recovery
- [ ] **Zero CRITICAL/HIGH security findings**
- [ ] **Test count:** 800+ (up from current 507)
- [ ] **External audit report:** findings addressed, no CRITICAL/HIGH remaining
- [ ] **CHANGELOG.md:** complete history from v0.1 to v1.0

**Risk:** Production launch is gated on external audit completion. Plan for 2-4 weeks of remediation after audit findings.

---

## 5. Agent Assignment Matrix

### Milestone 1: Security Hardening (Sprint 17-18)

| Task | Agent | Files | Reviewer |
|------|-------|-------|----------|
| SEC-008 scalar zeroize | R1 Crypto | `protocol/gg20.rs` | R6 |
| SEC-013 FROST from-field validation | R1 Crypto | `protocol/frost_*.rs` | R6 |
| SEC-014 LocalTransport feature gate | R2 Infra | `transport/local.rs` | R6 |
| SEC-017 Solana from-address validation | R3c Solana | `solana/tx.rs` | R6 |
| SEC-018 async-nats upgrade | R2 Infra | `Cargo.toml`, `Cargo.lock` | R0, R6 |
| SEC-019 quinn-proto upgrade | R0 Arch | `Cargo.toml`, `Cargo.lock` | R6 |
| SEC-023 Sui hex validation test | R3d Sui | `sui/` tests | R6 |
| GATEWAY_PUBKEY mandatory | R2 Infra | `services/mpc-node/` | R6 |
| Control plane message signing | R2 Infra | `orchestrator.rs`, `rpc/` | R6 |
| SignAuthorization replay protection | R1 Crypto | `sign_authorization.rs` | R6 |
| **Extended agents:** | Security Engineer (threat model review), Code Reviewer (PR review) |

### Milestone 2: MPC-CMP Protocol (Sprint 19-21)

| Task | Agent | Files | Reviewer |
|------|-------|-------|----------|
| CGGMP21 protocol implementation | R1 Crypto | `protocol/cggmp21.rs` (new) | R6, Blockchain Security Auditor |
| CryptoScheme variant addition | R0 Arch | `types.rs`, `protocol/mod.rs` | R1 |
| Paillier + range proof integration | R1 Crypto | `protocol/cggmp21.rs` | R6 |
| Pre-signing phase | R1 Crypto | `protocol/cggmp21.rs` | R6 |
| Chain integration (50 chains) | R3a-R3d | `chains/*/provider.rs` | R5 |
| Benchmarks | R5 QA | `benches/` | Performance Benchmarker |
| Protocol integration tests | R5 QA | `tests/protocol_integration.rs` | R6 |
| **Extended agents:** | Blockchain Security Auditor (protocol audit), Performance Benchmarker |

### Milestone 3: HSM/SGX Integration (Sprint 22-23)

| Task | Agent | Files | Reviewer |
|------|-------|-------|----------|
| AWS KMS signer implementation | R4 Service | `auth/kms_signer.rs` | R6 |
| HSM key encryption backend | R2 Infra | `key_store/hsm.rs` | R6 |
| Vault dynamic secrets rotation | R4 Service | `vault.rs` | R6 |
| SGX enclave design document | R0 Arch | `docs/SGX_DESIGN.md` | Security Engineer |
| SGX signing prototype | R1 Crypto + R2 Infra | `protocol/sgx/` (new) | R6 |
| Attestation verification | R2 Infra | `transport/attestation.rs` (new) | R6 |
| **Extended agents:** | Security Engineer (enclave threat model), Backend Architect (KMS architecture) |

### Milestone 4: Policy Engine v2 & Key Delegation (Sprint 24-26)

| Task | Agent | Files | Reviewer |
|------|-------|-------|----------|
| Policy DSL parser | R4 Service | `policy/dsl.rs` (new) | R0, Code Reviewer |
| Nested rule engine | R4 Service | `policy/engine.rs` (new) | R6 |
| Key delegation token | R1 Crypto | `protocol/delegation.rs` (new) | R6 |
| Organization hierarchy | R4 Service | `identity/org.rs` (new) | R0 |
| Address whitelist | R4 Service | `policy/whitelist.rs` (new) | R6 |
| Webhook notification system | R4 Service | `services/api-gateway/src/webhooks/` (new) | R5 |
| Spending limits v2 | R4 Service | `policy/velocity.rs` | R6 |
| Policy engine tests | R5 QA | `tests/policy_v2.rs` (new) | R6 |
| **Extended agents:** | Workflow Architect (delegation flow), Software Architect (policy engine design) |

### Milestone 5: DeFi Access & Tx Screening (Sprint 27-29)

| Task | Agent | Files | Reviewer |
|------|-------|-------|----------|
| TransactionScreener trait | R0 Arch | `provider.rs` or new module | R6 |
| Threat intelligence adapter | R4 Service | `screening/` (new) | R6 |
| EVM contract decoder | R3a EVM | `evm/decoder.rs` (new) | R6 |
| DeFi protocol adapters | R3a EVM | `evm/defi/` (new) | R6, Code Reviewer |
| Fork-state simulation | R3a EVM | `evm/simulate.rs` | R5 |
| Gas oracle integration | R3a EVM | `evm/gas.rs` (new) | R5 |
| Screening tests | R5 QA | `tests/screening.rs` (new) | R6 |
| **Extended agents:** | Blockchain Security Auditor (DeFi risk), API Tester (endpoint validation) |

### Milestone 6: Multi-Tenant & Webhooks (Sprint 30-31)

| Task | Agent | Files | Reviewer |
|------|-------|-------|----------|
| Tenant isolation middleware | R4 Service | `middleware/tenant.rs` (new) | R6 |
| NATS subject namespacing | R2 Infra | `transport/nats.rs` | R6 |
| Per-tenant key store isolation | R2 Infra | `key_store/encrypted.rs` | R6 |
| Webhook delivery engine | R4 Service | `webhooks/` (new) | R5, SRE |
| Tenant management API | R4 Service | `routes/tenants.rs` (new) | R5 |
| Prometheus metrics export | R4 Service | `metrics.rs` (new) | SRE |
| Health + readiness endpoints | R4 Service | `routes/health.rs` (new) | R5 |
| **Extended agents:** | SRE (observability), DevOps Automator (deployment), Backend Architect |

### Milestone 7: Compliance & Audit Prep (Sprint 32-33)

| Task | Agent | Files | Reviewer |
|------|-------|-------|----------|
| SOC 2 control mapping | R7 PM | `docs/SOC2_CONTROLS.md` (new) | Compliance Auditor |
| Cryptographic audit package | R1 Crypto | `docs/CRYPTO_AUDIT_PACKAGE.md` (new) | Blockchain Security Auditor |
| Threat model (STRIDE) | R6 Security | `docs/THREAT_MODEL.md` (new) | Security Engineer |
| AML/KYT trait + mock | R4 Service | `compliance/` (new) | R6 |
| Security whitepaper | R7 PM + R6 | `docs/SECURITY_WHITEPAPER.md` (new) | Security Engineer |
| Incident response playbook | R4 Service + R6 | `docs/RUNBOOKS.md` (update) | Incident Response Commander |
| **Extended agents:** | Compliance Auditor, Blockchain Security Auditor, Security Engineer, Technical Writer |

### Milestone 8: Production Launch (Sprint 34-35)

| Task | Agent | Files | Reviewer |
|------|-------|-------|----------|
| crates.io publish preparation | R0 Arch | `Cargo.toml` (all crates) | R7 |
| OpenAPI spec generation | R4 Service | `specs/openapi.yaml` (new) | API Tester |
| TypeScript SDK | NEW: R8 SDK Agent | `sdks/typescript/` (new) | R5 |
| Python SDK | NEW: R8 SDK Agent | `sdks/python/` (new) | R5 |
| Docker Compose reference | R4 Service | `infra/docker-compose.yml` | DevOps Automator |
| Helm chart | NEW: R9 DevOps Agent | `infra/helm/` (new) | DevOps Automator, SRE |
| Terraform modules | NEW: R9 DevOps Agent | `infra/terraform/` (new) | DevOps Automator |
| Load testing suite | R5 QA | `tests/load/` (new) | Performance Benchmarker, SRE |
| **Extended agents:** | Technical Writer, Developer Advocate, DevOps Automator, SRE, Reality Checker |

### New Agent Proposals

| Agent | ID | Justification |
|-------|-----|---------------|
| SDK Agent | R8 | TypeScript + Python client SDKs require language expertise outside Rust |
| DevOps Agent | R9 | Helm charts, Terraform modules, and deployment automation are a distinct skill set |

---

## 6. Sprint Mapping

### Phase 1: Harden (Sprint 17-18)

**Sprint 17: Security Findings Closure -- COMPLETE**
- T-S17-01 (R1): SEC-008 scalar zeroize + SEC-013 FROST from-field validation + authorization_id replay protection -- DONE
- T-S17-02 (R2): SEC-014 LocalTransport gate + SEC-018 async-nats mitigated + GATEWAY_PUBKEY mandatory -- DONE
- T-S17-03 (R3c): SEC-017 Solana from-address validation -- DONE
- T-S17-04 (R3d): SEC-023 Sui hex validation test -- DONE
- T-S17-05 (R0): SEC-019 quinn-proto already patched at 0.11.14 -- DONE

**Sprint 18: Control Plane Hardening**
- T-S18-01 (R2): Control plane message signing (keygen/sign/freeze channels)
- T-S18-02 (R1): SignAuthorization replay protection (nonce + dedup cache)
- T-S18-03 (R5): Integration tests for all hardening changes
- T-S18-04 (R6): Full security audit of Sprint 17-18 changes
- T-S18-05 (R7): Update CLAUDE.md, SPRINT.md, SECURITY_FINDINGS.md

### Phase 2: Protocol (Sprint 19-21)

**Sprint 19: CGGMP21 Foundation**
- T-S19-01 (R0): Add `CryptoScheme::Cggmp21Secp256k1` variant + dependency approval
- T-S19-02 (R1): CGGMP21 keygen — 3-round DKG with Paillier modulus proofs
- T-S19-03 (R1): Auxiliary info generation (Pedersen + Paillier key pairs)

**Sprint 20: CGGMP21 Signing**
- T-S20-01 (R1): CGGMP21 pre-signing phase (offline, batchable)
- T-S20-02 (R1): CGGMP21 online signing phase (1 round from pre-shares)
- T-S20-03 (R1): Identifiable abort — detect and report cheating party

**Sprint 21: CGGMP21 Integration**
- T-S21-01 (R3a-R3d): Wire CGGMP21 to all 50 secp256k1 chains
- T-S21-02 (R5): 30+ protocol tests + benchmarks (keygen, sign, abort, subsets)
- T-S21-03 (R6): Full protocol security audit — APPROVED verdict required
- T-S21-04 (R1): CGGMP21 key refresh implementation

### Phase 3: Hardware (Sprint 22-23)

**Sprint 22: KMS/HSM Integration**
- T-S22-01 (R4): AWS KMS signer — real implementation replacing stub
- T-S22-02 (R2): HSM key encryption backend — PKCS#11 or cloud KMS API
- T-S22-03 (R4): Vault dynamic secrets — NATS + Redis credential rotation

**Sprint 23: SGX Prototype**
- T-S23-01 (R0): SGX enclave design document
- T-S23-02 (R1 + R2): SGX signing prototype via Gramine
- T-S23-03 (R2): Enclave attestation verification between nodes
- T-S23-04 (R6): Hardware security audit

### Phase 4: Policy & Delegation (Sprint 24-26)

**Sprint 24: Policy DSL**
- T-S24-01 (R0): Policy rule type definitions (AND/OR/NOT combinators)
- T-S24-02 (R4): Policy DSL parser (JSON/YAML -> rule tree)
- T-S24-03 (R4): Nested rule evaluation engine

**Sprint 25: Key Delegation & Org Hierarchy**
- T-S25-01 (R1): DelegationToken — Ed25519-signed, scoped, time-limited
- T-S25-02 (R4): Organization -> Team -> Vault hierarchy model
- T-S25-03 (R4): Team-scoped RBAC (admin/operator/viewer per team)

**Sprint 26: Address Whitelist & Spending v2**
- T-S26-01 (R4): Address whitelist with verification workflow
- T-S26-02 (R4): Per-key/team/org velocity limits (daily/weekly/monthly)
- T-S26-03 (R4): Webhook notification system (first implementation)
- T-S26-04 (R5): 50+ policy engine v2 tests

### Phase 5: DeFi & Screening (Sprint 27-29)

**Sprint 27: Transaction Screening**
- T-S27-01 (R0): TransactionScreener trait definition
- T-S27-02 (R4): Threat intelligence adapter framework + known-address list
- T-S27-03 (R4): Screening integration in sign request pipeline (before policy)

**Sprint 28: DeFi Protocol Adapters**
- T-S28-01 (R3a): EVM contract function decoder (ABI parsing)
- T-S28-02 (R3a): Uniswap V2/V3, Aave V3, Compound V3 adapters
- T-S28-03 (R3a): Fork-state simulation via eth_call with state overrides

**Sprint 29: Gas Management**
- T-S29-01 (R3a): EIP-1559 gas oracle integration
- T-S29-02 (R3a): Fee bumping for stuck transactions
- T-S29-03 (R5): DeFi + screening test suite (40+ tests)

### Phase 6: Multi-Tenant (Sprint 30-31)

**Sprint 30: Tenant Isolation**
- T-S30-01 (R4): Tenant isolation middleware (header/JWT claim extraction)
- T-S30-02 (R2): NATS subject namespacing per tenant
- T-S30-03 (R2): Per-tenant key store isolation (tenant KEK wrapping)

**Sprint 31: Webhooks & Observability**
- T-S31-01 (R4): Webhook delivery engine with retry
- T-S31-02 (R4): Tenant management API
- T-S31-03 (R4): Prometheus metrics + structured logging + health endpoints
- T-S31-04 (R5): Multi-tenant isolation test suite (30+ tests)

### Phase 7: Compliance (Sprint 32-33)

**Sprint 32: Audit Preparation**
- T-S32-01 (R7): SOC 2 control mapping document
- T-S32-02 (R1): Cryptographic audit package (specs, proofs, test vectors)
- T-S32-03 (R6): STRIDE threat model document

**Sprint 33: Documentation & Engagement**
- T-S33-01 (R7 + R6): Security whitepaper
- T-S33-02 (R4): AML/KYT compliance trait + mock
- T-S33-03 (R4 + R6): Incident response playbook update
- T-S33-04 (R7): Engage external audit firm

### Phase 8: Launch (Sprint 34-35)

**Sprint 34: SDK & Documentation**
- T-S34-01 (R0): crates.io publish preparation (semver, metadata, docs)
- T-S34-02 (R4): OpenAPI 3.0 spec for gateway API
- T-S34-03 (R8): TypeScript SDK v0.1
- T-S34-04 (R8): Python SDK v0.1

**Sprint 35: Infrastructure & Launch**
- T-S35-01 (R9): Docker Compose reference deployment
- T-S35-02 (R9): Kubernetes Helm chart
- T-S35-03 (R9): Terraform modules (AWS + GCP)
- T-S35-04 (R5): Load testing (1000 concurrent sessions)
- T-S35-05 (R5): Chaos testing (node failure, network partition)
- T-S35-06 (R7): CHANGELOG.md, release notes, GA announcement

---

## 7. Success Metrics

### 7.1 Test Coverage

| Milestone | Target Test Count | Current |
|-----------|-------------------|---------|
| M1 (Sprint 18) | 550+ | 540 |
| M2 (Sprint 21) | 620+ | — |
| M3 (Sprint 23) | 660+ | — |
| M4 (Sprint 26) | 730+ | — |
| M5 (Sprint 29) | 780+ | — |
| M6 (Sprint 31) | 820+ | — |
| M7 (Sprint 33) | 840+ | — |
| M8 (Sprint 35) | 900+ | — |

### 7.2 Security Audit Requirements

| Requirement | Target | Status |
|-------------|--------|--------|
| Zero CRITICAL findings | Maintained | ACHIEVED |
| Zero HIGH findings | Maintained | ACHIEVED |
| All MEDIUM findings closed or documented | By M1 (Sprint 18) | IN PROGRESS |
| External cryptographic audit | Engaged by M7 (Sprint 33) | NOT STARTED |
| External pen test | Completed by M8 (Sprint 35) | NOT STARTED |
| SOC 2 Type II readiness | Controls documented by M7 | NOT STARTED |

### 7.3 Performance Benchmarks

| Operation | Target (2-of-3) | Protocol | Milestone |
|-----------|-----------------|----------|-----------|
| Keygen | < 500ms | GG20 | M1 |
| Keygen | < 200ms | CGGMP21 | M2 |
| Keygen | < 150ms | FROST | M1 |
| Signing | < 200ms | GG20 | M1 |
| Signing | < 100ms | CGGMP21 (pre-sign online) | M2 |
| Signing | < 50ms | FROST | M1 |
| Key refresh | < 1s | All protocols | M1 |
| Throughput | > 100 signs/sec | CGGMP21 (batched pre-sign) | M8 |
| P99 latency (sign) | < 500ms | Any protocol | M8 |

### 7.4 Enterprise Readiness Checklist

| Requirement | Description | Milestone |
|-------------|-------------|-----------|
| Multi-chain support | 50+ chains with correct encoding and verification | ACHIEVED |
| Key share isolation | No single point holds > 1 share | ACHIEVED (DEC-015) |
| Policy enforcement | No signing without policy pass | ACHIEVED |
| Approval workflows | Quorum-based with SoD | ACHIEVED |
| Audit trail | Immutable, hash-chained, exportable | ACHIEVED |
| Auth system | mTLS + Session JWT + Bearer JWT | ACHIEVED |
| RBAC + ABAC | Role-based + attribute-based access control | ACHIEVED |
| Key lifecycle | Refresh + reshare + freeze/unfreeze | ACHIEVED |
| Disaster recovery | Multi-cloud distribution + quorum risk assessment | ACHIEVED |
| MPC-CMP protocol | 1-round signing, malicious-secure | M2 |
| HSM integration | Hardware-isolated key encryption | M3 |
| Advanced policies | Nested rules, delegation, org hierarchy | M4 |
| Transaction screening | Real-time threat intelligence | M5 |
| Multi-tenant | Isolated organizations | M6 |
| Compliance ready | SOC 2 controls, audit package | M7 |
| Production deployment | Helm, Terraform, load-tested | M8 |

### 7.5 Competitive Position Target

By M8 (Production Launch), Vaultex should:

| Dimension | Target Position |
|-----------|----------------|
| Security | **Best in class** — open-source + external audit + SGX enclave option |
| Transparency | **Unmatched** — full source code, published threat model, public audit reports |
| Protocol | **Top tier** — CGGMP21 + FROST + GG20 (more protocol options than any competitor) |
| Chain coverage | **Competitive** — 50+ chains (matching Fireblocks) |
| Policy engine | **Competitive** — nested rules + delegation (matching Fordefi) |
| Developer experience | **Best for SDK** — Rust-native, crates.io, TypeScript + Python wrappers |
| Multi-tenant | **Competitive** — matching Cobo/Fireblocks |
| DeFi access | **Competitive** — protocol adapters + screening (matching Fireblocks) |
| Compliance | **Preparation complete** — SOC 2 controls documented, audit engaged |

---

## Appendix: Decision References

This roadmap builds on and extends the following architectural decisions:

| Decision | Reference | Roadmap Impact |
|----------|-----------|----------------|
| DEC-001 | Distributed ECDSA (no reconstruction) | Foundation — all protocol work builds on this |
| DEC-004 | GG20 hard commitment | M2 extends this to CGGMP21 |
| DEC-007 | ChainRegistry unified factory | M5 DeFi adapters use ChainRegistry |
| DEC-008 | FROST reshare = fresh DKG | M2 CGGMP21 reshare follows same pattern |
| DEC-009 | Work on `dev` branch | All milestones follow this workflow |
| DEC-012 | SignAuthorization independent verification | M1 hardens this, M4 extends with delegation |
| DEC-013 | 3 auth methods (mTLS, Session JWT, Bearer JWT) | M6 adds tenant-aware auth |
| DEC-014 | Redis + KMS/HSM migration | M3 implements real HSM backend |
| DEC-015 | Gateway holds 0 shares, nodes hold 1 each | Foundation for all multi-tenant + HSM work |

---

## Appendix: Open Security Findings Tracker

All Sprint 17 MEDIUM/LOW findings have been resolved:

| Finding | Severity | Target Sprint | Owner | Status |
|---------|----------|---------------|-------|--------|
| SEC-008 | MEDIUM | Sprint 17 | R1 | RESOLVED |
| SEC-013 | MEDIUM | Sprint 17 | R1 | RESOLVED |
| SEC-014 | LOW | Sprint 17 | R2 | RESOLVED |
| SEC-017 | LOW | Sprint 17 | R3c | RESOLVED |
| SEC-018 | LOW | Sprint 17 | R2 | MITIGATED |
| SEC-019 | LOW | Sprint 17 | R0 | RESOLVED |
| SEC-023 | LOW | Sprint 17 | R3d | RESOLVED |
| SEC-025 | MEDIUM | Sprint 17 | R2 | RESOLVED |

Remaining open findings from DEC-015 audit (non-blocking, deferred to Sprint 18):

| Finding | Severity | Target Sprint | Owner |
|---------|----------|---------------|-------|
| SEC-026 | MEDIUM | Sprint 18 | R2 |
| SEC-027 | MEDIUM | Sprint 18 | R2 |
| SEC-028 | LOW | Sprint 18 | R2 |
| SEC-029 | LOW | Sprint 18 | R1 |
| SEC-030 | LOW | Sprint 18 | R2 |
| SEC-031 | LOW | Sprint 18 | R2 |

---

*This roadmap is a living document. It will be updated at the end of each milestone with actual results, revised timelines, and new priorities discovered during execution.*

*Last updated: 2026-03-19 by R7 PM Agent*
