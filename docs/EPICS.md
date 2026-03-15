# MPC Wallet SDK — Epic & Story Breakdown

**Version:** 0.1.0-draft  
**Date:** 2026-03-15  
**Author:** R7 PM Agent

Epic phases:
- **Phase 0** — Interface freeze (must complete before Phase 1 work starts on that interface)
- **Phase 1** — Core crypto, transport, storage, chain adapters
- **Phase 2** — Enterprise services (policy, approvals, session manager)
- **Phase 3** — Hardening, chaos, multi-cloud ops

Story status values: `pending` | `in-progress` | `done` | `blocked`

---

## Epic 0: Interface Freeze

**Owner Agent:** R0 (Architect)  
**Phase:** 0  
**Status:** In Progress (KeyStore missing `freeze`; `CryptoScheme` variants stable)

### Why
All four public traits are contracts between agents. Every story in Epics H, E, D depends on
these interfaces being stable. No implementation work should begin on a trait method that is
not yet defined.

### Stories

| ID | Story | Agent | Branch | Acceptance Criteria | Status |
|----|-------|-------|--------|--------------------|----|
| 0-1 | Add `freeze` / `unfreeze` to `KeyStore` trait | R0 | `agent/r0-interface` | `KeyStore::freeze(group_id)` and `::unfreeze(group_id)` compile; `cargo check --workspace` green | pending |
| 0-2 | Document all public types with rustdoc | R0 | `agent/r0-interface` | Every `pub` item in `mod.rs` files has `///` comment explaining its role | pending |
| 0-3 | Add `reshare` method stub to `MpcProtocol` | R0 | `agent/r0-interface` | `MpcProtocol::reshare(...)` defined; R1 can implement; `cargo check` green | pending |
| 0-4 | Bump `KeyShare` to include `frozen: bool` field | R0 | `agent/r0-interface` | `KeyShare.frozen` field exists; existing JSON deserialization still works (default false) | pending |

---

## Epic A: Identity & Access

**Owner Agent:** R4 (Service)  
**Phase:** 2  
**Status:** Not Started

### Why
Without OIDC auth and RBAC, the API gateway cannot distinguish legitimate requests from
unauthorized ones. All enterprise service stories in Epics B–D depend on knowing who the caller is.

### Stories

| ID | Story | Agent | Branch | Acceptance Criteria | Status |
|----|-------|-------|--------|--------------------|----|
| A1 | OIDC JWT validation middleware with JWKS caching | R4 | `agent/r4-identity` | Middleware validates RS256/ES256 JWTs; JWKS cached with TTL; expired token returns 401 | pending |
| A2 | RBAC permission model (initiator / approver / admin) | R4 | `agent/r4-identity` | Three roles defined; endpoint guards enforce minimum role; tests cover allow and deny paths | pending |
| A3 | ABAC attribute extensions | R4 | `agent/r4-identity` | JWT claims include `dept`, `cost_center`, `risk_tier`; policy evaluator can read attributes | pending |
| A4 | Step-up MFA for admin actions | R4 | `agent/r4-identity` | Admin endpoints require additional MFA claim in JWT; missing claim returns 403 | pending |

---

## Epic B: Policy Engine

**Owner Agent:** R4 (Service)  
**Phase:** 2  
**Status:** Not Started

### Why
The "no policy → no sign" rule is the primary defense against unauthorized transfers. Without
the policy engine, all other security controls can be bypassed by simply initiating a signing
session without a policy check.

### Stories

| ID | Story | Agent | Branch | Acceptance Criteria | Status |
|----|-------|-------|--------|--------------------|----|
| B1 | Policy schema v1 + semantic versioning | R4 | `agent/r4-policy` | JSON Schema for policy document; version field; schema validation rejects invalid docs | pending |
| B2 | Signed policy bundle releases | R4 | `agent/r4-policy` | Policy bundle includes Ed25519 signature from SECURITY quorum; invalid sig rejected at load | pending |
| B3 | Policy evaluator: allowlists + velocity limits | R4 | `agent/r4-policy` | Evaluator returns Deny for out-of-allowlist address; Deny for over-limit amount; Allow for valid tx | pending |
| B4 | Policy templates: Exchange / Treasury / Custodian | R4 | `agent/r4-policy` | Three pre-built templates loadable; each has sensible defaults documented | pending |
| B5 | "No policy → no sign" session gate | R4 | `agent/r4-policy` | Session creation without loaded policy returns `PolicyRequired` error; unit test passes | pending |

---

## Epic C: Approvals & Separation of Duties

**Owner Agent:** R4 (Service)  
**Phase:** 2  
**Status:** Not Started

### Why
Enterprise custody requires provable, non-repudiable approvals. The approver's cryptographic
signature over the exact approval payload is the audit evidence.

### Stories

| ID | Story | Agent | Branch | Acceptance Criteria | Status |
|----|-------|-------|--------|--------------------|----|
| C1 | Approver payload signing (Ed25519 / P256) | R4 | `agent/r4-approvals` | Approver signs `ApprovalPayload { session_id, tx_fingerprint, timestamp }`; signature stored in ledger | pending |
| C2 | Quorum enforcement + configurable hold periods | R4 | `agent/r4-approvals` | M-of-N quorum from policy enforced; session blocked until hold period elapsed; tests cover edge cases | pending |
| C3 | Maker / checker / approver SoD validation | R4 | `agent/r4-approvals` | Same `user_id` cannot fill two SoD roles in same session; violation returns `SodViolation` error | pending |
| C4 | Break-glass approvals with extra evidence | R4 | `agent/r4-approvals` | Break-glass path requires N+1 approvals + signed reason; creates separate audit evidence bundle | pending |

---

## Epic D: Session Manager

**Owner Agent:** R4 (Service)  
**Phase:** 2  
**Status:** Not Started

### Why
The session manager is the orchestration heart of every signing operation. It enforces the
ordering guarantee: policy check → approval quorum → tx_fingerprint lock → MPC signing.

### Stories

| ID | Story | Agent | Branch | Acceptance Criteria | Status |
|----|-------|-------|--------|--------------------|----|
| D1 | Persistent state machine for signing sessions | R4 | `agent/r4-session` | States: Pending → Approved → Signing → Done / Failed; state persisted to storage; recovery after restart | pending |
| D2 | Idempotent session creation + tx_fingerprint lock | R4 | `agent/r4-session` | Duplicate `tx_fingerprint` returns existing session ID; once locked, fingerprint cannot change | pending |
| D3 | Retry budget + exponential back-off | R4 | `agent/r4-session` | Configurable max retries; back-off doubles each attempt; exceeding budget moves session to Failed | pending |
| D4 | Quorum degrade policy (node unavailable) | R4 | `agent/r4-session` | If threshold nodes available < configured min, session waits or aborts per policy; test with simulated node kill | pending |

---

## Epic E: Transport Hardening

**Owner Agent:** R2 (Infrastructure)  
**Phase:** 1  
**Status:** Not Started

### Why
The `NatsTransport` implementation is entirely `todo!()`. Without a working production transport,
the system can only run in single-machine test configurations. ECDH per-session encryption and
signed envelopes with replay protection are required before any real deployment.

### Stories

| ID | Story | Agent | Branch | Acceptance Criteria | Status |
|----|-------|-------|--------|--------------------|----|
| E1 | Implement `NatsTransport::connect` + `send` + `recv` | R2 | `agent/r2-nats` | No `todo!()` stubs; two-party integration test (in separate Tokio tasks) passes; `cargo test -p mpc-wallet-core` green | pending |
| E2 | mTLS configuration + cert rotation support | R2 | `agent/r2-nats` | `NatsTransport` accepts `rustls::ClientConfig`; cert reload without restart | pending |
| E3 | Per-session ECDH layer (X25519 + ChaCha20-Poly1305) | R2 | `agent/r2-nats` | Messages encrypted beyond TLS; decryption fails with wrong session key; unit test passes | pending |
| E4 | Signed envelopes (Ed25519) + seq_no + TTL replay protection | R2 | `agent/r2-nats` | Replayed message (stale seq_no or expired TTL) is rejected; chaos test passes | pending |
| E5 | JetStream subjects + per-tenant ACL configuration | R2 | `agent/r2-nats` | JetStream subject naming scheme documented; ACL config applied in integration test | pending |

---

## Epic F: Audit Ledger

**Owner Agent:** R2 (Infrastructure)  
**Phase:** 1–2  
**Status:** Not Started

### Why
Immutable, verifiable audit evidence is a hard requirement for SOC 2 and financial custody
compliance. Without it, the system cannot prove what was signed, by whom, under what policy.

### Stories

| ID | Story | Agent | Branch | Acceptance Criteria | Status |
|----|-------|-------|--------|--------------------|----|
| F1 | Append-only ledger + hash chain + service Ed25519 signature | R2 | `agent/r2-audit` | Each entry commits `hash(prev_entry)`; service signs each entry; `cargo test` passes | pending |
| F2 | Evidence pack exporter | R2 | `agent/r2-audit` | Exports: policy version, approval signatures, tx hashes, ledger entries as JSON bundle | pending |
| F3 | `audit-verify` CLI command | R2 | `agent/r2-audit` | CLI reads ledger, verifies hash chain and signatures; prints PASS or identifies first tampered entry | pending |
| F4 | WORM storage integration (S3 Object Lock) | R2 | `agent/r2-audit` | Ledger entries written to S3 with Object Lock retention; test with LocalStack | pending |

---

## Epic G: Transaction Simulation

**Owner Agents:** R3a (EVM), R3b (BTC), R3c (SOL)  
**Phase:** 2  
**Status:** Not Started

### Why
Transaction simulation is the last defense before a signature is produced. A misconfigured or
malicious transaction should be caught here, not after broadcast.

### Stories

| ID | Story | Agent | Branch | Acceptance Criteria | Status |
|----|-------|-------|--------|--------------------|----|
| G1 | EVM: `eth_call` simulation + ABI decode + proxy detect | R3a | `agent/r3a-sim` | Simulated revert raises `SimulationFailed`; proxy contract detected via EIP-1967 storage slot | pending |
| G2 | Bitcoin: PSBT validation + fee sanity check | R3b | `agent/r3b-sim` | PSBT with fee > 10x estimated rate rejected; unit test covers normal and high-fee cases | pending |
| G3 | Solana: program allowlist + writable account check | R3c | `agent/r3c-sim` | Transaction to non-allowlisted program rejected; non-signer writable account flagged | pending |
| G4 | Risk score output + policy hook | R4 | `agent/r4-policy` | All simulations return `RiskScore { value: u8, flags: Vec<RiskFlag> }`; policy hook can block on threshold | pending |

---

## Epic H: Key Lifecycle

**Owner Agent:** R1 (Crypto)  
**Phase:** 1  
**Status:** Not Started — Sprint 1 priority

### Why
Production MPC wallets must support proactive refresh (to limit share exposure window) and
freeze/unfreeze (for incident response). Without these, the system cannot meet enterprise
operational requirements.

### Stories

| ID | Story | Agent | Branch | Acceptance Criteria | Status |
|----|-------|-------|--------|--------------------|----|
| H1 | Proactive key refresh (share rotation without key change) | R1 | `agent/r1-zeroize` | `MpcProtocol::refresh(key_share, ...)` produces new shares; group public key unchanged; integration test passes | pending |
| H2 | Resharing: add/remove nodes, change threshold | R1 | `agent/r1-zeroize` | Old node set can produce new shares for new node set; public key unchanged; requires approval quorum (gated) | pending |
| H3 | Freeze / unfreeze wallet (coordinate with R0 for `KeyStore` trait) | R1 | `agent/r1-zeroize` | `KeyStore::freeze(group_id)` persists frozen state; any `sign` call on frozen key returns `KeyFrozen` error | pending |
| H4 | Disaster recovery playbook + drill test | R1 | `agent/r1-zeroize` | Recovery playbook in docs; test reconstructs wallet from 3-of-5 backup shards; verified by `audit-verify` | pending |

---

## Epic I: Multi-cloud Ops

**Owner Agent:** R2 (Infrastructure)  
**Phase:** 3  
**Status:** Not Started

### Why
Enterprise deployments require nodes distributed across cloud providers so no single provider
outage can compromise the quorum. This requires enforcement at the infrastructure layer, not
just documentation.

### Stories

| ID | Story | Agent | Branch | Acceptance Criteria | Status |
|----|-------|-------|--------|--------------------|----|
| I1 | Node distribution constraint enforcement | R2 | `agent/r2-infra` | Policy rule: `max_nodes_per_cloud: 2` enforced; adding 3rd node from same cloud returns error | pending |
| I2 | Health / heartbeat service + quorum risk metric | R2 | `agent/r2-infra` | Each node publishes heartbeat; quorum risk Prometheus metric updates when node drops; alert fires | pending |
| I3 | RPC provider failover for broadcaster | R2 | `agent/r2-infra` | Broadcaster retries across ranked RPC list; primary failure triggers secondary; test with mock RPC | pending |
| I4 | Chaos test suite: node kill, NATS partition, replay | R5 | `agent/r5-qa` | Three chaos scenarios pass: node kill mid-round, NATS partition, replayed message rejected | pending |

---

## Epic J: Production Hardening

**Owner Agents:** R1 (Crypto), R3c (Solana), R3d (Sui)  
**Phase:** 1  
**Status:** Not Started — Sprint 1 priority (highest urgency)

### Why
The current codebase has three critical production blockers:
1. GG20 signing **reconstructs the full private key** via Lagrange interpolation — this is
   a fatal security flaw for a custody product.
2. Solana transaction builder produces correct binary format but must be validated against the
   real Solana SDK to confirm field ordering and encoding edge cases.
3. Sui transaction builder uses JSON instead of BCS encoding.

These must be fixed before any other feature work is meaningful.

### Stories

| ID | Story | Agent | Branch | Acceptance Criteria | Status |
|----|-------|-------|--------|--------------------|----|
| J1 | Replace GG20 simulation with real multi-party ECDSA (no key reconstruction) | R1 | `agent/r1-zeroize` | `sign()` never calls `lagrange_interpolate` or equivalent; partial sigs combined without reconstructing secret; integration test: sign + verify on secp256k1 curve | pending |
| J2 | Full BCS transaction serialization for Sui | R3d | `agent/r3d-sui-followup` | `build_sui_transaction` produces BCS-encoded `TransactionData`; `finalize_sui_transaction` produces valid 97-byte Sui signature; `cargo test -p mpc-wallet-chains` green | pending |
| J3 | Validate / harden Solana wire-format transaction | R3c | `agent/r3c-sol` | Binary serialization matches Solana SDK output byte-for-byte; test: build tx, deserialize with solana-sdk, verify structure; `cargo test -p mpc-wallet-chains` green | pending |
| J4 | Complete `zeroize` coverage across all protocol impls | R1 | `agent/r1-zeroize` | `Gg20ShareData`, FROST share scalars, ephemeral signing nonces all use `ZeroizeOnDrop`; `cargo test` green | pending |
