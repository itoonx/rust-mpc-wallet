# MPC Wallet SDK — Epic & Story Breakdown

**Version:** 1.0.0
**Date:** 2026-04-01
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
**Status:** COMPLETE (Sprint 1-19) -- all traits stable since Sprint 19

### Why
All four public traits are contracts between agents. Every story in Epics H, E, D depends on
these interfaces being stable. No implementation work should begin on a trait method that is
not yet defined.

### Stories

| ID | Story | Agent | Delivered | Status |
|----|-------|-------|-----------|--------|
| 0-1 | Add `freeze` / `unfreeze` to `KeyStore` trait | R0 | Sprint 1 | done |
| 0-2 | Document all public types with rustdoc | R0 | Sprint 4 | done |
| 0-3 | Add `reshare` method stub to `MpcProtocol` | R0 | Sprint 12 | done |
| 0-4 | Bump `KeyShare` to include `frozen: bool` field | R0 | Sprint 4 | done |

---

## Epic A: Identity & Access

**Owner Agent:** R4 (Service)
**Phase:** 2
**Status:** COMPLETE (Sprint 7-9)

### Why
Without OIDC auth and RBAC, the API gateway cannot distinguish legitimate requests from
unauthorized ones. All enterprise service stories in Epics B-D depend on knowing who the caller is.

### Stories

| ID | Story | Agent | Delivered | Status |
|----|-------|-------|-----------|--------|
| A1 | OIDC JWT validation middleware with JWKS caching | R4 | Sprint 8 | done |
| A2 | RBAC permission model (initiator / approver / admin) | R4 | Sprint 7 | done |
| A3 | ABAC attribute extensions | R4 | Sprint 9 | done |
| A4 | Step-up MFA for admin actions | R4 | Sprint 9 | done |

---

## Epic B: Policy Engine

**Owner Agent:** R4 (Service)
**Phase:** 2
**Status:** COMPLETE (Sprint 4-11, extended Sprint 24-26)

### Why
The "no policy, no sign" rule is the primary defense against unauthorized transfers. Without
the policy engine, all other security controls can be bypassed by simply initiating a signing
session without a policy check.

### Stories

| ID | Story | Agent | Delivered | Status |
|----|-------|-------|-----------|--------|
| B1 | Policy schema v1 + semantic versioning | R4 | Sprint 4 | done |
| B2 | Signed policy bundle releases | R4 | Sprint 10 | done |
| B3 | Policy evaluator: allowlists + velocity limits | R4 | Sprint 8 | done |
| B4 | Policy templates: Exchange / Treasury / Custodian | R4 | Sprint 11 | done |
| B5 | "No policy, no sign" session gate | R4 | Sprint 4 | done |
| B6 | Policy DSL (composable AND/OR/NOT rules) | R4 | Sprint 24 | done |
| B7 | Address whitelist with 24h cool-down | R4 | Sprint 26 | done |
| B8 | Multi-window velocity limits | R4 | Sprint 26 | done |

---

## Epic C: Approvals & Separation of Duties

**Owner Agent:** R4 (Service)
**Phase:** 2
**Status:** COMPLETE (Sprint 5)

### Why
Enterprise custody requires provable, non-repudiable approvals. The approver's cryptographic
signature over the exact approval payload is the audit evidence.

### Stories

| ID | Story | Agent | Delivered | Status |
|----|-------|-------|-----------|--------|
| C1 | Approver payload signing (Ed25519 / P256) | R4 | Sprint 5 | done |
| C2 | Quorum enforcement + configurable hold periods | R4 | Sprint 5 | done |
| C3 | Maker / checker / approver SoD validation | R4 | Sprint 5 | done |
| C4 | Break-glass approvals with extra evidence | R4 | Sprint 5 | done |

---

## Epic D: Session Manager

**Owner Agent:** R4 (Service)
**Phase:** 2
**Status:** COMPLETE (Sprint 4-6)

### Why
The session manager is the orchestration heart of every signing operation. It enforces the
ordering guarantee: policy check, approval quorum, tx_fingerprint lock, MPC signing.

### Stories

| ID | Story | Agent | Delivered | Status |
|----|-------|-------|-----------|--------|
| D1 | Persistent state machine for signing sessions | R4 | Sprint 6 | done |
| D2 | Idempotent session creation + tx_fingerprint lock | R4 | Sprint 4 | done |
| D3 | Retry budget + exponential back-off | R4 | Sprint 6 | done |
| D4 | Quorum degrade policy (node unavailable) | R4 | Sprint 13 | done |

---

## Epic E: Transport Hardening

**Owner Agent:** R2 (Infrastructure)
**Phase:** 1
**Status:** COMPLETE (Sprint 3-18)

### Why
The `NatsTransport` implementation must support production multi-party communication. ECDH
per-session encryption and signed envelopes with replay protection are required before any
real deployment.

### Stories

| ID | Story | Agent | Delivered | Status |
|----|-------|-------|-----------|--------|
| E1 | Implement `NatsTransport::connect` + `send` + `recv` | R2 | Sprint 3 | done |
| E2 | mTLS configuration + cert rotation support | R2 | Sprint 7 | done |
| E3 | Per-session ECDH layer (X25519 + ChaCha20-Poly1305) | R2 | Sprint 8 | done |
| E4 | Signed envelopes (Ed25519) + seq_no + TTL replay protection | R2 | Sprint 5-6 | done |
| E5 | JetStream subjects + per-tenant ACL configuration | R2 | Sprint 14 | done |
| E6 | Signed control plane messages (SEC-026) | R2 | Sprint 18 | done |

---

## Epic F: Audit Ledger

**Owner Agent:** R2 (Infrastructure)
**Phase:** 1-2
**Status:** COMPLETE (Sprint 5-14)

### Why
Immutable, verifiable audit evidence is a hard requirement for SOC 2 and financial custody
compliance. Without it, the system cannot prove what was signed, by whom, under what policy.

### Stories

| ID | Story | Agent | Delivered | Status |
|----|-------|-------|-----------|--------|
| F1 | Append-only ledger + hash chain + service Ed25519 signature | R2 | Sprint 5 | done |
| F2 | Evidence pack exporter | R2 | Sprint 6 | done |
| F3 | `audit-verify` CLI command | R2 | Sprint 7 | done |
| F4 | WORM storage integration (S3 Object Lock) | R2 | Sprint 14 | done |

---

## Epic G: Transaction Simulation

**Owner Agents:** R3a (EVM), R3b (BTC), R3c (SOL), R3d (SUI)
**Phase:** 2
**Status:** COMPLETE (Sprint 9-11)

### Why
Transaction simulation is the last defense before a signature is produced. A misconfigured or
malicious transaction should be caught here, not after broadcast.

### Stories

| ID | Story | Agent | Delivered | Status |
|----|-------|-------|-----------|--------|
| G1 | EVM: `eth_call` simulation + ABI decode + proxy detect | R3a | Sprint 9 | done |
| G2 | Bitcoin: PSBT validation + fee sanity check | R3b | Sprint 10 | done |
| G3 | Solana: program allowlist + writable account check | R3c | Sprint 11 | done |
| G4 | Sui: value + gas budget simulation | R3d | Sprint 11 | done |
| G5 | CLI simulate command | R4 | Sprint 11 | done |

---

## Epic H: Key Lifecycle

**Owner Agent:** R1 (Crypto)
**Phase:** 1
**Status:** COMPLETE (Sprint 8-13)

### Why
Production MPC wallets must support proactive refresh (to limit share exposure window) and
freeze/unfreeze (for incident response). Without these, the system cannot meet enterprise
operational requirements.

### Stories

| ID | Story | Agent | Delivered | Status |
|----|-------|-------|-----------|--------|
| H1 | Proactive key refresh (GG20 + FROST Ed25519 + FROST Secp256k1) | R1 | Sprint 8-10 | done |
| H2 | GG20 resharing: add/remove nodes, change threshold | R1 | Sprint 12 | done |
| H3 | Freeze / unfreeze wallet persistence | R1 | Sprint 4 | done |
| H4 | FROST reshare (fresh DKG, new group key) | R1 | Sprint 13 | done |
| H5 | CGGMP21 key refresh (additive re-sharing) | R1 | Sprint 21 | done |
| H6 | Disaster recovery plan + drill test | R1 | Sprint 13 | done |

---

## Epic I: Multi-cloud Ops

**Owner Agent:** R2 (Infrastructure)
**Phase:** 3
**Status:** COMPLETE (Sprint 12-13)

### Why
Enterprise deployments require nodes distributed across cloud providers so no single provider
outage can compromise the quorum. This requires enforcement at the infrastructure layer, not
just documentation.

### Stories

| ID | Story | Agent | Delivered | Status |
|----|-------|-------|-----------|--------|
| I1 | Node distribution constraint enforcement | R2 | Sprint 12 | done |
| I2 | Health / heartbeat service + quorum risk metric | R2 | Sprint 12 | done |
| I3 | RPC provider failover for broadcaster | R2 | Sprint 13 | done |
| I4 | Chaos test suite: node kill, NATS partition, replay | R5 | Sprint 13 | done |

---

## Epic J: Production Hardening

**Owner Agents:** R1 (Crypto), R3c (Solana), R3d (Sui), R6 (Security)
**Phase:** 1
**Status:** COMPLETE (Sprint 2-31)

### Why
The codebase required fixing critical security flaws (GG20 key reconstruction, chain encoding
bugs), implementing production-grade protocols (CGGMP21, Stark ECDSA), and resolving all 68
security findings across 30 sprints of hardening.

### Stories

| ID | Story | Agent | Delivered | Status |
|----|-------|-------|-----------|--------|
| J1 | Replace GG20 simulation with distributed ECDSA (SEC-001) | R1 | Sprint 2 | done |
| J2 | Full BCS transaction serialization for Sui (SEC-011) | R3d | Sprint 2 | done |
| J3 | Validate / harden Solana wire-format transaction | R3c | Sprint 2 | done |
| J4 | Complete `zeroize` coverage across all protocol impls | R1 | Sprint 4-17 | done |
| J5 | CGGMP21 protocol (keygen + signing + pre-signing) | R1 | Sprint 19-21 | done |
| J6 | Real Paillier cryptosystem + ZK proofs (5/5) | R1 | Sprint 27a-28 | done |
| J7 | TSSHOCK CVE hardening (Fiat-Shamir) | R1 | Sprint 29 | done |
| J8 | Stark ECDSA threshold signing | R1 | Sprint 31 | done |
| J9 | Chi_i Schnorr PoK for identifiable abort | R1 | Sprint 31 | done |
| J10 | All 68 security findings resolved | R6 | Sprint 30 | done |

---

## Summary

All 11 epics (0 + A-J) are **COMPLETE**. The project has delivered:

- 4 production threshold signing protocols (GG20, CGGMP21, FROST, Stark ECDSA)
- 50+ chain support with transaction simulation
- Enterprise features: RBAC, ABAC, MFA, policy DSL, approval workflows, audit ledger
- Production architecture: gateway/node split, NATS transport, Vault, KMS stubs
- 68/68 security findings resolved across 17 CVEs
- 882 tests + 16 E2E tests, CI fully green

Next phase: Sprint 32-36 (deployment readiness, SDK release, external audit).
