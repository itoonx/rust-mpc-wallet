# Threat Model

> MPC Wallet SDK (Vaultex) — Threshold Multi-Party Computation Wallet
>
> Last updated: 2026-04-01

## 1. System Overview

The MPC Wallet SDK implements threshold signing where no single party ever holds a complete private key. The production architecture consists of:

```
Client (web/mobile/API)
    │
    ▼
API Gateway (orchestrator, holds ZERO key shares)
    │ NATS message bus (mTLS)
    ├── MPC Node 1 (holds share 1, EncryptedFileStore)
    ├── MPC Node 2 (holds share 2, EncryptedFileStore)
    └── MPC Node 3 (holds share 3, EncryptedFileStore)
```

- **Gateway:** Authenticates clients, enforces policy, collects approvals, orchestrates MPC rounds. Holds no key shares (DEC-015).
- **MPC Nodes:** Each holds exactly one key share. Communicate via NATS for protocol rounds. Independently verify sign authorization before participating.
- **Supported Protocols:** GG20 (threshold ECDSA), CGGMP21 (threshold ECDSA with identifiable abort), FROST (Ed25519 and Secp256k1 Taproot), Stark (threshold ECDSA on the StarkNet curve).

## 2. Assets

| Asset | Location | Sensitivity |
|-------|----------|-------------|
| Key shares (secp256k1, Ed25519, Stark field scalars) | MPC node EncryptedFileStore (Argon2id + AES-256-GCM) | CRITICAL — compromise of t shares reconstructs the key |
| Paillier secret keys (p, q, lambda, mu) | MPC node memory during CGGMP21 keygen/signing | CRITICAL — enables extraction of peer shares via MtA |
| Pre-signatures (k_i, chi_i, big_r) | MPC node memory during CGGMP21 pre-signing | HIGH — nonce reuse leads to key extraction |
| Gateway Ed25519 signing key | Gateway process (signs SignAuthorization) | HIGH — forged authorizations bypass node verification |
| Session tokens (JWT, HMAC-SHA256) | Gateway memory / Redis (ChaCha20-Poly1305 encrypted) | HIGH — session hijack enables unauthorized signing |
| Node Ed25519 identity keys | MPC node process (signs protocol messages) | HIGH — impersonation of a node in MPC rounds |
| Audit log (hash-chained, Ed25519 signed) | Append-only storage | MEDIUM — tamper = undetectable unauthorized operations |
| Policy bundles (Ed25519 signed) | Gateway configuration | MEDIUM — bypass = unauthorized transaction approval |

## 3. Adversary Models

### 3.1 Malicious Party (< threshold t)

**Capability:** Controls fewer than t MPC nodes. Can observe own share, deviate from protocol, send malicious messages.

| Threat | Impact | Mitigation |
|--------|--------|------------|
| Inject malicious Paillier key with small factors | Extract other parties' shares in ~16 signatures (CVE-2023-33241) | Pifac ZK proof rejects N with any factor < 2^256; Pimod proof validates Blum modulus structure |
| Send inconsistent commitments during keygen | Bias public key or learn extra information | Feldman VSS with Schnorr proofs of knowledge; commit-then-reveal (SHA-256) in all keygen rounds |
| Send invalid signature shares during signing | Denial of service or blame shifting | CGGMP21 identifiable abort detects cheating party; GG20 signature verification before broadcast |
| Replay old protocol messages | Re-sign with stale nonce or re-run keygen | SignedEnvelope with monotonic seq_no per (session, party) + TTL expiry (SEC-007 fix) |
| Claim false party ID | Impersonate another node | Ed25519 signed envelopes authenticate sender identity; FROST validates `from` against expected signer set (SEC-013 fix) |
| Frame honest party via forged chi_i during identifiable abort | Honest party blamed and excluded; attacker gains advantage | Chi_i Schnorr proof of knowledge (Sprint 31): each party proves knowledge of chi_i during pre-signing; verifier checks sigma_i * G == e * K_i + r * Chi_i with proven Chi_i |
| Exploit TSSHOCK alpha-shuffle in Fiat-Shamir hashes | Forge ZK proofs by finding hash collisions across variable-length inputs | Length-prefixed encoding (hash_update_lp) in all Fiat-Shamir hashes prevents alpha-shuffle collisions (CVE-2022-47931 fix, Sprint 29) |
| Replay ZK proofs across sessions or parties | Re-use a valid proof from session A in session B | session_id + prover_index bound into all ZK proof challenges: Pienc, PiAffg, PiLogstar (CVE-2022-47930 fix, Sprint 29) |
| Submit malicious PiAffg proof with fake EC commitment | Bypass range proof to inject out-of-range MtA values | PiAffg commitment_bx is real EC point alpha*G, included in Fiat-Shamir hash; verifier checks z1*G == Bx + e*X (SEC-056 fix, Sprint 29) |
| Inject malicious MtA values in Stark pre-signing | Extract Stark private key shares via Paillier homomorphism | Stark protocol reuses CGGMP21 Paillier MtA with PiLogStarStark + PiAffgStark ZK proofs on Stark curve (Sprint 31b) |

### 3.2 Compromised Gateway

**Capability:** Full control of the orchestrator. Can forge requests, alter routing, attempt unauthorized signing. Holds zero key shares.

| Threat | Impact | Mitigation |
|--------|--------|------------|
| Forge sign requests to MPC nodes | Unauthorized transaction signing | SignAuthorization: Ed25519-signed proof verified independently by each node (DEC-012). Nodes check: gateway signature, message hash binding, policy_passed, approval quorum, 2-minute TTL |
| Replay a captured SignAuthorization | Double-sign the same transaction | authorization_id replay dedup with AuthorizationCache at each node (TTL-based expiry, max_entries capacity) |
| Forge control plane messages (keygen/freeze) | Trigger unauthorized keygen or freeze honest nodes | All control plane messages Ed25519-signed by gateway, verified by nodes via unwrap_signed_message() (SEC-026 fix) |
| Tamper with NATS routing | Partition or delay messages between nodes | MPC nodes verify message origin via Ed25519 signatures; protocol-level timeouts detect stalls |
| Bypass policy engine | Approve transactions that violate policy | Each node verifies policy_hash in SignAuthorization matches expected policy; policy bundles are Ed25519-signed |

### 3.3 Network Attacker (MITM on NATS)

**Capability:** Can observe, modify, drop, replay, and inject messages on the NATS transport layer.

| Threat | Impact | Mitigation |
|--------|--------|------------|
| Eavesdrop on protocol messages | Learn partial information about shares | Per-session ChaCha20-Poly1305 encryption (X25519 ECDH key agreement, HKDF-SHA256 key derivation) |
| Replay protocol messages | Disrupt protocol execution or nonce reuse | Monotonic seq_no per (session, sender) pair in SignedEnvelope; TTL-based expiry |
| Modify messages in transit | Inject malicious protocol payloads | Ed25519 signature over canonical envelope bytes; tampered messages fail verification |
| Drop messages | Denial of service | Protocol-level timeout and retry; does not compromise key security |
| MITM on NATS connection | Full message interception | NATS mTLS (NatsTlsConfig with PEM cert loading, client key zeroization) |

### 3.4 Insider (Admin with Access to One MPC Node)

**Capability:** Root access to one MPC node. Can read filesystem, dump memory, modify binaries.

| Threat | Impact | Mitigation |
|--------|--------|------------|
| Extract key share from disk | Obtains 1 of t shares (insufficient alone) | EncryptedFileStore: Argon2id (64MiB/3t/4p) + AES-256-GCM; password not stored on disk |
| Extract key share from memory | Obtains 1 of t shares | Zeroizing<Vec<u8>> for all share material; ZeroizeOnDrop on secret structs (SEC-004, SEC-008); PaillierSecretKey with Zeroize+ZeroizeOnDrop; Debug impls redact secrets (SEC-015) |
| Modify node binary to exfiltrate | Leak share or sign unauthorized | Out of scope for SDK; operational control: code signing, integrity monitoring, SGX enclaves (Sprint 23 prototype) |
| Collude with gateway operator | 1 share + orchestration control | Still requires t shares for signing; gateway holds 0 shares (DEC-015); nodes independently verify SignAuthorization |

## 4. Trust Boundaries

```
┌─────────────────────────────────────────────────────┐
│  EXTERNAL (untrusted)                               │
│  ┌───────────┐                                      │
│  │  Client   │                                      │
│  └─────┬─────┘                                      │
│        │ TLS + Auth (mTLS / Session JWT / Bearer JWT)│
├────────┼────────────────────────────────────────────┤
│  GATEWAY ZONE (semi-trusted — no key material)      │
│  ┌─────▼─────┐                                      │
│  │  Gateway   │ Auth, Policy, Approvals, Orchestrate│
│  └─────┬─────┘                                      │
│        │ NATS mTLS + SignedControlMessage            │
├────────┼────────────────────────────────────────────┤
│  MPC NODE ZONE (trusted — holds key shares)         │
│  ┌─────▼─────┐  ┌───────────┐  ┌───────────┐      │
│  │  Node 1   │  │  Node 2   │  │  Node 3   │      │
│  │  Share 1  │  │  Share 2  │  │  Share 3  │      │
│  └─────┬─────┘  └─────┬─────┘  └─────┬─────┘      │
│        │ Argon2id + AES-256-GCM                     │
│  ┌─────▼─────────────────▼───────────────▼─────┐   │
│  │  Encrypted Key Store (per-node, isolated)    │   │
│  └──────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────┘
```

### Boundary Crossings

| Boundary | Direction | Protection |
|----------|-----------|------------|
| Client → Gateway | Inbound | 3-method auth stack (mTLS → Session JWT → Bearer JWT); rate limiting (10 req/sec); present-but-invalid = fail (no fallthrough) |
| Gateway → NATS | Internal | NATS mTLS; Ed25519-signed control messages |
| NATS → MPC Node | Internal | SignedEnvelope verification; SignAuthorization verification; authorization_id replay dedup |
| MPC Node ↔ MPC Node (via NATS) | Internal | Per-session ChaCha20-Poly1305 encryption; Ed25519 signed envelopes; seq_no replay protection |
| MPC Node → KeyStore | Local | Argon2id key derivation; AES-256-GCM encryption; Zeroizing wrappers on all secret material |

## 5. Mitigation Summary

| Category | Mechanism | Protects Against | Reference |
|----------|-----------|------------------|-----------|
| **Message Authentication** | Ed25519 SignedEnvelope | Sender impersonation, message tampering | SEC-007 |
| **Replay Protection** | Monotonic seq_no + TTL expiry | Protocol message replay | SEC-007 |
| **Sign Authorization** | Ed25519-signed gateway proof, 2-min TTL | Compromised gateway unauthorized signing | DEC-012 |
| **Authorization Replay** | authorization_id + AuthorizationCache | Double-signing via captured authorization | SEC-025 |
| **Control Plane Auth** | SignedControlMessage | Forged keygen/sign/freeze commands | SEC-026 |
| **Paillier Key Validation** | Pimod (Blum modulus) + Pifac (no small factor) ZK proofs | CVE-2023-33241 small-factor key injection | Sprint 27a |
| **MtA Security** | Pienc, Piaff-g, Pilogstar ZK proofs | Malicious MtA inputs extracting shares | Sprint 27b |
| **Key Zeroization** | Zeroize + ZeroizeOnDrop on all secret types | Memory scraping after use | SEC-004, SEC-008 |
| **Key Encryption at Rest** | Argon2id (64MiB/3t/4p) + AES-256-GCM | Disk-level key extraction | SEC-006 |
| **Transport Encryption** | Per-session ChaCha20-Poly1305 (X25519 ECDH) | Network eavesdropping | Sprint 8 |
| **NATS Security** | mTLS with PEM cert loading, client key zeroization | Network MITM | Sprint 7 |
| **Auth System** | mTLS + Session JWT + Bearer JWT, no fallthrough | Unauthorized API access | DEC-013 |
| **Low-S Normalization** | Canonical ECDSA signatures (EIP-2) | Signature malleability | SEC-012 |
| **FROST Sender Validation** | Validate `from` against expected signer set | Party impersonation in FROST rounds | SEC-013 |
| **Identifiable Abort** | CGGMP21 cheater detection on invalid sigma_i + Chi_i Schnorr PoK | Blame-shifting and framing attack by malicious party | Sprint 20, Sprint 31 |
| **TSSHOCK Fiat-Shamir Hardening** | Length-prefixed hash_update_lp() + session_id/prover_index binding | CVE-2022-47931 alpha-shuffle, CVE-2022-47930 proof replay | Sprint 29 |
| **PiAffg EC Binding** | Real EC point commitment_bx = alpha*G in Fiat-Shamir | SEC-056 forged Pedersen commitment bypass | Sprint 29 |
| **Nonce Crash Safety** | FilePreSignatureStore with fsync + mark-before-use | SEC-037 nonce reuse after crash-replay | Sprint 30c |
| **Signed Control Plane** | Ed25519-signed control messages, unsigned paths removed | SEC-026/027 forged keygen/sign/freeze commands | Sprint 30b |
| **Stark Threshold ECDSA** | Feldman VSS over Stark field + PiLogStarStark/PiAffgStark proofs | Stark-specific key extraction via MtA | Sprint 31b |
| **Debug Redaction** | Manual Debug impls on all secret types | Secret material in logs | SEC-015 |

## 6. Known Limitations

| Limitation | Description | Status |
|------------|-------------|--------|
| GG20 coordinator nonce | GG20 protocol has a coordinator nonce dependency; mitigated by distributed nonce commitment in DEC-017 (deferred) | Tracked: DEC-017 |
| SGX enclave | SGX integration is prototype only (MockEnclaveProvider); not production-hardened | Sprint 23 prototype |
| KMS integration | AWS KMS signer is a stub; Ed25519 signing stays local per DEC-016 | Tracked: DEC-016 |

### Resolved Limitations (for historical reference)

| Limitation | Resolution | Sprint |
|------------|-----------|--------|
| Simulated MtA path (SEC-058) | Legacy Paillier deleted; real Paillier mandatory; legacy shares unconditionally rejected | Sprint 29 |
| Pre-signature nonce reuse on crash (SEC-037) | FilePreSignatureStore with fsync, mark-before-use pattern | Sprint 30c |
| Pienc Pedersen commitment (SEC-055) | Verified correct: Pedersen LHS bound into Fiat-Shamir challenge | Sprint 29 |
| PiAffg response binding (SEC-056) | commitment_bx is now real EC point alpha*G, included in Fiat-Shamir, verifier checks z1*G == Bx + e*X | Sprint 29 |
| PiLogstar verification (SEC-057) | Verified correct: EC verification equation is sound | Sprint 29 |

## 7. Current Threat Summary

**As of 2026-04-01, all 68 security findings (SEC-001 through SEC-060) are resolved.**

- **7 threshold signing protocols** are production-ready: GG20, CGGMP21, FROST Ed25519, FROST Secp256k1, Stark Threshold ECDSA, GG20 Refresh, CGGMP21 Refresh.
- **919 tests pass** (cargo test --workspace), including security regression tests.
- **0 open CRITICAL or HIGH findings.** All known attack vectors have mitigations in place.
- **TSSHOCK family (CVE-2022-47931, CVE-2022-47930):** Fully mitigated with length-prefixed Fiat-Shamir hashing and session/prover binding.
- **CVE-2023-33241 (small-factor Paillier):** Fully mitigated with Pimod + Pifac ZK proofs and 2048-bit minimum enforcement.
- **CVE-2025-66016 (missing ZK proof check):** NOT AFFECTED -- both Pimod and Pifac proofs are generated and verified for all peers during keygen.
- **Identifiable abort:** Sound -- Chi_i Schnorr proof of knowledge prevents framing attacks (Sprint 31).
- **Nonce safety:** FilePreSignatureStore provides crash-safe nonce reuse protection with fsync (Sprint 30c).
- **Control plane:** All unsigned paths removed; only Ed25519-signed control messages accepted (Sprint 30b).

## 8. Assumptions

1. **Honest majority:** Fewer than t of n MPC nodes are compromised at any time.
2. **Secure randomness:** `OsRng` provides cryptographically secure randomness on all deployment targets.
3. **Time synchronization:** MPC nodes have roughly synchronized clocks (within the 2-minute SignAuthorization TTL window).
4. **Secure key provisioning:** Node Ed25519 identity keys and gateway signing keys are provisioned securely out-of-band.
5. **Infrastructure isolation:** MPC nodes run on separate infrastructure (different cloud accounts, regions, or operators).
6. **NATS availability:** NATS message bus is available; unavailability causes liveness failure but not safety failure.
