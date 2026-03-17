# MPC Wallet — Key-Exchange Authentication Specification

> Production-grade technical specification for cryptographic key-exchange-based authentication.
> Version 1.0 — 2026-03-17

**Critical invariant:** Key exchange alone is NOT authentication. Unauthenticated Diffie-Hellman is vulnerable to man-in-the-middle attacks. Identity MUST be bound to the handshake via cryptographic signatures.

---

## 1. Executive Summary

This specification defines the authentication and session-establishment protocol for the MPC Wallet API Gateway. It replaces simple API key / JWT authentication with a cryptographic handshake that provides:

- **Forward secrecy** via ephemeral X25519 ECDH key exchange
- **Mutual authentication** via Ed25519 digital signatures over transcript hashes
- **Replay protection** via random nonces, timestamps, and challenge-response binding
- **Session key derivation** via HKDF-SHA256 with directional key separation

The protocol is designed for two contexts:
1. **Client → API Gateway**: REST clients (mobile apps, admin dashboards, service integrations)
2. **MPC Node → MPC Node**: Inter-party transport during keygen/signing ceremonies

This spec is implementation-ready. A team can review and implement from this document alone.

---

## 2. Scope

### In Scope
- Client-to-gateway authentication handshake
- MPC node-to-node mutual authentication
- Session key derivation and lifecycle
- Key management (generation, rotation, revocation)
- Threat model and mitigations
- Error handling and failure semantics
- Audit logging requirements

### Out of Scope
- Blockchain-level transaction security
- Smart contract auditing
- End-user wallet UX design
- Quantum-resistant cryptography (future work)
- Custom TLS implementation (use standard TLS 1.3)

---

## 3. Goals and Non-Goals

### Security Goals
- Mutual authentication between client and server
- Perfect forward secrecy for every session
- Replay attack prevention
- Man-in-the-middle attack prevention
- Key compromise resilience (compromised static key does not compromise past sessions)
- Tamper-evident session binding

### System Goals
- Sub-100ms handshake latency
- Horizontal scalability (stateless verification, shared session store)
- Backward compatibility with existing JWT/API-key auth during migration
- Minimal dependencies (use existing workspace crates)

### Non-Goals
- Custom TLS implementation (rely on standard TLS 1.3 for transport)
- Quantum resistance (out of scope for v1)
- Certificate Authority infrastructure (use pinned public keys)
- Browser-based WebAuthn/FIDO2 (separate spec)

---

## 4. Terminology

| Term | Definition |
|------|-----------|
| **Client** | Any entity initiating a connection to the API gateway (mobile app, service, admin dashboard) |
| **Server** | The MPC Wallet API Gateway that terminates client connections |
| **Static Key** | Long-lived Ed25519 signing keypair used for identity. Rotated annually. |
| **Ephemeral Key** | Per-session X25519 key pair. Generated fresh for each handshake. Destroyed after key derivation. |
| **Session Key** | Symmetric key derived from ECDH shared secret via HKDF. Used for AEAD encryption of session data. |
| **Shared Secret** | Raw output of X25519 Diffie-Hellman. Never used directly — always fed into HKDF. |
| **Challenge** | 32-byte random value sent by server. Client must sign it to prove liveness. |
| **Nonce** | 32-byte cryptographically random value. Unique per handshake. Prevents replay. |
| **Signature** | Ed25519 digital signature over a transcript hash. Binds identity to handshake. |
| **Transcript Hash** | SHA-256 hash of all handshake messages (in order). Ensures both parties agree on the full conversation. |
| **Mutual Authentication** | Both client and server prove their identity to each other. |
| **Forward Secrecy** | Compromise of long-term keys does not compromise past session keys. Achieved via ephemeral ECDH. |
| **Replay Attack** | Attacker captures and re-sends a valid handshake message. Prevented by nonces and challenges. |
| **MITM** | Man-in-the-middle: attacker intercepts and modifies messages between client and server. Prevented by signing the transcript. |
| **AEAD** | Authenticated Encryption with Associated Data. Provides confidentiality + integrity + authenticity. |
| **HKDF** | HMAC-based Key Derivation Function. Extracts and expands keying material from ECDH shared secret. |

---

## 5. System Context

### Deployment Context 1: Client → API Gateway

```
┌──────────┐     HTTPS/TLS 1.3     ┌──────────────┐
│  Client  │ ◄──────────────────► │  API Gateway  │
│ (mobile/ │   + Key-Exchange     │   (Axum)      │
│  service)│     Handshake        │               │
└──────────┘                      └───────┬───────┘
                                          │
                                    ┌─────┴─────┐
                                    │  KMS/HSM  │
                                    └───────────┘
```

- Transport: HTTPS with TLS 1.3 (mandatory baseline)
- Application-layer handshake provides: forward secrecy, mutual auth, session binding
- Key storage: HSM/KMS for server static keys, secure enclave for mobile clients

### Deployment Context 2: MPC Node → MPC Node

```
┌──────────┐    NATS + mTLS    ┌──────────┐
│  Node 1  │ ◄──────────────► │  Node 2  │
│ (party 1)│  + SignedEnvelope │ (party 2)│
│          │  + SessionKey     │          │
└──────────┘                   └──────────┘
```

- Transport: NATS with mutual TLS (mTLS)
- Application-layer: Ed25519 signed envelopes + X25519 session encryption (already implemented)
- Key registry: pre-shared Ed25519 public keys per party

---

## 6. Threat Model

| # | Threat | Attack Description | Impact | Mitigation |
|---|--------|--------------------|--------|------------|
| T1 | **Man-in-the-Middle** | Attacker intercepts ECDH exchange and substitutes own keys | Full session compromise, fund theft | Ed25519 signatures over transcript hash bind identity to key exchange |
| T2 | **Replay Attack** | Attacker captures valid handshake and replays it | Session hijacking | 32-byte random nonces + 30-second timestamp window + server challenge |
| T3 | **Key Theft (static)** | Attacker steals server's Ed25519 private key | Can impersonate server for new sessions | HSM/KMS storage; forward secrecy means past sessions remain safe |
| T4 | **Key Theft (ephemeral)** | Attacker steals ephemeral X25519 key during handshake | Single session compromised | Ephemeral keys are in-memory only, zeroized after key derivation |
| T5 | **Impersonation** | Attacker presents a different identity | Unauthorized access to wallets | Static key verification against trusted key registry |
| T6 | **Message Tampering** | Attacker modifies handshake messages in transit | Handshake produces wrong keys, auth fails | Transcript hash covers all messages; any change breaks signatures |
| T7 | **Downgrade Attack** | Attacker forces weaker algorithms | Easier cryptanalysis | Server rejects any algorithm not in the approved set; fail closed |
| T8 | **Session Hijacking** | Attacker steals session token after handshake | Unauthorized API access | Session tokens bound to key fingerprint; short TTL (1 hour) |
| T9 | **Malicious Client** | Client attempts unauthorized operations | Fund theft, DoS | RBAC enforcement post-authentication; rate limiting; audit logging |
| T10 | **Compromised Server Node** | Single MPC node compromised | Partial key material exposure | Threshold cryptography ensures no single node holds complete key |
| T11 | **Leaked Long-Term Key** | Server static key published or leaked | Future impersonation possible | Key revocation list; immediate rotation; forward secrecy protects past sessions |
| T12 | **Insider Misuse** | Authorized user abuses access | Unauthorized transactions | MFA for sensitive operations; audit ledger; approval quorums |

---

## 7. Security Principles

1. **Key exchange alone is NOT authentication.** Unauthenticated Diffie-Hellman is vulnerable to MITM. Identity MUST be bound to the handshake.
2. **Never trust raw key exchange without identity verification.** Every ECDH exchange must be accompanied by a signature from a trusted static key.
3. **Avoid custom cryptography.** Use proven primitives: X25519, Ed25519, HKDF-SHA256, ChaCha20-Poly1305.
4. **Use ephemeral keys for forward secrecy.** Generate fresh X25519 keypairs per session. Zeroize after key derivation.
5. **Bind identity to handshake.** Sign the transcript hash (all messages) with static Ed25519 key.
6. **Protect against replay.** Use random nonces, server challenges, and timestamp validation.
7. **Minimize trust in long-lived secrets.** Static keys are for identity only. Session keys are ephemeral.
8. **Prefer short-lived credentials.** Session TTL = 1 hour. Rekey every 10 minutes.
9. **Explicit algorithm negotiation.** Client proposes, server selects. Reject unknown algorithms.
10. **Fail closed.** Any validation failure terminates the handshake immediately. No fallback to weaker auth.
11. **Authorization must not begin before authentication completes.** No API access until SessionEstablished.
12. **Key rotation and revocation must exist.** Static keys have planned rotation. Compromised keys are immediately revocable.

---

## 8. Protocol Overview

### Client → Gateway Handshake

```
Client                                    Server
  │                                         │
  │──── 1. ClientHello ────────────────────►│  (ephemeral pubkey + nonce + key_id)
  │                                         │
  │◄─── 2. ServerHello ────────────────────│  (ephemeral pubkey + nonce + challenge + signature)
  │                                         │
  │──── 3. ClientAuth ─────────────────────►│  (signature over transcript hash)
  │                                         │
  │◄─── 4. SessionEstablished ─────────────│  (session_id + token + expiry)
  │                                         │
  │════ Authenticated Session ═════════════│  (RBAC checks, API access)
```

1. **Client initiates** with ClientHello containing ephemeral X25519 pubkey, random nonce, and static key ID.
2. **Server responds** with its ephemeral pubkey, nonce, challenge, and Ed25519 signature over transcript.
3. **Client proves identity** by signing the full transcript hash with its Ed25519 static key.
4. **Server verifies**, derives session keys, and returns an encrypted session token.
5. **Authorization begins** only after step 4 completes successfully.

### MPC Node → Node Authentication

Already implemented via `transport::signed_envelope` (Ed25519) + `transport::session_key` (X25519 ECDH + HKDF + ChaCha20-Poly1305). See `crates/mpc-wallet-core/src/transport/`.

---

## 9. Cryptographic Design

### Recommended Primitives

| Purpose | Algorithm | Justification |
|---------|-----------|---------------|
| Key Exchange | **X25519** (Curve25519 ECDH) | Fast, constant-time, no foot-guns. RFC 7748. |
| Identity Signatures | **Ed25519** | Deterministic, fast verification. RFC 8032. |
| Key Derivation | **HKDF-SHA256** | Standard KDF. Extract + expand. RFC 5869. |
| Symmetric AEAD | **ChaCha20-Poly1305** | Fast on mobile/ARM. No padding oracles. RFC 8439. |
| Hashing | **SHA-256** | Transcript hashing, key fingerprints. |
| Random Number Generation | **OS CSPRNG** (`OsRng`) | Mandatory. Never use `rand::thread_rng()` for key material. |

### Algorithm Status

| Algorithm | Status | Notes |
|-----------|--------|-------|
| X25519 | **Preferred** | Only approved ECDH algorithm |
| Ed25519 | **Preferred** | Only approved signature algorithm |
| HKDF-SHA256 | **Preferred** | Only approved KDF |
| ChaCha20-Poly1305 | **Preferred** | Primary AEAD |
| AES-256-GCM | **Acceptable** | Alternative AEAD (existing key store uses this) |
| ECDSA (secp256k1) | **Discouraged** for auth | Use Ed25519 instead. ECDSA is for blockchain signatures only. |
| RSA | **Forbidden** | Too slow, complex parameter choices, padding attacks |
| MD5, SHA-1 | **Forbidden** | Broken collision resistance |
| 3DES, RC4, Blowfish | **Forbidden** | Deprecated, known weaknesses |
| Custom / proprietary | **Forbidden** | No homebrew cryptography |

### RNG Requirements

- All nonces, challenges, and ephemeral keys MUST use `OsRng` (kernel CSPRNG).
- Never seed a PRNG from a timestamp or predictable source.
- Verify entropy source availability at startup; panic if unavailable.

---

## 10. Identity Model

### Comparison of Models

| Model | Use Case | Pros | Cons |
|-------|----------|------|------|
| **Server-auth only (TLS)** | Client → gateway baseline | Simple, standard | No client identity verification |
| **Mutual TLS (mTLS)** | Service → gateway, node → node | Strong mutual auth, standard | Certificate management complexity |
| **Signed challenge-response** | Client → gateway (this spec) | Forward secrecy, fine-grained control | Custom protocol complexity |
| **Pinned public keys** | MPC nodes in known cluster | Simple, no CA needed | Manual key distribution |
| **Pre-shared trusted pubkeys** | Node registry | Zero trust anchor complexity | Rotation requires coordination |

### Recommendation for MPC Wallet

| Context | Recommended Model |
|---------|-------------------|
| Client → API Gateway | **TLS 1.3 + signed challenge-response** (this spec) |
| Service → API Gateway | **mTLS** with pinned certificates |
| MPC Node → MPC Node | **Mutual Ed25519 auth + X25519 session keys** (already implemented) |
| Admin Dashboard → Gateway | **TLS 1.3 + signed challenge-response + MFA enforcement** |

---

## 11. Handshake Specification

### Message 1: ClientHello

| Field | Type | Size | Purpose |
|-------|------|------|---------|
| `protocol_version` | string | — | Protocol version. Must be `"mpc-wallet-auth-v1"`. |
| `supported_kex` | array | — | Supported key exchange algorithms. Must include `"x25519"`. |
| `supported_sig` | array | — | Supported signature algorithms. Must include `"ed25519"`. |
| `client_ephemeral_pubkey` | hex string | 64 chars (32 bytes) | Client's ephemeral X25519 public key. |
| `client_nonce` | hex string | 64 chars (32 bytes) | Client's random nonce. Unique per handshake. |
| `timestamp` | u64 | 8 bytes | UNIX timestamp (seconds). |
| `client_key_id` | hex string | 16 chars (8 bytes) | First 8 bytes of client's Ed25519 public key (fingerprint). |

**Validation Rules (server-side):**
1. `protocol_version` == `"mpc-wallet-auth-v1"` — reject otherwise (UnsupportedVersion)
2. `supported_kex` contains `"x25519"` — reject otherwise (NoCommonAlgorithm)
3. `supported_sig` contains `"ed25519"` — reject otherwise (NoCommonAlgorithm)
4. `client_ephemeral_pubkey` is valid hex, 32 bytes — reject otherwise (MalformedMessage)
5. `client_nonce` is valid hex, 32 bytes — reject otherwise (MalformedMessage)
6. `|timestamp - server_time| <= 30 seconds` — reject otherwise (TimestampDrift)
7. `client_key_id` is not on revocation list — reject otherwise (KeyRevoked)

**Failure:** Any validation failure immediately terminates the handshake. Server responds with generic error (no details leaked).

### Message 2: ServerHello

| Field | Type | Size | Purpose |
|-------|------|------|---------|
| `protocol_version` | string | — | Echo of accepted protocol version. |
| `selected_kex` | string | — | Selected key exchange: `"x25519"`. |
| `selected_sig` | string | — | Selected signature: `"ed25519"`. |
| `selected_aead` | string | — | Selected AEAD: `"chacha20-poly1305"`. |
| `server_ephemeral_pubkey` | hex string | 64 chars | Server's ephemeral X25519 public key. |
| `server_nonce` | hex string | 64 chars | Server's random nonce. |
| `server_challenge` | hex string | 64 chars | Random challenge client must sign. |
| `timestamp` | u64 | — | Server timestamp. |
| `server_key_id` | hex string | 16 chars | Server's Ed25519 public key fingerprint. |
| `server_signature` | hex string | 128 chars (64 bytes) | Ed25519 signature over transcript hash (ClientHello + ServerHello fields). |

**Client-side validation:**
1. `protocol_version` matches — reject otherwise
2. `selected_kex` is in client's supported list — reject otherwise
3. `server_ephemeral_pubkey` is 32 bytes — reject otherwise
4. `server_key_id` matches a trusted server public key — reject otherwise (unknown server)
5. `server_signature` verifies against trusted server public key and transcript hash — reject otherwise
6. `|timestamp - client_time| <= 30 seconds` — reject otherwise

### Message 3: ClientAuth

| Field | Type | Size | Purpose |
|-------|------|------|---------|
| `client_signature` | hex string | 128 chars (64 bytes) | Ed25519 signature over full transcript hash. |
| `client_static_pubkey` | hex string | 64 chars (32 bytes) | Client's static Ed25519 public key. |

**Server-side validation:**
1. `client_static_pubkey` is 32 bytes — reject otherwise
2. `client_key_id` (from ClientHello) matches first 8 bytes of `client_static_pubkey` — reject otherwise (KeyIdMismatch)
3. `client_static_pubkey` is in trusted client key registry — reject otherwise (UnknownClient)
4. `client_signature` verifies against `client_static_pubkey` and transcript hash — reject otherwise (InvalidSignature)

**Transcript hash construction:**
```
transcript = SHA-256(
    serialize(ClientHello) ||
    serialize(ServerHello fields, excluding server_signature) ||
    serialize(ClientAuth fields, excluding client_signature)
)
```

### Message 4: SessionEstablished

| Field | Type | Purpose |
|-------|------|---------|
| `session_id` | string | Unique session identifier (hex-encoded hash). |
| `expires_at` | u64 | Session expiration (UNIX seconds). Default: 1 hour from now. |
| `session_token` | string | Opaque encrypted token for subsequent API requests. |
| `key_fingerprint` | string | SHA-256 fingerprint of derived session key (first 16 bytes hex). |

**When handshake is complete:** After server sends SessionEstablished and client receives it, the authenticated session is established. Authorization checks (RBAC, ABAC, MFA) may now proceed.

---

## 12. Key Derivation and Session Establishment

### Shared Secret

```
shared_secret = X25519(client_ephemeral_private, server_ephemeral_public)
              = X25519(server_ephemeral_private, client_ephemeral_public)  // same value
```

### HKDF Parameters

```
salt   = client_nonce || server_nonce   (64 bytes)
IKM    = shared_secret                  (32 bytes)
```

### Derived Keys

```
client_write_key = HKDF-Expand(PRK, info="mpc-wallet-session-v1-client-write", L=32)
server_write_key = HKDF-Expand(PRK, info="mpc-wallet-session-v1-server-write", L=32)
```

- `client_write_key`: used by client to encrypt, by server to decrypt
- `server_write_key`: used by server to encrypt, by client to decrypt
- Keys MUST be different (different `info` strings ensure this)

### Session Expiration

| Parameter | Value | Rationale |
|-----------|-------|-----------|
| Session TTL | 1 hour | Limits window of session token theft |
| Rekey interval | 10 minutes | Limits data encrypted under one key |
| Max requests per session | 10,000 | Prevents abuse from compromised token |

### Transcript Binding

The session ID is derived from the transcript hash:
```
session_id = hex(SHA-256(transcript_hash)[0..16])
```

This binds the session to the exact handshake conversation, preventing session fixation.

---

## 13. Authentication Binding Rules

### What is bound:

1. **Identity → ephemeral keys**: Ed25519 signature covers the transcript which includes ephemeral public keys
2. **Handshake transcript → session**: session ID derived from transcript hash
3. **Algorithm negotiation → session**: selected algorithms are part of the transcript
4. **Nonces → session**: nonces are part of HKDF salt, binding derived keys to this specific exchange

### What this prevents:

| Attack | Prevention Mechanism |
|--------|---------------------|
| MITM on unauthenticated ECDH | Ed25519 signatures over transcript (both sides) |
| Replay of old auth proofs | Nonces are unique; challenge is unique; timestamp validated |
| Algorithm downgrade | Selected algorithms are in the signed transcript |
| Key substitution | Client ephemeral pubkey is in the signed transcript |
| Session fixation | Session ID derived from transcript hash |

### Channel Binding

```
channel_binding_token = HKDF-Expand(PRK, info="mpc-wallet-channel-binding", L=32)
```

This token can be included in higher-level protocols (e.g., API request headers) to bind API requests to the authenticated session.

---

## 14. Authorization Boundary

### Authentication → Authorization Transition

```
                Authentication                    Authorization
┌──────────────────────────────────┐  ┌──────────────────────────────┐
│ ClientHello → ServerHello →      │  │ RBAC role check              │
│ ClientAuth → SessionEstablished  │  │ ABAC attribute check         │
│                                  │  │ MFA enforcement              │
│ Identity verified                │  │ Wallet-level access control  │
│ Session keys derived             │  │ Rate limiting per key/role   │
└──────────────────────────────────┘  └──────────────────────────────┘
         COMPLETE before ─────────────────► STARTS after
```

**Rules:**
- Authentication is complete ONLY after SessionEstablished is received
- No API endpoint may be accessed before authentication completes
- Session token carries: `user_id`, `roles`, `key_fingerprint`, `expiry`
- Authorization must NOT assume any claims not verified during handshake
- RBAC roles come from the client key registry (for API keys) or JWT claims (for user tokens)

---

## 15. Replay Protection

### Mechanisms

| Mechanism | Protection Against | Implementation |
|-----------|--------------------|----------------|
| **Client nonce** (32 bytes, random) | Replay of ClientHello | Server includes in HKDF salt; makes each session unique |
| **Server nonce** (32 bytes, random) | Replay of ServerHello | Included in HKDF salt |
| **Server challenge** (32 bytes, random) | Replay of ClientAuth | Client must sign; server verifies freshness |
| **Timestamp** (30-second window) | Old message replay | Reject messages with stale timestamps |
| **Session ID** (unique per handshake) | Session reuse | Derived from transcript hash; never reused |

### Replay Cache

For high-security deployments, the server SHOULD maintain a short-lived replay cache of recent `(client_nonce, server_nonce)` pairs. If a duplicate pair is seen within the timestamp window, reject.

Cache TTL = `MAX_TIMESTAMP_DRIFT * 2` = 60 seconds.

### Tradeoffs of Timestamp-Based Protection

| Approach | Pros | Cons |
|----------|------|------|
| Timestamp only | Stateless, simple | Clock skew issues; window for replay |
| Nonce only | No clock dependency | Requires stateful replay cache |
| **Both (recommended)** | Defense in depth | Slightly more complex; small state overhead |

---

## 16. Key Management Lifecycle

### Key Generation

| Key Type | Algorithm | Where Generated | Storage |
|----------|-----------|-----------------|---------|
| Server static (identity) | Ed25519 | HSM/KMS | HSM/KMS (never exported) |
| Client static (identity) | Ed25519 | Client device | Secure enclave / keychain |
| Ephemeral (per-session) | X25519 | In-memory | RAM only; zeroized after HKDF |

### Key Rotation Policy

| Key Type | Rotation Period | Procedure |
|----------|----------------|-----------|
| Server static key | Annually | Generate new key in HSM; publish new key_id; dual-key transition for 30 days |
| Client static key | Annually or on compromise | Client generates new key; registers with server; old key revoked |
| Ephemeral keys | Per session | Automatic; no rotation needed |
| Session keys | Rekey every 10 minutes | Derive new keys from current session via HKDF with incremented counter |

### Key Revocation

- Maintain a key revocation list (KRL) checked during handshake validation
- Check `client_key_id` and `server_key_id` against KRL before proceeding
- Revocation takes effect immediately; no grace period for compromised keys
- KRL distributed via API endpoint: `GET /v1/auth/revoked-keys`

### Compromised Key Recovery

1. **Freeze all wallets** associated with the compromised key
2. **Revoke the key** immediately (add to KRL)
3. **Rotate to new key** (generate in HSM, update key registry)
4. **Audit all sessions** established with the compromised key
5. **Notify affected users** per compliance requirements
6. **Break-glass procedure**: M-of-N key custodians authorize emergency key replacement

### Bootstrap Trust Model

- Server public keys distributed via: HTTPS pinning, DNS-based key discovery, or manual provisioning
- Client public keys registered via: authenticated admin API (Admin + MFA required)
- MPC node public keys: pre-configured in node deployment (ConfigMap/secrets)

---

## 17. Error Handling and Failure Semantics

### Error Types and Behavior

| Error | Server Behavior | Client Behavior | Loggable? | Leaked to Client? |
|-------|----------------|-----------------|-----------|-------------------|
| UnsupportedVersion | Terminate handshake, log | Retry with different version or fail | Yes (version) | No — generic "authentication failed" |
| TimestampDrift | Terminate, log drift amount | Check clock sync | Yes (drift_secs) | No |
| NoCommonAlgorithm | Terminate, log offered algorithms | Update algorithm support | Yes (offered list) | No |
| MalformedMessage | Terminate, log field name | Fix message format | Yes (field) | No |
| InvalidSignature | Terminate, increment failure counter | Check key material | Yes (key_id prefix) | No |
| KeyIdMismatch | Terminate, log mismatch details | Fix key registration | Yes (both IDs) | No |
| KeyRevoked | Terminate | Re-register with new key | Yes (revoked key_id) | No |
| KeyDerivationFailed | Terminate, alert ops | Should not happen | Yes (full details) | No |
| SessionExpired | Return 401, require re-handshake | Perform new handshake | Yes (session_id) | "session expired" only |

**Critical rule:** Error responses MUST use a generic `"authentication failed"` message. NEVER leak which specific check failed — this helps attackers enumerate valid parameters.

### What Must Never Appear in Logs

- Private keys (static or ephemeral)
- Shared secrets
- Derived session keys
- Raw API keys
- Full JWT tokens
- Full client signatures (log key_id prefix only)

---

## 18. Logging, Monitoring, and Auditability

### Required Security Events

| Event | Log Level | Fields |
|-------|-----------|--------|
| Handshake started | INFO | client_key_id, client_ip, timestamp |
| Handshake success | INFO | client_key_id, session_id, duration_ms |
| Handshake failed | WARN | client_key_id prefix, failure_reason, client_ip |
| Replay detected | WARN | client_nonce prefix, client_ip |
| Key rotation | INFO | old_key_id, new_key_id, rotated_by |
| Key revocation | WARN | revoked_key_id, reason, revoked_by |
| Session expired | DEBUG | session_id |
| Suspicious retry pattern | WARN | client_ip, attempt_count, window |
| Certificate/key validation failure | WARN | key_id, validation_error_type |

### Redaction Rules

- Key IDs: first 8 bytes (16 hex chars) only
- IP addresses: full address (needed for abuse detection)
- Timestamps: full precision
- Session IDs: full (non-secret)
- Nonces: first 8 bytes only
- Signatures: NEVER log
- Private keys: NEVER log
- Session keys: NEVER log

### Audit Requirements

All authentication events MUST be written to the tamper-evident `AuditLedger` (existing `crates/mpc-wallet-core/src/audit/`). Entries are hash-chained and Ed25519-signed for non-repudiation.

---

## 19. Rate Limiting and Abuse Controls

| Control | Target | Limit | Action |
|---------|--------|-------|--------|
| Handshake rate (per IP) | ClientHello messages | 10/minute | Reject with 429 |
| Handshake rate (per key_id) | ClientHello messages | 5/minute | Reject with 429 |
| Failed handshakes (per IP) | Failed auth attempts | 5 in 5 minutes | Block IP for 15 minutes |
| Failed handshakes (per key_id) | Failed auth attempts | 3 in 5 minutes | Block key_id for 30 minutes |
| Concurrent handshakes (global) | In-progress handshakes | 1000 | Reject with 503 |
| Session creation rate | New sessions | 100/minute per key_id | Reject with 429 |

### Exponential Backoff

After N consecutive failures for a client, enforce a backoff:
- 1st failure: no delay
- 2nd failure: 1 second
- 3rd failure: 5 seconds
- 4th failure: 30 seconds
- 5th failure: 15-minute block

---

## 20. Operational Considerations

### Multi-Region Deployment

- Session tokens MUST be valid across regions (shared session store or stateless JWT-like tokens)
- Key revocation lists MUST be replicated with < 5 second propagation delay
- Clock sync: NTP required on all servers, 30-second tolerance

### Certificate/Key Rollout Strategy

1. **Phase 1 (Day 0):** Generate new key in HSM; register as secondary
2. **Phase 2 (Day 1–30):** Server accepts both old and new key_ids; clients can migrate
3. **Phase 3 (Day 30):** Revoke old key; new key is sole active key

### Protocol Versioning

- `protocol_version` field in ClientHello enables future upgrades
- Server MUST reject unknown versions immediately
- Multiple versions MAY be supported simultaneously during migration
- Version `mpc-wallet-auth-v1` is the initial and current version

### Migration from JWT/API-Key Auth

1. **Phase 1:** Deploy key-exchange auth endpoints alongside existing auth
2. **Phase 2:** New clients use key-exchange; existing clients continue with JWT/API-key
3. **Phase 3:** Deprecation notices for legacy auth
4. **Phase 4:** Legacy auth disabled; all clients use key-exchange

---

## 21. Reference Architecture

```
                                    ┌─────────────────────┐
                                    │   Trust Anchor       │
                                    │   (Key Registry)     │
                                    └──────────┬──────────┘
                                               │
┌──────────┐    TLS 1.3    ┌──────────────┐    │    ┌─────────┐
│  Client   │─────────────►│  Load        │────┴───►│  Auth   │
│  (mobile/ │◄─────────────│  Balancer    │         │ Service │
│  service) │  + Handshake │  (nginx/    │         │         │
└──────────┘               │   envoy)    │         └────┬────┘
                           └──────┬───────┘              │
                                  │                 ┌────┴────┐
                           ┌──────┴───────┐         │ KMS/HSM │
                           │  API Gateway  │         └─────────┘
                           │  (Axum)       │
                           └──────┬───────┘
                                  │
                    ┌─────────────┼─────────────┐
                    │             │             │
              ┌─────┴────┐ ┌─────┴────┐ ┌─────┴────┐
              │ MPC Node │ │ MPC Node │ │ MPC Node │
              │    1     │ │    2     │ │    3     │
              └─────┬────┘ └─────┬────┘ └─────┬────┘
                    │             │             │
              ┌─────┴────┐ ┌─────┴────┐ ┌─────┴────┐
              │Key Store │ │Key Store │ │Key Store │
              └──────────┘ └──────────┘ └──────────┘
                                  │
                           ┌──────┴───────┐
                           │ Audit Ledger │
                           │ (WORM)       │
                           └──────────────┘
```

---

## 22. Sequence Diagram

### Client → Gateway Handshake

```
Client                                          Server
  │                                               │
  │  1. Generate ephemeral X25519 keypair         │
  │  2. Generate 32-byte random nonce             │
  │                                               │
  │── ClientHello ──────────────────────────────► │
  │   { protocol_version, supported_kex,          │
  │     supported_sig, client_ephemeral_pubkey,   │
  │     client_nonce, timestamp, client_key_id }  │
  │                                               │
  │                 3. Validate ClientHello        │
  │                 4. Generate ephemeral X25519   │
  │                 5. Generate nonce + challenge  │
  │                 6. Compute transcript hash     │
  │                 7. Sign transcript with Ed25519│
  │                                               │
  │◄── ServerHello ────────────────────────────── │
  │   { protocol_version, selected_kex,           │
  │     selected_sig, selected_aead,              │
  │     server_ephemeral_pubkey, server_nonce,    │
  │     server_challenge, timestamp,              │
  │     server_key_id, server_signature }         │
  │                                               │
  │  8. Verify server_signature                   │
  │  9. Compute full transcript hash              │
  │ 10. Sign transcript with client Ed25519       │
  │                                               │
  │── ClientAuth ───────────────────────────────► │
  │   { client_signature, client_static_pubkey }  │
  │                                               │
  │                11. Verify client_key_id match │
  │                12. Verify client_signature    │
  │                13. X25519 ECDH shared secret  │
  │                14. HKDF derive session keys   │
  │                15. Create session record      │
  │                                               │
  │◄── SessionEstablished ─────────────────────── │
  │   { session_id, expires_at,                   │
  │     session_token, key_fingerprint }          │
  │                                               │
  ║═══ Authenticated Session ═══════════════════ ║
  │   API requests with session_token             │
```

---

## 23. Pseudocode

### Client Handshake

```rust
fn client_handshake(
    server_trusted_pubkey: &Ed25519VerifyingKey,
    client_signing_key: &Ed25519SigningKey,
) -> Result<AuthenticatedSession, HandshakeError> {
    // 1. Generate ephemeral X25519 keypair
    let eph_secret = X25519Secret::random();
    let eph_public = X25519Public::from(&eph_secret);

    // 2. Generate random nonce
    let client_nonce = random_bytes(32);

    // 3. Send ClientHello
    let client_hello = ClientHello {
        protocol_version: "mpc-wallet-auth-v1",
        supported_kex: ["x25519"],
        supported_sig: ["ed25519"],
        client_ephemeral_pubkey: hex(eph_public),
        client_nonce: hex(client_nonce),
        timestamp: now(),
        client_key_id: hex(client_signing_key.pubkey()[..8]),
    };
    send(client_hello);

    // 4. Receive and validate ServerHello
    let server_hello = receive();
    let transcript = sha256(serialize(client_hello) || serialize(server_hello.fields_no_sig()));
    verify_ed25519(server_trusted_pubkey, transcript, server_hello.server_signature)?;

    // 5. Sign full transcript
    let full_transcript = sha256(transcript || serialize(client_auth.fields_no_sig()));
    let client_sig = client_signing_key.sign(full_transcript);

    // 6. Send ClientAuth
    send(ClientAuth { client_signature: hex(client_sig), client_static_pubkey: hex(pubkey) });

    // 7. Receive SessionEstablished
    let session = receive();

    // 8. Derive session keys
    let shared_secret = x25519(eph_secret, server_hello.server_ephemeral_pubkey);
    let salt = client_nonce || server_nonce;
    let prk = hkdf_extract(salt, shared_secret);
    let client_write_key = hkdf_expand(prk, "mpc-wallet-session-v1-client-write", 32);
    let server_write_key = hkdf_expand(prk, "mpc-wallet-session-v1-server-write", 32);

    // 9. Zeroize ephemeral secret
    eph_secret.zeroize();

    Ok(AuthenticatedSession { session_id, client_write_key, server_write_key, expires_at })
}
```

### Server Handshake

```rust
fn server_handshake(
    server_signing_key: &Ed25519SigningKey,
    client_key_registry: &KeyRegistry,
) -> Result<AuthenticatedSession, HandshakeError> {
    // 1. Receive ClientHello
    let client_hello = receive();
    validate_protocol_version(client_hello.protocol_version)?;
    validate_timestamp(client_hello.timestamp, 30)?;
    validate_algorithms(client_hello.supported_kex, client_hello.supported_sig)?;

    // 2. Generate server ephemeral keys + nonce + challenge
    let eph_secret = X25519Secret::random();
    let eph_public = X25519Public::from(&eph_secret);
    let server_nonce = random_bytes(32);
    let server_challenge = random_bytes(32);

    // 3. Build transcript and sign
    let mut transcript = Sha256::new();
    transcript.update(serialize(client_hello));
    transcript.update(serialize(server_hello_fields_no_sig));
    let sig = server_signing_key.sign(transcript.clone().finalize());

    // 4. Send ServerHello
    send(ServerHello { ..., server_signature: hex(sig) });

    // 5. Receive ClientAuth
    let client_auth = receive();
    let client_pubkey = decode_hex(client_auth.client_static_pubkey)?;

    // 6. Verify key_id match
    assert_eq!(client_hello.client_key_id, hex(client_pubkey[..8]))?;

    // 7. Verify client is in trusted registry
    client_key_registry.verify_trusted(client_pubkey)?;

    // 8. Verify client signature over full transcript
    transcript.update(serialize(client_auth.fields_no_sig()));
    let full_hash = transcript.finalize();
    verify_ed25519(client_pubkey, full_hash, client_auth.client_signature)?;

    // 9. Derive session keys
    let shared_secret = x25519(eph_secret, client_hello.client_ephemeral_pubkey);
    let salt = client_nonce || server_nonce;
    let prk = hkdf_extract(salt, shared_secret);
    let client_write_key = hkdf_expand(prk, "mpc-wallet-session-v1-client-write", 32);
    let server_write_key = hkdf_expand(prk, "mpc-wallet-session-v1-server-write", 32);

    // 10. Zeroize ephemeral secret
    eph_secret.zeroize();

    // 11. Create session
    let session_id = hex(sha256(full_hash)[..16]);
    Ok(AuthenticatedSession { session_id, client_write_key, server_write_key, expires_at: now() + 3600 })
}
```

### Replay Check

```rust
fn check_replay(
    replay_cache: &mut HashMap<[u8; 32], u64>,
    client_nonce: &[u8; 32],
    timestamp: u64,
) -> Result<(), HandshakeError> {
    // 1. Check timestamp freshness
    let now = current_unix_time();
    if now.abs_diff(timestamp) > 30 {
        return Err(HandshakeError::TimestampDrift);
    }

    // 2. Check replay cache
    if replay_cache.contains_key(client_nonce) {
        return Err(HandshakeError::ReplayDetected);
    }

    // 3. Add to cache with expiry
    replay_cache.insert(*client_nonce, now + 60);

    // 4. Prune expired entries
    replay_cache.retain(|_, expiry| *expiry > now);

    Ok(())
}
```

---

## 24. API / Message Schema Examples

### ClientHello

```json
{
  "protocol_version": "mpc-wallet-auth-v1",
  "supported_kex": ["x25519"],
  "supported_sig": ["ed25519"],
  "client_ephemeral_pubkey": "a1b2c3d4e5f6789012345678901234567890abcdef1234567890abcdef123456",
  "client_nonce": "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210",
  "timestamp": 1710700000,
  "client_key_id": "a1b2c3d4e5f67890"
}
```

### ServerHello

```json
{
  "protocol_version": "mpc-wallet-auth-v1",
  "selected_kex": "x25519",
  "selected_sig": "ed25519",
  "selected_aead": "chacha20-poly1305",
  "server_ephemeral_pubkey": "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
  "server_nonce": "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
  "server_challenge": "0011223344556677889900aabbccddeeff0011223344556677889900aabbccddee",
  "timestamp": 1710700001,
  "server_key_id": "1234567890abcdef",
  "server_signature": "ed25519-signature-hex-128-chars..."
}
```

### ClientAuth

```json
{
  "client_signature": "ed25519-signature-over-transcript-hash-hex-128-chars...",
  "client_static_pubkey": "a1b2c3d4e5f6789012345678901234567890abcdef1234567890abcdef123456"
}
```

### SessionEstablished

```json
{
  "session_id": "7f83b1657ff1fc53b92dc18148a1d65d",
  "expires_at": 1710703600,
  "session_token": "encrypted-opaque-token...",
  "key_fingerprint": "3a7bd3e2360a3d29eea436fcfb7e44c7"
}
```

---

## 25. State Machine

### Server States

| State | Description |
|-------|-------------|
| `INIT` | Waiting for ClientHello |
| `HELLO_SENT` | ServerHello sent, waiting for ClientAuth |
| `AUTHENTICATED` | ClientAuth verified, session established |
| `FAILED` | Handshake failed (terminal) |
| `EXPIRED` | Session expired (terminal) |

### Transitions

| From | Event | To | Condition |
|------|-------|-----|-----------|
| INIT | ClientHello received | HELLO_SENT | All validations pass |
| INIT | ClientHello received | FAILED | Any validation fails |
| HELLO_SENT | ClientAuth received | AUTHENTICATED | Signature valid |
| HELLO_SENT | ClientAuth received | FAILED | Signature invalid |
| HELLO_SENT | Timeout (30s) | FAILED | No ClientAuth received |
| AUTHENTICATED | Session expires | EXPIRED | `now > expires_at` |
| AUTHENTICATED | Revocation | FAILED | Key revoked |

### Invalid Transitions

| From | Event | Result |
|------|-------|--------|
| HELLO_SENT | Second ClientHello | FAILED (InvalidState) |
| AUTHENTICATED | ClientHello | FAILED (InvalidState) |
| FAILED | Any | Rejected |
| EXPIRED | Any | Rejected |

### Client States

| State | Description |
|-------|-------------|
| `INIT` | Ready to start handshake |
| `HELLO_SENT` | ClientHello sent, waiting for ServerHello |
| `HELLO_RECEIVED` | ServerHello received, verifying |
| `AUTH_SENT` | ClientAuth sent, waiting for SessionEstablished |
| `SESSION_ESTABLISHED` | Authenticated, session active |
| `FAILED` | Handshake failed (terminal) |

---

## 26. Security Review Checklist

- [ ] Key exchange is NOT used as sole authentication — Ed25519 signatures verify identity
- [ ] Unauthenticated DH is never used — all ECDH exchanges accompanied by signatures
- [ ] Transcript hash covers ALL handshake messages before signing
- [ ] Nonces are 32 bytes from OS CSPRNG (`OsRng`)
- [ ] Timestamps validated within 30-second window
- [ ] Server challenge consumed exactly once
- [ ] Ephemeral X25519 keys zeroized after HKDF derivation
- [ ] HKDF salt includes both client and server nonces
- [ ] Client and server write keys derived with different `info` strings
- [ ] Error messages are generic — no auth details leaked to clients
- [ ] Private keys never appear in logs
- [ ] Session tokens bound to key fingerprint
- [ ] Key revocation list checked during handshake
- [ ] Rate limiting on handshake attempts (per IP and per key_id)
- [ ] Session TTL enforced (1 hour default)
- [ ] RBAC/authorization only after authentication completes
- [ ] Algorithm negotiation rejects unknown algorithms
- [ ] Protocol version checked and unknown versions rejected
- [ ] Constant-time comparison for signatures and key material
- [ ] No fallback to weaker auth on handshake failure
- [ ] HSM/KMS used for server static key storage
- [ ] Audit ledger records all auth events (tamper-evident)
- [ ] Clock synchronization (NTP) verified on all servers
- [ ] Key rotation procedure documented and tested
- [ ] Replay cache or nonce deduplication in place

---

## 27. Implementation Pitfalls

| # | Pitfall | Consequence | Prevention |
|---|---------|-------------|------------|
| 1 | **Confusing encryption with authentication** | Encrypted channel with no identity = MITM vulnerable | Always sign the transcript; verify signatures |
| 2 | **Trusting public keys without root trust** | Attacker substitutes their key | Verify key_id against trusted registry |
| 3 | **Reusing nonces** | Catastrophic AEAD failure (plaintext recovery) | Use OS CSPRNG; monotonic counters for AEAD |
| 4 | **No transcript binding** | MITM can modify early messages | Hash all messages into signature input |
| 5 | **Weak randomness** | Predictable keys; attacker can derive session keys | OsRng only; panic if entropy unavailable |
| 6 | **Storing private keys insecurely** | Key theft → full impersonation | HSM/KMS for servers; secure enclave for clients |
| 7 | **No revocation flow** | Compromised key remains valid forever | Key revocation list checked at every handshake |
| 8 | **Relying only on timestamps** | Clock skew allows replay | Combine timestamps with random nonces |
| 9 | **Inventing custom crypto** | Unknown vulnerabilities, no peer review | Use proven primitives (X25519, Ed25519, HKDF) |
| 10 | **Not zeroizing ephemeral secrets** | Memory dump exposes session keys | `zeroize` crate on all sensitive material |
| 11 | **Leaking error details** | Attacker enumerates valid parameters | Generic "authentication failed" for all errors |
| 12 | **Skipping algorithm negotiation** | Stuck on one algorithm; no upgrade path | Version and algorithm fields in handshake |
| 13 | **Starting authorization before auth completes** | Unauthenticated access to resources | Enforce state machine: no API access in INIT/HELLO_SENT |
| 14 | **Using HMAC-SHA256 signing key for ECDH** | Domain separation violation | Separate keys for separate purposes |
| 15 | **Not binding session to handshake** | Session fixation attacks | Derive session_id from transcript hash |
| 16 | **Forgetting to validate key_id against pubkey** | Key substitution attack | Verify first 8 bytes of pubkey match key_id |

---

## 28. Recommendations

### Default Design for MPC Wallet

**TLS 1.3 (transport) + Signed Challenge-Response + Ephemeral X25519 ECDH (application layer)**

This is the recommended design for the MPC Wallet API Gateway. It provides:
- Transport security via standard TLS 1.3 (no custom implementation)
- Forward secrecy via ephemeral X25519 per session
- Mutual authentication via Ed25519 signed transcript
- Session binding via HKDF-derived keys

### When to Use Each Model

| Scenario | Recommended Auth |
|----------|-----------------|
| Mobile app → API Gateway | TLS 1.3 + this handshake protocol |
| Admin dashboard → API Gateway | TLS 1.3 + this handshake + MFA enforcement |
| Service → API Gateway | Mutual TLS (mTLS) with pinned certificates |
| MPC node → MPC node | Mutual Ed25519 + X25519 (existing implementation) |
| Development / testing | JWT with HMAC-SHA256 (existing, legacy mode) |

### When NOT to Build a Custom Protocol

- **If TLS 1.3 alone is sufficient** for your threat model (most web applications)
- **If mTLS meets your needs** (service-to-service with certificate management)
- **If the engineering team lacks cryptographic expertise** to implement and review correctly

### Why This Spec Uses a Custom Handshake

TLS 1.3 alone is not sufficient for MPC wallet infrastructure because:

1. **TLS terminates at the load balancer** — the API gateway needs its own identity verification
2. **Forward secrecy at the application layer** protects against TLS key compromise
3. **Session keys bound to client identity** enable per-session RBAC and audit
4. **MPC ceremonies require session-scoped encryption** beyond what TLS provides
5. **Key management is already part of the system** — Ed25519 and X25519 are already in the workspace

### Risks of This Custom Design

| Risk | Mitigation |
|------|-----------|
| Implementation bugs | Extensive test suite; security review before production |
| Protocol design flaws | Based on well-studied patterns (Noise Protocol Framework, TLS 1.3 handshake) |
| Maintenance burden | Use standard primitives; minimize custom logic |
| Interoperability | JSON messages over HTTPS; any language can implement |

### Migration Path

1. **Phase 1 (current):** JWT + API key auth (deployed)
2. **Phase 2 (next):** Key-exchange auth module (implemented, this spec)
3. **Phase 3:** Add handshake endpoints (`POST /v1/auth/hello`, `POST /v1/auth/verify`)
4. **Phase 4:** New clients use key-exchange; legacy clients continue with JWT
5. **Phase 5:** Deprecate legacy auth; require key-exchange for all clients
