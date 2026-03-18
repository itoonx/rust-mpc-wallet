# Redis + KMS/HSM Migration Spec

## Problem

All auth state is in-memory — if the gateway restarts, sessions/revocations are lost.
Horizontal scaling is impossible because each instance has its own session store.
Server signing key sits in env var / process memory — no HSM protection.

```
Current (single-instance, in-memory):

  ┌─────────────── Gateway Process ───────────────┐
  │                                                │
  │  SessionStore     100k HashMap (RAM)           │ ← lost on restart
  │  ReplayCache      100k HashMap (RAM)           │ ← lost on restart
  │  PendingHandshakes HashMap (RAM, 30s TTL)      │ ← lost on restart
  │  revoked_keys     HashSet (RAM + file)         │ ← dynamic adds lost
  │  server_signing_key  Ed25519 in process memory │ ← no HSM/audit
  │                                                │
  └────────────────────────────────────────────────┘
```

## Target Architecture

```
┌─────── Gateway 1 ──────┐  ┌─────── Gateway 2 ──────┐
│                         │  │                         │
│  Local cache (L1)       │  │  Local cache (L1)       │
│  ↕ async read-through   │  │  ↕ async read-through   │
└────────┬────────────────┘  └────────┬────────────────┘
         │                            │
         ▼                            ▼
┌──────────────── Redis (TLS + auth) ────────────────┐
│                                                     │
│  session:{id}        → encrypted session blob + TTL │
│  replay:{nonce}      → "1" + TTL (60s)             │
│  handshake:{challenge} → serialized state + TTL (30s)│
│  revoked_keys        → SET of key_ids              │
│  client_registry     → HASH of key_id → entry      │
│                                                     │
└─────────────────────────┬───────────────────────────┘
                          │
                          ▼
┌─────────────── KMS/HSM ────────────────┐
│                                         │
│  server_signing_key → Ed25519 in HSM    │
│  session_encryption_key → AES-256 KEK   │
│  mpc_share_wrapping_key → per-group DEK │
│                                         │
│  Key NEVER leaves HSM                   │
│  Every sign/decrypt = audit log entry   │
└─────────────────────────────────────────┘
```

## Phase 1: Redis Session Store

### What Changes

| Component | Before | After |
|-----------|--------|-------|
| SessionStore | `HashMap<String, AuthenticatedSession>` | Redis `SET session:{id}` + local L1 cache |
| ReplayCache | `HashMap<String, u64>` | Redis `SETEX replay:{nonce}` |
| revoked_keys | `RwLock<HashSet<String>>` | Redis `SADD revoked_keys` |
| PendingHandshakes | `HashMap<String, PendingHandshake>` | Keep in-memory (30s TTL, sticky routing) |

### Session Encryption for Redis

Session keys (`client_write_key`, `server_write_key`) are cryptographic material.
They MUST NOT be stored plaintext in Redis.

```
Gateway encrypts before storing:
  plaintext = session.client_write_key || session.server_write_key  (64 bytes)
  nonce = random 12 bytes
  ciphertext = AES-256-GCM(session_encryption_key, nonce, plaintext)

Redis stores:
  KEY: session:{session_id}
  VALUE: {
    "client_key_id": "a1b2c3d4",
    "client_pubkey": "hex...",
    "encrypted_keys": "base64(nonce || ciphertext)",
    "expires_at": 1710771600,
    "created_at": 1710768000
  }
  EXPIRE: session_ttl seconds

Gateway decrypts after retrieval:
  plaintext = AES-256-GCM_decrypt(session_encryption_key, nonce, ciphertext)
  client_write_key = plaintext[0..32]
  server_write_key = plaintext[32..64]
```

The `session_encryption_key` comes from KMS (Phase 2) or env var (Phase 1).

### Implementation: SessionStore Trait

```rust
#[async_trait]
pub trait SessionBackend: Send + Sync {
    async fn store(&self, session: &AuthenticatedSession) -> bool;
    async fn get(&self, session_id: &str) -> Option<AuthenticatedSession>;
    async fn revoke(&self, session_id: &str) -> bool;
    async fn count(&self) -> usize;
}
```

Two backends:
- `InMemorySessionBackend` — current behavior (for tests + dev)
- `RedisSessionBackend` — production

### Config

```
SESSION_BACKEND=redis              # or "memory" (default)
REDIS_URL=rediss://user:pass@redis:6379/0  # TLS required
SESSION_ENCRYPTION_KEY=hex...      # 32-byte AES key (Phase 1: env, Phase 2: KMS)
```

## Phase 2: KMS/HSM for Signing Key

### What Changes

| Key | Before | After |
|-----|--------|-------|
| `server_signing_key` | Ed25519 in env var → process memory | KMS key ID → sign via API |
| `session_encryption_key` | (new) env var | KMS-derived DEK |

### Signing Abstraction

```rust
#[async_trait]
pub trait AuthSigner: Send + Sync {
    async fn sign(&self, message: &[u8]) -> Result<Vec<u8>, CoreError>;
    fn verifying_key(&self) -> &[u8; 32];
}
```

Two implementations:
- `LocalSigner` — current `ed25519_dalek::SigningKey` (dev/test)
- `KmsSigner` — AWS KMS / Azure Key Vault / GCP Cloud KMS

### Latency Consideration

KMS sign: ~10-50ms vs local: <1ms.
Handshake has 1 sign operation (ServerHello) → acceptable.
Per-request JWT verify does NOT use server signing key → no impact.

## Phase 3: MPC Key Share HSM Wrapping

### What Changes

| Key | Before | After |
|-----|--------|-------|
| MPC share encryption | AES-256-GCM + Argon2id (password) | AES-256-GCM + HSM-derived DEK |

### Envelope Encryption Pattern

```
HSM holds: Master Key (KEK)
  ↓
HSM derives: Data Encryption Key (DEK) per key group
  ↓
Gateway encrypts: KeyShare with DEK
  ↓
Store: encrypted share + encrypted DEK (wrapped by KEK)
  ↓
On load: HSM unwraps DEK → gateway decrypts share in-process
```

Key share bytes (`Zeroizing<Vec<u8>>`) are decrypted only in-process, never in HSM.

## Implementation Order

| Sprint | Scope | Files | Tests |
|--------|-------|-------|-------|
| **S1** | SessionStore trait + InMemory backend | `auth/session.rs` | **DONE** |
| **S2** | Redis backend + session encryption | `auth/session_redis.rs` | **DONE** (ChaCha20-Poly1305, Zeroizing KEK) |
| **S3** | ReplayCache → Redis | `state.rs`, `redis_backend.rs` | **DONE** (SET NX EX, SCAN) |
| **S4** | revoked_keys → Redis SET | `state.rs`, `redis_backend.rs` | **DONE** (SADD/SISMEMBER) |
| **S5** | AuthSigner trait + LocalSigner | `auth/signer.rs` | **DONE** |
| **S6** | KmsSigner (AWS KMS) | `auth/kms_signer.rs` | **DONE** (stub, returns Err) |
| **S7** | HSM key share wrapping | `key_store/hsm.rs` | **DONE** (LocalKeyEncryption) |
| **S8** | Real Redis integration | `redis_backend.rs` + `redis` crate | **DONE** (ConnectionManager, SCAN) |

## Security Checklist

- [ ] Redis connections: TLS + password auth (`rediss://`)
- [ ] Session keys encrypted before Redis storage (AES-256-GCM)
- [ ] Ephemeral handshake secrets NEVER in Redis
- [ ] KMS signing key: NEVER in application memory
- [ ] KMS audit trail: every sign/decrypt logged
- [ ] Redis failover: sessions invalidated, clients re-handshake
- [ ] Revoked keys: immediately propagated via Redis pub/sub
- [ ] Key share wrapping: envelope encryption with HSM-held KEK
