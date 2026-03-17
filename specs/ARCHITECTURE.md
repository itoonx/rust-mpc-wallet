# Architecture

## System Overview

```
┌─────────────────────────────────────────────────────────┐
│                    mpc-wallet-cli                        │
│  keygen | sign | simulate | audit-verify | list-keys     │
└──────────────────────┬──────────────────────────────────┘
                       │
┌──────────────────────┴──────────────────────────────────┐
│                  mpc-wallet-chains                       │
│  ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐       │
│  │   EVM   │ │ Bitcoin │ │ Solana  │ │   Sui   │       │
│  │ EIP-1559│ │ Taproot │ │   v0    │ │  BCS    │       │
│  └────┬────┘ └────┬────┘ └────┬────┘ └────┬────┘       │
│       └──────┬─────┴──────────┴─────┬──────┘            │
│         ChainProvider trait    ChainRegistry              │
└──────────────────────┬──────────────────────────────────┘
                       │
┌──────────────────────┴──────────────────────────────────┐
│                  mpc-wallet-core                         │
│                                                          │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐              │
│  │ Protocol │  │Transport │  │ KeyStore │              │
│  │  GG20    │  │  NATS    │  │  AES-GCM │              │
│  │  FROST   │  │  mTLS    │  │  Argon2  │              │
│  │  Ed25519 │  │  ECDH    │  │  Zeroize │              │
│  └──────────┘  └──────────┘  └──────────┘              │
│                                                          │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐              │
│  │  Policy  │  │Approvals │  │  Audit   │              │
│  │ velocity │  │ quorum   │  │hashchain │              │
│  │ signed   │  │  SoD     │  │ Ed25519  │              │
│  │templates │  │  MFA     │  │   WORM   │              │
│  └──────────┘  └──────────┘  └──────────┘              │
│                                                          │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐              │
│  │ Identity │  │  RBAC    │  │   Ops    │              │
│  │   JWT    │  │ 3 roles  │  │ failover │              │
│  │  ABAC    │  │  guards  │  │  chaos   │              │
│  │   MFA    │  │          │  │   DR     │              │
│  └──────────┘  └──────────┘  └──────────┘              │
└─────────────────────────────────────────────────────────┘
```

## Core Traits (Plugin Boundaries)

| Trait | Purpose | Implementations |
|-------|---------|----------------|
| `MpcProtocol` | Distributed keygen, sign, refresh, reshare | GG20 ECDSA, FROST Ed25519, FROST Secp256k1-Taproot |
| `Transport` | Inter-party messaging | NATS (mTLS + ECDH + SignedEnvelope), Local (testing) |
| `KeyStore` | Encrypted share persistence | EncryptedFileStore (AES-256-GCM + Argon2id) |
| `ChainProvider` | Chain-specific tx building | EVM, Bitcoin, Solana, Sui |

## Module Map

### mpc-wallet-core

| Module | Purpose |
|--------|---------|
| `protocol/gg20.rs` | GG20 threshold ECDSA (additive shares, no key reconstruction) |
| `protocol/frost_ed25519.rs` | FROST Ed25519 with DKG-based refresh |
| `protocol/frost_secp256k1.rs` | FROST Secp256k1 with Taproot tweaks |
| `transport/nats.rs` | NATS transport with mTLS + SignedEnvelope |
| `transport/session_key.rs` | X25519 ECDH + ChaCha20-Poly1305 per-session encryption |
| `transport/jetstream.rs` | JetStream stream config + per-party ACL |
| `key_store/encrypted.rs` | AES-256-GCM + Argon2id encrypted file store |
| `policy/` | Policy engine: schema, evaluator, velocity, signed bundles, templates |
| `approvals/` | M-of-N quorum, maker/checker/approver SoD |
| `audit/` | Hash-chained ledger, Ed25519 signatures, evidence pack, WORM config |
| `identity/` | JWT validation (RS256/ES256), ABAC attributes |
| `rbac/` | ApiRole (initiator/approver/admin), MFA step-up |
| `session/` | Session state machine, tx_fingerprint idempotency |
| `ops/` | Multi-cloud constraints, quorum risk, RPC failover, chaos, DR |

### mpc-wallet-chains

| Module | Purpose |
|--------|---------|
| `evm/` | Ethereum/Polygon/BSC — EIP-1559, low-S normalization, simulation |
| `bitcoin/` | Taproot P2TR, PSBT validation, fee/dust checks |
| `solana/` | Legacy + v0 versioned tx, Address Lookup Tables, program allowlist |
| `sui/` | BCS encoding, intent prefix, gas budget simulation |
| `registry.rs` | ChainRegistry — unified provider factory |

## Design Principles

1. **No key reconstruction** — additive shares combined via partial signatures
2. **Trait boundaries = parallel work boundaries** — agents work independently
3. **Defense in depth** — TLS + ECDH + SignedEnvelope layered security
4. **Zeroize everything** — all key material wiped from memory on drop
5. **No policy → no sign** — signing blocked without explicit policy
