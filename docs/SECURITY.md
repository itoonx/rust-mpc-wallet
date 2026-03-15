# MPC Wallet — Security Posture Report

> **Auditor:** R6 Security Agent  
> **Audit Date:** 2026-03-15  
> **Version Audited:** `0.1.0` (commit `bdee859` — post-merge of all Phase 1 agents)  
> **Audit Type:** Initial comprehensive audit (first cycle)

---

## Overall Security Posture Score

**3 / 10**

This score reflects the current **pre-production, Phase 1** state of the codebase. The
primary deduction is a CRITICAL protocol-level flaw (SEC-001) that fundamentally violates
the MPC architecture's core guarantee. Additional CRITICAL issues around hardcoded credentials
(SEC-002) and an entirely unimplemented production transport (SEC-003) prevent any production
deployment. The FROST-based protocols and the encryption-at-rest layer are well-designed and
represent a solid foundation — the score will improve significantly once the three CRITICAL
findings are resolved.

---

## Top 3 Risks to Address Before Production

### Risk 1 — [CRITICAL] GG20 Reconstructs Full Private Key (SEC-001)

The `Gg20Protocol::sign()` in `crates/mpc-wallet-core/src/protocol/gg20.rs` performs Lagrange
interpolation on all collected shares, fully reconstructing the secp256k1 private key on every
signing party. This is the textbook anti-pattern that threshold signing is designed to eliminate.
Any single signing party, if compromised during a signing session, leaks the complete key.

**Block:** Must be fixed before GG20 scheme is used for any real asset signing.  
**Owner:** R1 (Crypto Agent)

### Risk 2 — [CRITICAL] Hardcoded Fallback Password "demo-password" (SEC-002)

All four CLI commands (`keygen`, `sign`, `address`, `keys`) fall back to `"demo-password"` when
`--password` is not supplied. This is a publicly known credential that silently encrypts key
shares at rest with a trivially known password, completely circumventing the AES-256-GCM /
Argon2id layer. An attacker with filesystem access can decrypt any key store created by a
user who omitted the password flag.

**Block:** Must be removed before any user interaction with real key material.  
**Owner:** R4 (Service Agent)

### Risk 3 — [CRITICAL] NatsTransport Is All `todo!()` Stubs (SEC-003)

The production multi-party network transport (`NatsTransport`) has zero implemented behavior.
Every method panics. There is no TLS, no message authentication, no replay protection, and
no ECDH envelope encryption. The system currently runs exclusively in single-process demo
mode (`LocalTransport`). Without a working, secured transport, the SDK cannot be deployed
in any distributed multi-party configuration.

**Block:** Must be fully implemented before Phase 2 (distributed operation).  
**Owner:** R2 (Infrastructure Agent)

---

## What's Done Well

1. **FROST protocols avoid key reconstruction** (SEC-020): `FrostEd25519Protocol` and
   `FrostSecp256k1TrProtocol` correctly use the FROST library's threshold signing — each
   party produces only a signature share. The full private key is never assembled on any
   single machine during signing or key generation.

2. **`ZeroizeOnDrop` on all internal share structs** (verified): `Gg20ShareData`,
   `FrostEd25519ShareData`, and `FrostSecp256k1ShareData` all derive `ZeroizeOnDrop`.
   The `zeroize` crate is correctly listed as a workspace dependency and imported where
   needed.

3. **Encryption at rest with AES-256-GCM + Argon2id** (SEC-021): `EncryptedFileStore`
   generates a fresh random salt (16 bytes) and nonce (12 bytes) per write. There is no
   nonce reuse risk. AES-256-GCM with a 128-bit authentication tag provides authenticated
   encryption, protecting both confidentiality and integrity of stored key shares.

4. **EIP-55 checksum encoding for EVM addresses**: `derive_evm_address` correctly implements
   EIP-55 checksummed hex addresses, protecting against typo-based address errors.

5. **Correct Sui intent prefix and Blake2b-256 signing payload**: The Sui `sign_payload`
   computation (Blake2b-256 of `[0,0,0] || tx_data`) correctly follows the Sui signing
   spec. The signature wire format (`0x00 || sig(64) || pubkey(32)`) is correct for
   Ed25519. The zero-byte pubkey bug noted in AGENTS.md has been fixed (pubkey is now
   extracted from `GroupPublicKey` and embedded in `tx_data`).

6. **No secrets in git history** (SEC-022): Review of git history found no committed
   private keys, passwords, or API secrets. Only intentional test vectors (public keys
   for known test scalars) were found.

7. **Input validation on transaction parameters**: Chain providers validate key types
   (e.g., EVM rejects Ed25519 keys, Solana rejects secp256k1 keys) with meaningful errors.

8. **Modular trait-based architecture**: The `MpcProtocol`, `Transport`, `KeyStore`, and
   `ChainProvider` trait boundaries make security auditing tractable and keep security
   concerns contained.

---

## Finding Summary

| Severity | Count | IDs |
|----------|-------|-----|
| CRITICAL | 3 | SEC-001, SEC-002, SEC-003 |
| HIGH     | 4 | SEC-004, SEC-005, SEC-006, SEC-007 |
| MEDIUM   | 6 | SEC-008, SEC-009, SEC-010, SEC-011, SEC-012, SEC-013 |
| LOW      | 6 | SEC-014, SEC-015, SEC-016, SEC-017, SEC-018, SEC-019 |
| INFO     | 3 | SEC-020, SEC-021, SEC-022 |
| **Total**| **22** | |

---

## Dependency Audit (`cargo audit`)

Audit performed with `cargo-audit v0.22.1` against the advisory database (950 advisories).

**Vulnerabilities (1):**

| Crate | Version | Advisory | Severity | Description |
|-------|---------|----------|---------|-------------|
| `quinn-proto` | 0.11.13 | RUSTSEC-2026-0037 | **8.7 HIGH** | DoS in Quinn QUIC endpoints. Fix: upgrade to ≥ 0.11.14. Transitive via `alloy → reqwest → quinn`. |

**Warnings — Unmaintained Crates (4):**

| Crate | Version | Advisory | Notes |
|-------|---------|----------|-------|
| `atomic-polyfill` | 1.0.3 | RUSTSEC-2023-0089 | Transitive via `frost-core → postcard → heapless` |
| `derivative` | 2.2.0 | RUSTSEC-2024-0388 | Transitive via `alloy → ruint → ark-ff` |
| `paste` | 1.0.15 | RUSTSEC-2024-0436 | Transitive via `alloy → syn-solidity` |
| `rustls-pemfile` | 2.2.0 | RUSTSEC-2025-0134 | Transitive via `async-nats → rustls-native-certs` |

All unmaintained crate warnings are from transitive dependencies; none are direct workspace
dependencies. The `quinn-proto` DoS vulnerability (SEC-019) should be resolved by updating
`alloy` when a version pinning `quinn-proto >= 0.11.14` is available.

---

## Threat Model Assessment

| STRIDE Threat | Current Status |
|--------------|----------------|
| **Spoofing** | HIGH RISK — `ProtocolMessage.from` is self-reported, no sender authentication (SEC-007, SEC-013) |
| **Tampering** | MEDIUM RISK — AES-GCM provides integrity at rest; transport layer has no integrity protection (SEC-003) |
| **Repudiation** | HIGH RISK — No audit log, no signed operation receipts, no session transcripts |
| **Info Disclosure** | CRITICAL RISK — GG20 reconstructs full key on every signer (SEC-001); secret may persist in memory (SEC-005, SEC-008) |
| **DoS** | MEDIUM RISK — quinn-proto CVE (SEC-019); panic on malformed Bitcoin tx (SEC-016) |
| **Elevation of Privilege** | HIGH RISK — Hardcoded demo password trivially decrypts all key shares (SEC-002) |

---

## Recommendations Priority Queue (Pre-Production Checklist)

**Sprint 1 (Block-release):**
- [ ] SEC-001: Replace GG20 key reconstruction with proper threshold ECDSA (R1)
- [ ] SEC-002: Remove all `"demo-password"` fallbacks; require explicit password or prompt (R4)
- [ ] SEC-003: Implement NatsTransport with TLS + ECDH envelope + replay protection (R2)

**Sprint 2 (Security hardening):**
- [ ] SEC-004: Wrap `KeyShare.share_data` in `Zeroizing<Vec<u8>>`; redact Debug (R0/R1)
- [ ] SEC-005: Zeroize derived key and password in EncryptedFileStore (R2)
- [ ] SEC-006: Increase Argon2id parameters: m=65536, t=3, p=4 (R2)
- [ ] SEC-007: Authenticate sender identity in Transport; strip self-reported `from` (R2/R0)
- [ ] SEC-009: Supply correct `prev_out.script_pubkey` for Taproot sighash (R3b)
- [ ] SEC-019: Pin `quinn-proto >= 0.11.14` (R2)

**Sprint 3 (Quality / defense-in-depth):**
- [ ] SEC-008: Explicitly zeroize secret scalar in GG20 signing (R1)
- [ ] SEC-010: Compute real Solana tx_hash from signature (R3c)
- [ ] SEC-011: Replace JSON stub with BCS in Sui (R3d)
- [ ] SEC-012: Assert/enforce low-S ECDSA in EVM finalization (R3a)
- [ ] SEC-013: Reject duplicate/forged `from` IDs in FROST message collection (R1)
- [ ] SEC-014: Gate LocalTransport behind `#[cfg(any(test, feature="demo"))]` (R2)
- [ ] SEC-015: Redact `share_data` in `KeyShare` Debug output (R0)
- [ ] SEC-016: Replace panicking `.unwrap()` in Bitcoin SerializableTx (R3b)
- [ ] SEC-017: Validate Solana `from` matches signing pubkey (R3c)
- [ ] SEC-018: Upgrade async-nats when rustls-pemfile replacement available (R2)

---

## Escalation to R7 (PM Agent)

The following CRITICAL findings must be resolved before any sprint that involves real key
material or distributed deployment:

1. **SEC-001** — GG20 full key reconstruction: Block use of `Gg20Ecdsa` scheme in any non-demo
   context until replaced. Suggest R7 mark CLI commands with `Gg20Ecdsa` scheme as
   `--experimental` and emit a loud warning.

2. **SEC-002** — Hardcoded demo password: All CLI commands silently use `"demo-password"`.
   Any key generated by the current CLI release should be considered compromised if the user
   did not explicitly pass `--password`.

3. **SEC-003** — NatsTransport unimplemented: The SDK cannot be safely deployed in any
   multi-machine configuration until R2 completes the NatsTransport implementation.

---

*Next audit cycle: after Sprint 1 fixes are merged. Focus: verify SEC-001/002/003 resolution,
re-audit GG20 replacement implementation, and confirm NatsTransport TLS configuration.*
