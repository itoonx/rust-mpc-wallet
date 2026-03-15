# Sprint 1 — 2026-03-15 → 2026-03-29

## Goal
**"Production-ready crypto core + all chains correct"**

Replace the GG20 key-reconstruction simulation with real distributed ECDSA, complete BCS
serialization for Sui, validate Solana wire-format against the real SDK, and add proactive
key refresh — so the codebase is no longer blocked on fundamental correctness issues.

**Sprint owner:** R7 PM Agent

---

## Gate Status

| Task | Agent | Branch | PM Approved | Implementation | R6 Verdict | Merged |
|------|-------|--------|-------------|----------------|------------|--------|
| T-01 | R1 | `agent/r1-zeroize` | ✓ | pending | pending | ✗ |
| T-02 | R1 | `agent/r1-zeroize` | ✓ | pending | pending | ✗ |
| T-03 | R1 | `agent/r1-zeroize` | ✓ | pending | pending | ✗ |
| T-04 | R1 | `agent/r1-zeroize` | ✓ | blocked (needs T-05) | pending | ✗ |
| T-05 | R0 | `agent/r0-interface` | ✓ | pending | pending | ✗ |
| T-06 | R3d | `agent/r3d-sui-followup` | ✓ | pending | pending | ✗ |
| T-07 | R3c | `agent/r3c-sol` | ✓ | pending | pending | ✗ |

---

## Task Specs

### Task Spec: T-01 — Replace GG20 simulation with real distributed ECDSA
- **Agent:** R1
- **Branch:** `agent/r1-zeroize`
- **Epic:** Epic J (Production Hardening)
- **Files owned (agent may only touch these):**
  - `crates/mpc-wallet-core/src/protocol/gg20.rs`
  - `crates/mpc-wallet-core/tests/protocol_integration.rs`
- **Acceptance Criteria:**
  - [ ] `gg20.rs::sign()` does NOT call `lagrange_interpolate` or any equivalent full-secret reconstruction
  - [ ] Integration test: 2-of-3 signing protocol produces a signature that verifies against the group public key using `k256::ecdsa::VerifyingKey::verify`
  - [ ] Old simulation gated behind `#[cfg(feature = "gg20-simulation")]`
  - [ ] `cargo test -p mpc-wallet-core` passes
- **Dependencies:** None (can start immediately)
- **Complexity:** XL

#### Security Checklist for R6
- [ ] Private key scalar is NEVER reconstructed during signing on any party — inspect every code path in `sign()`
- [ ] No call to `lagrange_interpolate` or equivalent secret-aggregation in production (non-simulation) path
- [ ] Any ephemeral nonce/scalar (`k_i`, `s_i`) is wrapped in `Zeroizing<T>` or explicitly zeroized before drop
- [ ] `#[cfg(feature = "gg20-simulation")]` gate is present and the simulation path cannot be activated in production builds
- [ ] No new `todo!()` macros in the signing or keygen critical path
- [ ] `cargo audit` clean — no new advisories introduced by this branch
- [ ] R6 code inspection confirms no reconstruction path exists (SEC-001 resolved)

---

### Task Spec: T-02 — Complete zeroize coverage for all protocol impls
- **Agent:** R1
- **Branch:** `agent/r1-zeroize`
- **Epic:** Epic J (Production Hardening)
- **Files owned (agent may only touch these):**
  - `crates/mpc-wallet-core/src/protocol/gg20.rs`
  - `crates/mpc-wallet-core/src/protocol/frost_ed25519.rs`
  - `crates/mpc-wallet-core/src/protocol/frost_secp256k1.rs`
- **Acceptance Criteria:**
  - [ ] `Gg20ShareData.y` uses `zeroize::Zeroizing<Vec<u8>>`
  - [ ] FROST Ed25519 and secp256k1 share structs use `ZeroizeOnDrop` on all secret fields
  - [ ] Any ephemeral nonce / scalar created during `sign()` is wrapped in `Zeroizing`
  - [ ] `cargo test -p mpc-wallet-core` passes
- **Dependencies:** Can overlap with T-01
- **Complexity:** M

#### Security Checklist for R6
- [ ] `Gg20ShareData` — all fields containing secret material wrapped in `Zeroizing<T>` or `#[zeroize(drop)]`
- [ ] `FrostEd25519ShareData` — same check
- [ ] `FrostSecp256k1ShareData` — same check
- [ ] No `impl Clone` on share structs that would copy secret material into unprotected memory
- [ ] Ephemeral signing scalars (nonces, partial `s` values) do not outlive their use
- [ ] `cargo audit` clean — no new advisories
- [ ] Addresses SEC-008 (GG20 secret scalar not zeroized after use)

---

### Task Spec: T-03 — Proactive key refresh implementation
- **Agent:** R1
- **Branch:** `agent/r1-zeroize`
- **Epic:** Epic H (Key Lifecycle)
- **Files owned (agent may only touch these):**
  - `crates/mpc-wallet-core/src/protocol/gg20.rs`
  - `crates/mpc-wallet-core/src/protocol/frost_ed25519.rs`
  - `crates/mpc-wallet-core/src/protocol/frost_secp256k1.rs`
  - `crates/mpc-wallet-core/tests/protocol_integration.rs`
- **Acceptance Criteria:**
  - [ ] `MpcProtocol::refresh(key_share, transport) -> Result<KeyShare>` defined (or standalone module function if trait change delayed)
  - [ ] After refresh, all new shares reconstruct the same group public key
  - [ ] Old shares + new shares cannot be mixed to reconstruct the key
  - [ ] Integration test with 2-of-3 parties passes
  - [ ] `cargo test -p mpc-wallet-core` passes
- **Dependencies:** T-05 ideally (R0 must add `refresh` to `MpcProtocol` trait); R1 may start as standalone function if R0 is delayed
- **Complexity:** L

#### Security Checklist for R6
- [ ] Resharing polynomial constant term is zero (additive randomization, not re-keying)
- [ ] Group public key is unchanged after refresh — verified by test
- [ ] Old + new shares cannot be combined — verified by test (reconstruct should fail or produce wrong result)
- [ ] All ephemeral re-sharing scalars are zeroized after use
- [ ] No logging of intermediate share values
- [ ] `cargo audit` clean

---

### Task Spec: T-04 — Add `freeze` / `unfreeze` implementation to `EncryptedFileStore`
- **Agent:** R1
- **Branch:** `agent/r1-zeroize`
- **Epic:** Epic H (Key Lifecycle)
- **Files owned (agent may only touch these):**
  - `crates/mpc-wallet-core/src/key_store/encrypted.rs`
- **Acceptance Criteria:**
  - [ ] `EncryptedFileStore::freeze(group_id)` writes `frozen: true` to the metadata JSON
  - [ ] `EncryptedFileStore::load(group_id, ...)` returns `CoreError::KeyFrozen` if frozen
  - [ ] `EncryptedFileStore::unfreeze(group_id)` clears the flag
  - [ ] `cargo test -p mpc-wallet-core` passes
- **Dependencies:** T-05 (R0 must add `freeze`/`unfreeze` to `KeyStore` trait — **BLOCKING**)
- **Complexity:** S

#### Security Checklist for R6
- [ ] `frozen` flag stored durably (on disk) — not only in-memory
- [ ] `load()` checks frozen flag BEFORE decrypting key material
- [ ] No timing side-channel between frozen and non-frozen branches in `load()`
- [ ] `unfreeze()` requires the same authentication as other `KeyStore` operations
- [ ] `cargo audit` clean

---

### Task Spec: T-05 — Add `freeze` / `unfreeze` to `KeyStore` trait
- **Agent:** R0
- **Branch:** `agent/r0-interface`
- **Epic:** Epic H (Key Lifecycle) / Story 0-1
- **Files owned (agent may only touch these):**
  - `crates/mpc-wallet-core/src/key_store/mod.rs`
  - `crates/mpc-wallet-core/src/error.rs`
  - `Cargo.toml` (workspace — only if bcs/solana-program approval needed)
- **Acceptance Criteria:**
  - [ ] `KeyStore` trait has `async fn freeze(&self, group_id: &KeyGroupId) -> Result<(), CoreError>`
  - [ ] `KeyStore` trait has `async fn unfreeze(&self, group_id: &KeyGroupId) -> Result<(), CoreError>`
  - [ ] `CoreError::KeyFrozen` variant exists in `error.rs`
  - [ ] `cargo check --workspace` passes
- **Dependencies:** None (highest-priority interface change — start Day 1)
- **Complexity:** S

#### Security Checklist for R6
- [ ] Trait method signatures use `&self` (not `&mut self`) — consistent with existing trait API
- [ ] `CoreError::KeyFrozen` is non-exhaustive-safe (no breaking match patterns)
- [ ] No implementation logic in the trait definition (only signatures + default impl if needed)
- [ ] `cargo audit` clean

---

### Task Spec: T-06 — Full BCS transaction serialization for Sui
- **Agent:** R3d
- **Branch:** `agent/r3d-sui-followup`
- **Epic:** Epic J (Production Hardening) / Story J2
- **Files owned (agent may only touch these):**
  - `crates/mpc-wallet-chains/src/sui/tx.rs`
  - `crates/mpc-wallet-chains/src/sui/mod.rs`
  - `crates/mpc-wallet-chains/tests/` (Sui test files)
- **Acceptance Criteria:**
  - [ ] `build_sui_transaction` produces BCS-encoded `TransactionData` bytes (not JSON)
  - [ ] `finalize_sui_transaction` produces a 97-byte Sui signature: `[0x00] || sig(64) || pubkey(32)`
  - [ ] Sign payload is `Blake2b-256(SUI_INTENT_PREFIX || bcs_tx_bytes)` — hashing unchanged, only input format changes
  - [ ] Unit test: build → sign → verify using `ed25519-dalek` verifier on the sign_payload hash
  - [ ] Zero-byte public key bug (`[0u8; 32]`) fixed — actual Ed25519 pubkey from `GroupPublicKey` used
  - [ ] `cargo test -p mpc-wallet-chains` passes
- **Dependencies:** R0 must approve adding `bcs = "0.1"` to `[workspace.dependencies]` (R7 pre-approves)
- **Complexity:** L

#### Security Checklist for R6
- [ ] BCS struct field order matches the on-chain `TransactionData` spec exactly — verify against Sui docs
- [ ] Intent prefix bytes are correct for the Sui transaction intent (`[0, 0, 0]` for transaction)
- [ ] `finalize_sui_transaction` uses the actual `GroupPublicKey` Ed25519 bytes — no `[0u8; 32]` placeholder (fixes SEC-011)
- [ ] Blake2b-256 hash input is `intent_prefix || bcs_tx_bytes` in that exact order
- [ ] No secret material logged or returned in error messages
- [ ] `cargo audit` clean — `bcs` crate has no known advisories

---

### Task Spec: T-07 — Validate / harden Solana wire-format transaction
- **Agent:** R3c
- **Branch:** `agent/r3c-sol`
- **Epic:** Epic J (Production Hardening) / Story J3
- **Files owned (agent may only touch these):**
  - `crates/mpc-wallet-chains/src/solana/tx.rs`
  - `crates/mpc-wallet-chains/src/solana/mod.rs`
  - `crates/mpc-wallet-chains/tests/` (Solana test files)
- **Acceptance Criteria:**
  - [ ] Test that builds a Solana transfer transaction using the manual serializer, then deserializes using `solana-program`'s `Message::deserialize` and verifies field values match
  - [ ] `encode_compact_u16` tested with values: 0, 1, 127, 128, 16383
  - [ ] `finalize_solana_transaction` tested: output is 1 (compact-u16) + 64 (sig) + N (msg) bytes
  - [ ] Transaction ID / `tx_hash` is base58-encoded signature (not first 8 bytes) — fixes SEC-010
  - [ ] `cargo test -p mpc-wallet-chains` passes
- **Dependencies:** R0 must approve adding `solana-program` as dev-dependency (R7 pre-approves as dev-only)
- **Complexity:** M

#### Security Checklist for R6
- [ ] `tx_hash` field in `SignedTransaction` is the base58-encoded full 64-byte signature (not truncated 8-byte hex) — resolves SEC-010
- [ ] `from` address validated against signing public key before transaction construction — check for SEC-017 fix
- [ ] Compact-u16 encoding is correct for all boundary values (0, 127, 128, 16383) — test coverage
- [ ] No secret material (signing key bytes) present in `SignedTransaction` output struct
- [ ] `cargo audit` clean — `solana-program` dev-dep has no new advisories affecting production builds

---

## Blocked Tasks

| Task | Blocker | Owner | Resolution |
|------|---------|-------|------------|
| T-04 | Needs `KeyStore::freeze` / `unfreeze` trait methods (T-05) | R0 | R0 must complete T-05 first. Target: Day 1–2 of sprint. |
| T-03 | Ideally needs `MpcProtocol::refresh` in trait | R0 | R0 to add in parallel with T-05. R1 can start as standalone function if R0 is delayed. |

---

## Done (pre-Sprint 1, already on main)

The following tasks were completed and merged to `main` before Sprint 1 began.
They are tracked here for completeness. **No R6 gate re-audit required** (merged pre-gate-model).

| Agent | Task | Branch (merged) | Description |
|-------|------|-----------------|-------------|
| R1 | Pre-sprint zeroize | `agent/r1-zeroize` (pre-merge) | `ZeroizeOnDrop` on `Gg20ShareData`, `FrostEd25519ShareData`, `FrostSecp256k1ShareData` |
| R2 | NatsTransport stub | `agent/r2-nats` (pre-merge) | `NatsTransport` struct and `todo!()` stubs committed (full impl is T-TODO Sprint 2+) |
| R3a | EVM multi-network | `agent/r3a-evm` (pre-merge) | Polygon, BSC, Arbitrum, Base chain IDs added to `EvmProvider` |
| R3b | Bitcoin testnet | `agent/r3b-btc` (pre-merge) | Testnet/signet support added to `BitcoinProvider` |
| R3c | Solana binary serialization | `agent/r3c-sol` (pre-merge) | Manual wire-format serialization replacing JSON stub |
| R3d | Sui cleanup | `agent/r3d-sui-followup` (pre-merge) | Initial Sui provider scaffolding |

---

## Sprint Notes

- **Priority order for R1:** T-01 (real GG20) > T-02 (zeroize) > T-03 (refresh) > T-04 (freeze impl).
  T-01 is the most critical correctness fix in the entire codebase.
- **R3d and R3c** can work in parallel — no shared files.
- **R0** should complete T-05 in the first two days to unblock T-04.
- **R6 gate:** R6 must issue APPROVED verdict for each task branch before it can merge to main.
  T-01 R6 review is the highest-priority audit — must confirm SEC-001 is resolved.
- **bcs crate addition:** R7 pre-approves. R0 to add to `Cargo.toml` as part of T-05 batch or
  T-06 unblocking.
- **No branch merges without R6 APPROVED** — this is enforced per the Sprint Gate Model in AGENTS.md.

---

# Sprint 2 — HARD COMMITMENT: Real GG20 (Zengo multi-party-ecdsa)

## Goal
Replace the custom k256 distributed ECDSA from Sprint 1 with production-grade
Zengo GG20/CGGMP21 multi-party ECDSA (no secret reconstruction, malicious-secure).

**Sprint dates:** 2026-03-30 → 2026-04-13 (tentative — confirmed after Sprint 1 close)

## Why this is a hard goal
SEC-001 (CRITICAL): GG20 simulation reconstructs the full private key on every signer.
This finding BLOCKS production deployment. The Sprint 1 custom k256 two-round protocol
(DEC-001 Option 5) is semi-honest-secure only — it eliminates the reconstruction flaw
but does not provide the malicious-secure guarantees required for enterprise custody.
Sprint 2 must escalate to full GG20/CGGMP21 to resolve SEC-001 at the required security level.

## Planned Tasks

### Task Spec: T-S2-00 — Add multi-party-ecdsa to workspace (R0)
- **Agent:** R0
- **Branch:** `agent/r0-gg20-dep`
- **Epic:** Epic J (Production Hardening)
- **Files owned (agent may only touch these):**
  - `Cargo.toml` (workspace `[workspace.dependencies]`)
- **Acceptance Criteria:**
  - [ ] `multi-party-ecdsa` or `cggmp21` crate added to `[workspace.dependencies]`
  - [ ] `cargo check --workspace` passes
  - [ ] No breaking version conflicts with existing workspace dependencies (`k256`, `rand`, `tokio`)
- **Dependencies:** None — unblocks T-S2-01
- **Complexity:** S

#### Security Checklist for R6
- [ ] New crate has no known CRITICAL CVEs (`cargo audit` clean after addition)
- [ ] License is compatible with MIT (check `multi-party-ecdsa` / `cggmp21` license)
- [ ] Transitive dependency delta reviewed — no new CRITICAL/HIGH advisories introduced
- [ ] `curv-kzen` transitive dep (if pulled in) has no open CRITICAL advisories

---

### Task Spec: T-S2-01 — Integrate multi-party-ecdsa (Zengo GG20/CGGMP21)
- **Agent:** R1
- **Branch:** `agent/r1-real-gg20`
- **Epic:** Epic J (Production Hardening)
- **Files owned (agent may only touch these):**
  - `crates/mpc-wallet-core/src/protocol/gg20.rs`
  - `crates/mpc-wallet-core/tests/protocol_integration.rs`
- **Acceptance Criteria:**
  - [ ] `sign()` never reconstructs the full private key on any party
  - [ ] 2-of-3 threshold signing test passes with cryptographic verification
  - [ ] Full GG20 keygen + sign + verify integration test passes
  - [ ] Sprint 1 custom k256 two-round protocol is gated behind `#[cfg(feature = "gg20-custom")]` or removed
  - [ ] `cargo test -p mpc-wallet-core` all pass
- **Dependencies:** T-S2-00 (R0 adds multi-party-ecdsa to Cargo.toml workspace deps)
- **Complexity:** XL

#### Security Checklist for R6
- [ ] Private key scalar NEVER reconstructed during signing — check every code path exhaustively
- [ ] Paillier encryption present and used correctly (if using full GG20 protocol)
- [ ] ZK proofs verified: commitment scheme (Phase 1/2), range proofs where required
- [ ] Nonces not reused across sessions — each signing session uses fresh randomness
- [ ] `zeroize` applied to all ephemeral secret values (partial nonces, partial scalars, Paillier plaintexts)
- [ ] `cargo audit` clean after new dependency added
- [ ] SEC-001 marked Resolved — R6 confirms full private key is never a single-party value

---

## Gate Status (Sprint 2)

| Task | Agent | Branch | R6 Verdict | Notes |
|------|-------|--------|------------|-------|
| T-S2-00 | R0 | `agent/r0-gg20-dep` | pending | Unblocks T-S2-01 |
| T-S2-01 | R1 | `agent/r1-real-gg20` | pending | Resolves SEC-001 CRITICAL |
