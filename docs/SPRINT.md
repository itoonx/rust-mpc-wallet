# Sprint 1 — 2026-03-15

## Goal
**"Production-ready crypto core + all chains correct"**

Replace the GG20 key-reconstruction simulation with real distributed ECDSA, complete BCS
serialization for Sui, validate Solana wire-format against the real SDK, and add proactive
key refresh — so the codebase is no longer blocked on fundamental correctness issues.

**Sprint duration:** 2 weeks (2026-03-15 → 2026-03-29)  
**Sprint owner:** R7 PM Agent

---

## Active Tasks

| ID | Agent | Task | Branch | Story | Complexity | Status |
|----|-------|------|--------|-------|-----------|--------|
| T-01 | R1 | Replace GG20 simulation with real multi-party ECDSA (J1) | `agent/r1-zeroize` | J1 | XL | pending |
| T-02 | R1 | Complete zeroize coverage for all protocol impls (J4) | `agent/r1-zeroize` | J4 | M | pending |
| T-03 | R1 | Proactive key refresh implementation (H1) | `agent/r1-zeroize` | H1 | L | pending |
| T-04 | R1 | Add `freeze` method implementation to `EncryptedFileStore` (H3) | `agent/r1-zeroize` | H3 | S | blocked — needs T-05 (R0 interface change) |
| T-05 | R0 | Add `freeze` / `unfreeze` to `KeyStore` trait (0-1) | `agent/r0-interface` | 0-1 | S | pending — prerequisite for T-04 |
| T-06 | R3d | Full BCS transaction serialization for Sui (J2) | `agent/r3d-sui-followup` | J2 | L | pending |
| T-07 | R3c | Validate / harden Solana wire-format transaction (J3) | `agent/r3c-sol` | J3 | M | pending |

---

## Task Details

### T-01 — Replace GG20 simulation with real multi-party ECDSA
**Agent:** R1  
**Branch:** `agent/r1-zeroize`  
**Story:** J1  
**Complexity:** XL

**Context:**
`crates/mpc-wallet-core/src/protocol/gg20.rs` currently implements signing by reconstructing the
full private key via Lagrange interpolation (`lagrange_interpolate`), then signing with the
reconstructed secret using `k256::ecdsa::SigningKey`. This is cryptographically correct for
a simulation but is a **critical security flaw** for production — any single node that completes
the sign round can recover the full key.

**Approach (see DEC-001 in DECISIONS.md):**
Integrate `multi-party-ecdsa` (Zengo GG20/CGGMP21) crate. The signing protocol must produce
partial ECDSA signatures that combine into a valid secp256k1 ECDSA signature without any party
ever holding the full secret scalar.

If `multi-party-ecdsa` introduces dependency conflicts, fall back to a correct 2-round Schnorr-on-
secp256k1 protocol using `k256` primitives directly (linear combination of partial nonces and
scalars) while tagging a `// TODO: upgrade to full GG20` comment for the next sprint.

**Acceptance Criteria:**
1. `gg20.rs::sign()` does not call `lagrange_interpolate` or any equivalent full-secret-reconstruction.
2. Integration test: 2-of-3 signing protocol produces a signature that verifies against the
   group public key using `k256::ecdsa::VerifyingKey::verify`.
3. `cargo test -p mpc-wallet-core` passes.
4. R6 security review: code inspection confirms no reconstruction path.

**Dependencies:** None (can start immediately).

---

### T-02 — Complete zeroize coverage
**Agent:** R1  
**Branch:** `agent/r1-zeroize`  
**Story:** J4  
**Complexity:** M

**Context:**
`Gg20ShareData` already has `#[derive(ZeroizeOnDrop)]` but `y: Vec<u8>` is not currently
wrapped in `Zeroizing<Vec<u8>>`. FROST share data also needs audit. Ephemeral signing scalars
(per-round nonces) must be zeroized after use.

**Acceptance Criteria:**
1. `Gg20ShareData.y` uses `zeroize::Zeroizing<Vec<u8>>`.
2. FROST Ed25519 and secp256k1 share structs use `ZeroizeOnDrop` on all secret fields.
3. Any ephemeral nonce / scalar created during `sign()` is wrapped in `Zeroizing`.
4. `cargo test -p mpc-wallet-core` passes.

**Dependencies:** Can overlap with T-01.

---

### T-03 — Proactive key refresh
**Agent:** R1  
**Branch:** `agent/r1-zeroize`  
**Story:** H1  
**Complexity:** L

**Context:**
Proactive refresh re-randomizes all shares periodically (e.g., weekly) so that a share
compromised before the refresh is no longer useful after. The group public key and all
on-chain addresses remain unchanged.

For GG20/ECDSA: each party generates a fresh polynomial with constant term = 0, distributes
resharing shares, each party adds the new reshare to their existing share. The sum of the
polynomials' constant terms = sum of the secrets = unchanged original secret.

**Acceptance Criteria:**
1. `MpcProtocol::refresh(key_share, transport) -> Result<KeyShare>` is defined (requires T-05 /
   R0 to add method to trait, or implement as a standalone function if trait change is delayed).
2. After refresh, all new shares reconstruct the same group public key.
3. Old shares + new shares cannot be mixed to reconstruct the key.
4. Integration test with 2-of-3 parties passes.

**Dependencies:** T-05 (R0 must add `refresh` to `MpcProtocol` trait) — if R0 is delayed,
implement as a standalone module function first and wire into the trait in Sprint 2.

---

### T-04 — Add `freeze` implementation to `EncryptedFileStore`
**Agent:** R1  
**Branch:** `agent/r1-zeroize`  
**Story:** H3  
**Complexity:** S

**Context:**
R0 must first add `freeze(group_id)` and `unfreeze(group_id)` to the `KeyStore` trait (T-05).
Once the trait is updated, R1 implements the methods in `EncryptedFileStore`: persist a
`frozen: bool` flag to storage alongside the key share metadata.

**Acceptance Criteria:**
1. `EncryptedFileStore::freeze(group_id)` writes `frozen: true` to the metadata JSON.
2. `EncryptedFileStore::load(group_id, ...)` returns `CoreError::KeyFrozen` if frozen.
3. `EncryptedFileStore::unfreeze(group_id)` clears the flag.
4. `cargo test -p mpc-wallet-core` passes.

**Dependencies:** T-05 (R0 interface change — BLOCKING).

---

### T-05 — Add `freeze` / `unfreeze` to `KeyStore` trait
**Agent:** R0  
**Branch:** `agent/r0-interface`  
**Story:** 0-1  
**Complexity:** S

**Context:**
This is a prerequisite for T-04. R0 must add two methods to the `KeyStore` trait in
`crates/mpc-wallet-core/src/key_store/mod.rs`:

```rust
async fn freeze(&self, group_id: &KeyGroupId) -> Result<(), CoreError>;
async fn unfreeze(&self, group_id: &KeyGroupId) -> Result<(), CoreError>;
```

Also add `CoreError::KeyFrozen` variant to `error.rs` if not present.

**Acceptance Criteria:**
1. `KeyStore` trait has `freeze` and `unfreeze` methods.
2. `CoreError::KeyFrozen` variant exists.
3. `cargo check --workspace` passes.

**Dependencies:** None (can start immediately — highest priority interface change).

---

### T-06 — Full BCS transaction serialization for Sui
**Agent:** R3d  
**Branch:** `agent/r3d-sui-followup`  
**Story:** J2  
**Complexity:** L

**Context:**
`crates/mpc-wallet-chains/src/sui/tx.rs` currently uses a canonical JSON blob as the
transaction bytes. The TODO comment in the file correctly identifies the fix needed:
replace the JSON with BCS-encoded `TransactionData`.

The current sign_payload computation (Blake2b-256 of intent prefix || tx_bytes) is already
correct per the Sui spec; only the serialization of `tx_bytes` needs fixing.

**Approach (see DEC-003 in DECISIONS.md — add if needed):**
Use the `bcs` crate (lightweight BCS serializer) with a minimal manually-defined
`SuiTransactionData` struct that matches the on-chain format. Do NOT add the full Sui SDK
as a workspace dependency (it pulls in hundreds of crates and has version conflicts).

**Acceptance Criteria:**
1. `build_sui_transaction` produces BCS-encoded `TransactionData` bytes (not JSON).
2. `finalize_sui_transaction` produces a 97-byte Sui signature: `[0x00] || sig(64) || pubkey(32)`.
3. Sign payload is `Blake2b-256(SUI_INTENT_PREFIX || bcs_tx_bytes)` — the hashing is unchanged,
   only the input format changes.
4. Unit test: build → sign → verify using `ed25519-dalek`'s verifier on the sign_payload hash.
5. `cargo test -p mpc-wallet-chains` passes.

**Dependencies:**
- R0 must approve adding `bcs` crate to `[workspace.dependencies]` in `Cargo.toml`.
  (R7 pre-approves this as it's a lightweight, well-maintained crate with no security concerns.)

---

### T-07 — Validate / harden Solana wire-format transaction
**Agent:** R3c  
**Branch:** `agent/r3c-sol`  
**Story:** J3  
**Complexity:** M

**Context:**
`crates/mpc-wallet-chains/src/solana/tx.rs` was already updated with a manual binary
serialization (not a JSON stub). The serialization logic looks correct based on the Solana
spec, but it has not been validated against the real `solana-sdk` crate output.

**Approach (see DEC-002 in DECISIONS.md):**
Add `solana-program` (lightweight, ~60 crates) rather than `solana-sdk` (300+ crates) as a
dev-dependency only (for test validation). The production code path keeps the manual serialization
which avoids the large dependency in SDK consumers' builds.

**Acceptance Criteria:**
1. Test that builds a Solana transfer transaction using the manual serializer, then deserializes
   the result using `solana-program`'s `Message::deserialize` and verifies field values match.
2. `encode_compact_u16` tested with values: 0, 1, 127, 128, 16383.
3. `finalize_solana_transaction` tested: output is 1 (compact-u16) + 64 (sig) + N (msg) bytes.
4. `cargo test -p mpc-wallet-chains` passes.

**Dependencies:**
- R0 must approve adding `solana-program` as a dev-dependency. (R7 pre-approves as dev-only.)

---

## Blocked Tasks

| ID | Task | Blocker | Resolution |
|----|------|---------|------------|
| T-04 | Add `freeze` impl to `EncryptedFileStore` | Needs `KeyStore::freeze` trait method (T-05) | R0 must complete T-05 first. Target: Day 1–2 of sprint. |
| T-03 | Proactive key refresh | Ideally needs `MpcProtocol::refresh` in trait | R0 to add in parallel with T-05. R1 can start as standalone function if R0 is delayed. |

---

## Done This Sprint

*(Updated at sprint close — 2026-03-29)*

---

## Sprint Notes

- **Priority order for R1:** T-01 (real GG20) > T-02 (zeroize) > T-03 (refresh) > T-04 (freeze impl).
  T-01 is the most critical correctness fix in the entire codebase.
- **R3d and R3c** can work in parallel — no shared files.
- **R0** should complete T-05 in the first two days to unblock T-04.
- **R6** security audit should review T-01 output before sprint close — specifically confirm
  no secret reconstruction path exists in the new GG20 implementation.
- **bcs crate addition:** R7 pre-approves. R0 to add to `Cargo.toml` as part of T-05 batch or
  T-06 unblocking.
