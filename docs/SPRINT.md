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
| T-05 | R0 | `agent/r0-interface` | ✓ | pending | pending | ✗ |
| T-06 | R3d | `agent/r3d-sui-followup` | ✓ | pending | pending | ✗ |
| T-07 | R3c | `agent/r3c-sol` | ✓ | pending | pending | ✗ |

---

## Task Specs

### Task Spec: T-01
- **Agent:** R1
- **Branch:** `agent/r1-zeroize`
- **Epic:** Epic J (Production Hardening)
- **Title:** Gate GG20 simulation behind `gg20-simulation` feature flag
- **Files owned (agent may only touch these):**
  - `crates/mpc-wallet-core/src/protocol/gg20.rs`
  - `crates/mpc-wallet-core/Cargo.toml`
- **Acceptance Criteria:**
  - [ ] `Cargo.toml` declares `[features] gg20-simulation = []` and the feature is **off by default**
  - [ ] All code in `gg20.rs` that calls `lagrange_interpolate` (line 232) is wrapped in `#[cfg(feature = "gg20-simulation")]`
  - [ ] A `compile_error!` or prominent doc comment at the top of the `gg20-simulation`-gated block warns: `"SECURITY: SIMULATION ONLY — reconstructs full private key — NOT FOR PRODUCTION"`
  - [ ] When the feature is **disabled** (default), `cargo test -p mpc-wallet-core` still passes (the simulation code is absent; tests that test Shamir/Lagrange must also be gated or updated to be feature-gated)
  - [ ] When the feature is **enabled** (`cargo test -p mpc-wallet-core --features gg20-simulation`), all existing tests still pass
  - [ ] `cargo check -p mpc-wallet-core` passes without the feature (default)
- **Dependencies:** None — can start immediately
- **Complexity:** S

#### Security Checklist for R6
- [ ] Feature flag is **off by default** — verify in `Cargo.toml` that `gg20-simulation` is NOT listed under `default = [...]`
- [ ] The `lagrange_interpolate` function and its call site in `sign()` are entirely absent from the non-simulation build — confirm via `cargo check -p mpc-wallet-core` (no feature) that `lagrange_interpolate` does not appear
- [ ] The `#[cfg(feature = "gg20-simulation")]` gate wraps the entire reconstruction path — no partial gating that leaves the scalar accessible
- [ ] The simulation warning comment is prominent (top of gated block) and accurately describes the risk (full key reconstruction)
- [ ] `cargo audit` clean — no new advisories; no new dependencies added

---

### Task Spec: T-02
- **Agent:** R1
- **Branch:** `agent/r1-zeroize`
- **Epic:** Epic H (Key Lifecycle)
- **Title:** Add `EncryptedFileStore::touch(group_id)` for key refresh metadata tracking
- **Files owned (agent may only touch these):**
  - `crates/mpc-wallet-core/src/key_store/encrypted.rs`
- **Acceptance Criteria:**
  - [ ] `EncryptedFileStore` has a new concrete method `pub async fn touch(&self, group_id: &KeyGroupId) -> Result<(), CoreError>`
  - [ ] `touch()` reads the existing `metadata.json` for the group, updates a `last_refreshed` field (unix timestamp as `u64`, obtained via `std::time::SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs()`), and writes it back atomically (overwrite)
  - [ ] `KeyMetadata` in `key_store/types.rs` gains a new field `last_refreshed: Option<u64>` with `#[serde(default)]` so existing JSON files (without the field) continue to deserialize correctly — **NOTE: `types.rs` is owned by R0; R1 must NOT modify it. Instead R1 should write the `last_refreshed` value as a standalone JSON key alongside the `KeyMetadata` JSON, by reading the raw JSON as `serde_json::Value`, inserting the key, and writing back. This avoids touching R0-owned types.**
  - [ ] Alternative (preferred since it avoids R0 files): `touch()` writes a separate file `touch.json` containing `{"last_refreshed": <unix_u64>}` in the group directory — keeps all R0 types untouched
  - [ ] A unit test `test_touch_updates_timestamp` verifies: create a group (via `save()`), call `touch()`, read `touch.json`, verify `last_refreshed` is a non-zero u64 and is >= the `created_at` timestamp
  - [ ] No key material is read or decrypted during `touch()` — only metadata files are accessed
  - [ ] `cargo test -p mpc-wallet-core` passes
- **Dependencies:** None — `encrypted.rs` is R1's file; no trait change required
- **Complexity:** S

#### Security Checklist for R6
- [ ] `touch()` does **not** call `decrypt()` or access the `.enc` share file — verified by code inspection
- [ ] No key material (share bytes, password, derived key) is present in any variable created during `touch()`
- [ ] The timestamp written is obtained from `std::time::SystemTime` (not user-supplied input) — no injection risk
- [ ] `touch.json` does not contain any sensitive fields — only the `last_refreshed` timestamp
- [ ] `cargo audit` clean — no new dependencies added

---

### Task Spec: T-05
- **Agent:** R0
- **Branch:** `agent/r0-interface`
- **Epic:** Epic H (Key Lifecycle)
- **Title:** Add `freeze` / `unfreeze` to `KeyStore` trait + `CoreError::KeyFrozen`
- **Files owned (agent may only touch these):**
  - `crates/mpc-wallet-core/src/key_store/mod.rs`
  - `crates/mpc-wallet-core/src/error.rs`
  - `crates/mpc-wallet-core/src/key_store/encrypted.rs`
- **Acceptance Criteria:**
  - [ ] `KeyStore` trait in `key_store/mod.rs` has two new async methods:
    ```rust
    async fn freeze(&self, group_id: &KeyGroupId) -> Result<(), CoreError>;
    async fn unfreeze(&self, group_id: &KeyGroupId) -> Result<(), CoreError>;
    ```
  - [ ] `CoreError::KeyFrozen(String)` variant added to `error.rs` with `#[error("key frozen: {0}")]`
  - [ ] `EncryptedFileStore` in `key_store/encrypted.rs` gets stub implementations: both `freeze` and `unfreeze` return `Ok(())` (no-op stubs; full implementation is deferred to a later sprint)
  - [ ] `cargo check --workspace` passes — all crates compile
  - [ ] `cargo test -p mpc-wallet-core` passes — no existing tests broken
- **Dependencies:** None — highest-priority interface change, must complete Day 1–2 to unblock dependent tasks
- **Complexity:** S

#### Security Checklist for R6
- [ ] Trait method signatures use `&self` (not `&mut self`) — consistent with the existing `KeyStore` API (`save`, `load`, `list`, `delete` all use `&self`)
- [ ] `CoreError::KeyFrozen(String)` error message does NOT include key share bytes, derived keys, or password material — only the `group_id` string or a safe descriptive message
- [ ] No implementation logic beyond `Ok(())` stubs in the trait-level default impls (if any) — logic belongs in `EncryptedFileStore`, not in trait defaults
- [ ] The `KeyFrozen` variant is additive — no existing `CoreError` variants are renamed, removed, or reordered (non-breaking change)
- [ ] `cargo audit` clean — no new dependencies added

---

### Task Spec: T-06
- **Agent:** R3d
- **Branch:** `agent/r3d-sui-followup`
- **Epic:** Epic J (Production Hardening)
- **Title:** Sui — add `build_transaction_with_sender` helper and sender address validation
- **Files owned (agent may only touch these):**
  - `crates/mpc-wallet-chains/src/sui/tx.rs`
  - `crates/mpc-wallet-chains/src/sui/mod.rs`
- **Acceptance Criteria:**
  - [ ] `SuiProvider` gains a new `pub fn build_transaction_with_sender<'a>(&'a self, params: TransactionParams, sender: &str) -> impl Future<Output = Result<UnsignedTransaction, CoreError>> + 'a` method in `mod.rs` that takes the sender address explicitly (bypassing `extra["sender"]` lookup)
  - [ ] The `sender` parameter is validated: must start with `"0x"` and the hex portion (after `0x`) must decode to exactly 32 bytes (64 hex chars). Return `CoreError::InvalidInput` if validation fails.
  - [ ] The existing `build_transaction` (which reads `extra["sender"]`) continues to work unchanged — no regression
  - [ ] A unit test `test_build_transaction_with_sender_valid` verifies a valid 0x-prefixed 32-byte hex sender succeeds and the resulting `sign_payload` is 32 bytes (Blake2b-256)
  - [ ] A unit test `test_build_transaction_with_sender_rejects_invalid` verifies that a sender missing `"0x"` prefix returns `Err(CoreError::InvalidInput(...))`
  - [ ] A unit test `test_build_transaction_with_sender_rejects_wrong_length` verifies that a sender with `"0x"` prefix but incorrect hex length (not 64 hex chars) returns `Err(CoreError::InvalidInput(...))`
  - [ ] `cargo test -p mpc-wallet-chains` passes
- **Dependencies:** None — `sui/tx.rs` and `sui/mod.rs` are R3d's files; no R0-owned files touched
- **Complexity:** S

#### Security Checklist for R6
- [ ] Sender address validation rejects: missing `0x` prefix, hex decode failure, decoded length ≠ 32 bytes — all three cases tested
- [ ] Validation occurs **before** any transaction data is constructed — fail-fast, no partial state built with invalid sender
- [ ] The `extra["sender"]` path in the existing `build_transaction` is unchanged — no regression in the existing API
- [ ] No secret material (private key, share bytes) present in error messages or returned values
- [ ] `cargo audit` clean — no new dependencies added

---

### Task Spec: T-07
- **Agent:** R3c
- **Branch:** `agent/r3c-sol`
- **Epic:** Epic J (Production Hardening)
- **Title:** Solana — binary message round-trip validation test + fix `tx_hash` to full base58 signature
- **Files owned (agent may only touch these):**
  - `crates/mpc-wallet-chains/tests/chain_integration.rs`
  - `crates/mpc-wallet-chains/src/solana/tx.rs`
- **Source change (tx.rs — one line fix):**
  - [ ] Line 183: replace `let tx_hash = hex::encode(&signature[..8]);` with `let tx_hash = bs58::encode(signature).into_string();` — fixes SEC-010 (truncated tx hash)
- **New tests to add in `chain_integration.rs`:**
  - [ ] `test_solana_message_structure_num_required_sigs`: build a transaction, assert `sign_payload[0] == 1` (num_required_sigs header byte)
  - [ ] `test_solana_message_structure_account_keys_offset`: build a transaction, assert that bytes at offset 4 (after header 3 bytes + compact-u16(3)=1 byte) match the `from` public key bytes (32 bytes starting at index 4)
  - [ ] `test_solana_message_structure_three_accounts_present`: build a transaction, assert sign_payload length >= 3 (header) + 1 (compact-u16) + 96 (3×32 account keys) + 32 (blockhash) = 132 bytes minimum
  - [ ] `test_solana_encode_compact_u16_boundary_values`: test the compact-u16 encoding for values 0, 1, 127, 128, 16383 — assert correct byte sequences (`[0]`, `[1]`, `[0x7f]`, `[0x80, 0x01]`, `[0xff, 0x7f]`)
  - [ ] `test_solana_tx_hash_is_base58_full_signature`: build+finalize a transaction with a known 64-byte signature, assert `tx_hash` decodes from base58 to exactly 64 bytes matching the signature
  - [ ] `test_solana_zero_lamports_transaction`: build a transaction with `value: "0"`, assert it succeeds (zero lamports is valid)
  - [ ] `test_solana_same_from_to_address`: build a transaction where from == to (same 32-byte address), assert it succeeds (network-level restriction, not SDK-level)
- **Acceptance Criteria:**
  - [ ] All 7 new tests pass
  - [ ] `finalize_solana_transaction` `tx_hash` is now `bs58::encode(signature).into_string()` (full 64-byte signature base58-encoded)
  - [ ] All pre-existing Solana tests in `chain_integration.rs` still pass
  - [ ] `cargo test -p mpc-wallet-chains` passes
- **Dependencies:** None — `chain_integration.rs` and `solana/tx.rs` are in R3c's scope
- **Complexity:** S

#### Security Checklist for R6
- [ ] `tx_hash` in `SignedTransaction` is the **full** base58-encoded 64-byte signature — NOT the previous truncated 8-byte hex. Verify the fix resolves SEC-010: `hex::encode(&signature[..8])` must no longer appear anywhere in `tx.rs`
- [ ] `encode_compact_u16` boundary test covers value 128 (two-byte encoding threshold) — verifies no off-by-one that could corrupt message structure
- [ ] Zero-lamports test: verify no integer underflow or panic on `u64` value of 0
- [ ] Same from/to test: verify no panic or assertion failure when sender == recipient (array aliasing non-issue in Rust, but must confirm no validation incorrectly rejects it)
- [ ] No secret material present in `SignedTransaction` output — `tx_hash` is the public signature, `raw_tx` is the serialized transaction; no private key bytes
- [ ] `cargo audit` clean — no new dependencies added (bs58 is already in workspace)

---

## Blocked Tasks

| Task | Blocker | Owner | Resolution |
|------|---------|-------|------------|
| (none) | — | — | All 5 tasks are independent and can start in parallel. T-05 (R0) should be prioritized to unblock any future freeze/unfreeze implementation work. |

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

- **T-01 and T-02 both assigned to R1** on the same branch `agent/r1-zeroize`. R1 should do T-01 first (feature flag), then T-02 (touch method), then commit each separately per checkpoint protocol.
- **T-05 (R0) has no blockers** and should be completed first — it unblocks any future freeze/unfreeze work and is the smallest task in the sprint.
- **T-06 (R3d) and T-07 (R3c)** can work in parallel — no shared files.
- **R6 gate:** R6 must issue APPROVED verdict for each task branch before it can merge to main.
- **No branch merges without R6 APPROVED** — enforced per the Sprint Gate Model in AGENTS.md.
- **No new crate dependencies** are required for any Sprint 1 task. `bs58` is already in the workspace (used in `solana/tx.rs`).

---

## Execution Order

All 5 tasks are independent and can run in parallel. Recommended priority:

```
Day 1:  R0 → T-05 (small, unblocks future work)
Day 1:  R1 → T-01 (feature flag — preparatory for Sprint 2 real GG20)
Day 1:  R3d → T-06 (Sui sender validation helper)
Day 1:  R3c → T-07 (Solana round-trip test + tx_hash fix)

Day 2:  R1 → T-02 (touch method, after T-01 lands on same branch)

Day 3+: R6 audits each branch as agents report complete
```

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
