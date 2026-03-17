# Chain Integration Proposal & Checklist

> Use this document when adding a new blockchain to Vaultex MPC Wallet.
> Every item must be completed and verified before merging to `main`.

---

## Pre-Implementation Research

Before writing any code, complete this research:

- [ ] **Official documentation** — Read the chain's official developer docs for address format, transaction structure, signing algorithm, and RPC API
- [ ] **Signing curve** — Identify which curve the chain uses:
  - `secp256k1` → GG20 ECDSA (existing)
  - `Ed25519` → FROST Ed25519 (existing)
  - `secp256k1 Schnorr` → FROST Schnorr (existing)
  - `Sr25519` → Not yet available (Substrate native)
  - `STARK curve` → Not yet available
  - `BLS12-381` → Not yet available
  - Other → Requires new MPC protocol implementation
- [ ] **Address format** — Document the exact derivation algorithm:
  - Hash function (SHA-256, Keccak-256, Blake2b, SHA3-256, etc.)
  - Encoding (hex, Base58, Base58Check, bech32, SS58, Base64, etc.)
  - Prefix/version bytes
  - Checksum algorithm
- [ ] **Transaction format** — Document the serialization:
  - Encoding (RLP, BCS, SCALE, Protobuf, TL-B, Amino, etc.)
  - Required fields (sender, recipient, amount, nonce, gas, etc.)
  - Sign payload computation (what exactly gets signed)
- [ ] **RPC API** — Document the broadcast method:
  - Protocol (JSON-RPC, REST, gRPC, etc.)
  - Endpoint URL pattern
  - Request/response format
  - Which RPC providers support this chain (Dwellir, Alchemy, Infura, etc.)
- [ ] **Testnet availability** — Is there a public testnet for integration testing?

---

## Implementation Checklist

### 1. Chain Enum (`provider.rs`)

- [ ] Add variant to `Chain` enum with appropriate category comment
- [ ] Add `Display` impl (lowercase chain name)
- [ ] Add `FromStr` impl with aliases (e.g., `"cosmos" | "atom"`)
- [ ] Chain variant derives: `Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize`

### 2. Module Structure (`src/{chain_name}/`)

Create the following files:

```
src/{chain_name}/
  mod.rs          ← Provider struct + ChainProvider impl
  address.rs      ← Address derivation + validation
  tx.rs           ← Transaction building + finalization
```

### 3. Address Derivation (`address.rs`)

- [ ] `derive_{chain}_address(pubkey: &GroupPublicKey) -> Result<String, CoreError>`
- [ ] Use the **correct hash algorithm** per chain specification
- [ ] Use the **correct encoding** (Base58Check, bech32, hex, SS58, etc.)
- [ ] Use the **correct prefix/version bytes**
- [ ] Use **real crypto libraries** — no simulated hashes (e.g., use `ripemd` not SHA-256 truncation)
- [ ] Reject unsupported key types (e.g., Ed25519 key for secp256k1 chain)
- [ ] `validate_{chain}_address(addr: &str) -> Result<(), CoreError>` — validate format + checksum
- [ ] Verify against known test vectors from official docs

### 4. Transaction Building (`tx.rs`)

- [ ] Define chain-specific transaction struct(s) with `Serialize, Deserialize`
- [ ] `build_{chain}_transaction(params) -> Result<UnsignedTransaction, CoreError>`
  - [ ] Parse required fields from `params.extra` (nonce, gas, etc.)
  - [ ] Use **correct serialization format** (BCS, SCALE, Protobuf, RLP, etc.)
  - [ ] Compute **correct sign payload** (the exact bytes that get signed)
  - [ ] Sign payload must be 32 bytes (hash output)
  - [ ] Store `serialized_data || pubkey` in `tx_data` for finalization
- [ ] `finalize_{chain}_transaction(unsigned, sig) -> Result<SignedTransaction, CoreError>`
  - [ ] Accept correct `MpcSignature` variant (Ecdsa / EdDsa / Schnorr)
  - [ ] Reject wrong signature type with clear error message
  - [ ] Build correct wire format: `tx_data + signature` per chain spec
  - [ ] Set `tx_hash` to hex-encoded sign payload hash

### 5. Provider (`mod.rs`)

- [ ] `{Chain}Provider` struct with optional `GroupPublicKey` + `SimulationConfig`
- [ ] Constructors: `new()`, `with_pubkey()`, `with_simulation()`
- [ ] `impl ChainProvider` with all required methods:
  - [ ] `chain()` — returns correct `Chain` variant
  - [ ] `derive_address()` — delegates to `address.rs`
  - [ ] `build_transaction()` — delegates to `tx.rs`
  - [ ] `finalize_transaction()` — delegates to `tx.rs`
  - [ ] `broadcast()` — correct RPC method + request format + error handling
  - [ ] `simulate_transaction()` — chain-specific risk checks (value, gas, fees)

### 6. Chain Registry (`registry.rs`)

- [ ] Add `Chain::NewChain => Box::new(NewChainProvider::new())` in `provider()` match
- [ ] Add `Chain::NewChain` to `supported_chains()` list
- [ ] Update `test_supported_chains_count` assertion

### 7. RPC Provider (`rpc/providers/dwellir.rs` + others)

- [ ] Add chain slug to `DwellirProvider::chain_slug()` (mainnet + testnet if applicable)
- [ ] Add chain to `DwellirProvider::supported_chains()` list
- [ ] If Alchemy/Infura support the chain, add to their `chain_slug()` + `supported_chains()` too

### 8. Lib Registration (`lib.rs`)

- [ ] Add `pub mod {chain_name};` in alphabetical order

### 9. Integration Tests (`tests/chain_{name}_integration.rs`)

Every chain MUST have the following tests:

```
tests/chain_{name}_integration.rs
```

**Required tests (minimum 8):**

- [ ] `test_{chain}_address_derivation` — correct format, prefix, length
- [ ] `test_{chain}_rejects_wrong_key_type` — Ed25519 for secp256k1 chain or vice versa
- [ ] `test_{chain}_sign_payload_32_bytes` — build_transaction produces 32-byte sign payload
- [ ] `test_{chain}_finalize_correct_format` — raw_tx has correct wire format
- [ ] `test_{chain}_rejects_wrong_signature_type` — ECDSA for EdDsa chain or vice versa
- [ ] `test_{chain}_provider_default_works` — `new()` constructor + derive_address
- [ ] `test_{chain}_broadcast_invalid_url` — returns error on unreachable URL
- [ ] `test_registry_creates_{chain}` — ChainRegistry creates provider correctly

**Recommended additional tests:**

- [ ] `test_{chain}_address_validation_valid` — valid address passes validation
- [ ] `test_{chain}_address_validation_invalid` — bad prefix/length/checksum rejected
- [ ] `test_{chain}_simulation_high_value` — high value flagged in simulation
- [ ] `test_{chain}_different_address_from_other_chains` — same key, different address vs similar chains

### 10. README Updates (ALL languages)

- [ ] `README.md` — Add chain to appropriate table with Chain ID / address format / signing / RPC provider checkmarks
- [ ] `README.zh-CN.md` — Same changes, translated to Chinese
- [ ] Update chain count in header, Features table, and Metrics section
- [ ] Update `CHAIN_ROADMAP.md` if the chain was listed there

---

## Verification Checklist (before merge)

```bash
# All must pass:
cargo test --workspace                                    # All tests green
cargo clippy --workspace --all-targets -- -D warnings     # Zero warnings
cargo fmt --check                                         # Clean formatting
cargo audit                                               # No known vulnerabilities
```

- [ ] `cargo test --workspace` — ALL pass
- [ ] `cargo clippy --workspace --all-targets -- -D warnings` — clean
- [ ] `cargo fmt --check` — clean
- [ ] `supported_chains().len()` matches expected count
- [ ] New chain's integration tests all pass
- [ ] Address derivation verified against official test vectors or explorer
- [ ] README EN + zh-CN both updated with same content
- [ ] Committed on `dev` branch, PR to `main`

---

## Quick Reference: Existing Patterns to Follow

| Chain Type | Reference Module | Key Differences |
|------------|-----------------|-----------------|
| EVM (new L2) | `src/evm/` | Just add chain_id to `EvmProvider::new()` match |
| UTXO | `src/utxo/` + `src/bitcoin/` | Different version bytes, same tx format |
| Move VM | `src/aptos/` | BCS encoding, SHA3-256, Ed25519 |
| Cosmos/IBC | `src/cosmos/` | Different bech32 HRP + denom |
| Substrate | `src/substrate/` | Different SS58 prefix |
| Ed25519 chain | `src/solana/` or `src/sui/` | Chain-specific tx format |
| secp256k1 chain | `src/evm/` or `src/tron/` | Chain-specific address + tx format |

---

## Effort Estimation Guide

| Scenario | Effort | Example |
|----------|--------|---------|
| New EVM L2 (just chain_id) | **~30 min** | Add variant + chain_id + RPC slug |
| New Cosmos chain (same SDK) | **~1 hour** | Add bech32 HRP + denom config |
| New Substrate parachain | **~1 hour** | Add SS58 prefix config |
| New chain, existing signing | **~1 day** | TON, TRON, Aptos pattern |
| New chain, new signing protocol | **~1-4 weeks** | Sr25519, STARK, BLS |
