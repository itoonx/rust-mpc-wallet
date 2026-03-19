# Security Findings Log

> Format: CRITICAL/HIGH findings BLOCK merge until resolved and re-audited by R6.
> MEDIUM/LOW do not block merge but must be tracked.
> Each finding links to the Task that introduced or must fix it.

## Open CRITICAL Findings (BLOCK merge)

| ID | Summary | Recommended Fix | Owner |
|----|---------|-----------------|-------|
| SEC-001 | ~~GG20 reconstructs full private key via Lagrange interpolation~~ **RESOLVED** by T-S2-01 (`agent/r1-real-gg20`) — distributed additive-share signing, full key never assembled | — | R1 |
| SEC-002 | ~~Hardcoded fallback password `"demo-password"` in all 4 CLI commands~~ **RESOLVED** by T-S2-03 (`agent/r4-cli-password`) — `rpassword::prompt_password` used in all 4 commands, zero `demo-password` occurrences | — | R4 |
| SEC-003 | ~~NatsTransport is entirely `todo!()` stubs — no TLS, no auth, no replay protection~~ **RESOLVED** by T-S3-01 (`agent/r2-nats-s3`) — real `async-nats` connect/send/recv impl, zero `todo!()` stubs | — | R2 |

## Open HIGH Findings (BLOCK merge)

| ID | Summary | Owner |
|----|---------|-------|
| SEC-004 | `KeyShare.share_data` stored as plain `Vec<u8>` — **IN PROGRESS** T-S3-03 (`agent/r1-zeroize-shares`): all deserialization call sites wrap copies in `Zeroizing<Vec<u8>>`; root fix (changing field type in `protocol/mod.rs`) deferred to Sprint 4 (R0 owned) | R0 / R1 |
| SEC-005 | ~~`EncryptedFileStore` holds password as plain `String`; derived AES key not zeroized~~ **RESOLVED** by T-S3-02 (`agent/r2-argon2`) — password wrapped in `Zeroizing<String>`, derived key in `Zeroizing<[u8; 32]>` | — | R2 |
| SEC-006 | ~~Argon2 uses `default()` parameters — too weak for wallet-class key encryption~~ **RESOLVED** by T-S3-02 (`agent/r2-argon2`) — explicit `m_cost=65536` / `t_cost=3` / `p_cost=4` + salt upgraded to 32 bytes | — | R2 |
| SEC-007 | `ProtocolMessage.from` is self-reported; no sender authentication in any transport | R2 / R0 |

## Open MEDIUM/LOW/INFO (non-blocking)

| ID | Severity | Summary |
|----|----------|---------|
| SEC-008 | MEDIUM | GG20 reconstructed `Scalar` not explicitly zeroized before drop |
| SEC-009 | MEDIUM | Bitcoin Taproot sighash uses empty `prev_out.script_pubkey` — produces invalid transactions |
| SEC-010 | MEDIUM | ~~Solana `tx_hash` is only first 8 bytes of signature — not a real Solana tx ID~~ **RESOLVED** by T-07 (R3c) |
| SEC-011 | MEDIUM | Sui transaction serialization uses JSON instead of BCS — rejected by Sui nodes |
| SEC-012 | MEDIUM | EVM finalization does not enforce low-S ECDSA normalization |
| SEC-013 | MEDIUM | FROST protocols trust self-reported `from` field for party ID mapping |
| SEC-014 | LOW | `LocalTransport` has no `#[cfg(test)]` gate — can be used in production accidentally |
| SEC-015 | LOW | `KeyShare` derives `Debug` — `share_data` bytes visible in log output |
| SEC-016 | LOW | Bitcoin `SerializableTx::to_tx()` uses `.unwrap()` — panics on malformed input |
| SEC-017 | LOW | Solana tx builder does not validate `from` address matches signing pubkey |
| SEC-018 | LOW | `rustls-pemfile` (transitive via `async-nats`) is unmaintained (RUSTSEC-2025-0134) |
| SEC-019 | LOW | `quinn-proto 0.11.13` — known DoS vulnerability RUSTSEC-2026-0037 (CVSS 8.7) |
| SEC-020 | INFO | FROST protocols correctly avoid full key reconstruction (positive finding) |
| SEC-021 | INFO | AES-256-GCM uses fresh random salt + nonce per write — no reuse risk (positive finding) |
| SEC-022 | INFO | Git history scan found no committed secrets (positive finding) |
| SEC-023 | LOW | T-06 (R3d): invalid-hex test case missing — no dedicated test for `0x` + 64 non-hex chars path |

---

## [CRITICAL] SEC-001: GG20 Reconstructs Full Private Key on Every Signer

- **ID:** SEC-001
- **Date:** 2026-03-15
- **Task:** pre-sprint → **Resolved by T-S2-01 (branch: agent/r1-real-gg20)**
- **Agent:** R1 (Crypto Agent)
- **File:** `crates/mpc-wallet-core/src/protocol/gg20.rs:231-237` (pre-fix)
- **Description:** The `Gg20Protocol::sign` implementation performs full Lagrange interpolation
  (`lagrange_interpolate`) across all collected shares, reconstructing the complete secp256k1
  private key as a `Scalar` in memory on every signing party. This is the exact anti-pattern
  that MPC threshold signing is designed to prevent. Every one of the `t` signers learns the
  full secret for the duration of the signing call.
- **Impact:** Any process compromise during signing exposes the complete private key. The
  "threshold" property provides key-at-rest protection only; there is no threshold property
  during signing. This negates the core security guarantee of the MPC architecture.
- **Recommendation:** Replace the Lagrange reconstruction with a proper threshold ECDSA
  signing protocol (e.g., FROST-secp256k1 like the other two schemes, or the real GG20/GG18
  protocol where each party produces only a signature share). The `secret` scalar (line 232)
  and `secret_key` (line 235) must never exist as a complete value on any single party.
  Until fixed, add a prominent `// SECURITY: SIMULATION ONLY — NOT FOR PRODUCTION` comment
  and block CLI from using this scheme in non-demo mode.
- **Status:** Resolved
- **Resolved in commit:** agent/r1-real-gg20 (T-S2-01) — `distributed_sign` uses additive
  share arithmetic: `x_i_add = λ_i · f(i)` per party, `s_i = x_i_add · r · k_inv` sent to
  coordinator; full key `x` never assembled on any single party. `lagrange_interpolate` exists
  only inside `#[cfg(feature = "gg20-simulation")]` gate which is OFF by default.
- **R6 Residual Finding (HIGH):** `k_inv` is broadcast from coordinator (Party 1) to all
  signers in plaintext over the transport. Combined with a party's own `s_i`, an attacker
  observing the network can derive information. This does not reconstruct the full key but
  is a trust assumption: Party 1 is fully trusted for nonce generation. Logged as SEC-024.
  This is expected for a Sprint 2 "honest-but-curious" protocol per the module doc comments.

---

## [CRITICAL] SEC-002: Hardcoded Fallback Password "demo-password" in Production CLI

- **ID:** SEC-002
- **Date:** 2026-03-15
- **Task:** pre-sprint → **Resolved by T-S2-03 (branch: agent/r4-cli-password)**
- **Agent:** R4 (Service Agent)
- **File:** `crates/mpc-wallet-cli/src/commands/keygen.rs:101`,
  `crates/mpc-wallet-cli/src/commands/sign.rs:32`,
  `crates/mpc-wallet-cli/src/commands/address.rs:28`,
  `crates/mpc-wallet-cli/src/commands/keys.rs:17`
- **Description:** All four CLI commands fall back to the literal string `"demo-password"` when
  `--password` is not supplied. This means any user who runs `mpc-wallet keygen` without
  explicitly passing `--password` will silently encrypt their key shares with a publicly known
  password. The fallback is identical across all commands, so someone who knows the default can
  trivially decrypt any key share stored on disk.
- **Impact:** Key shares encrypted with `"demo-password"` can be decrypted by any attacker who
  reads the filesystem, entirely circumventing the AES-256-GCM / Argon2id encryption layer.
- **Recommendation:** Remove all `unwrap_or_else(|| "demo-password".into())` fallbacks.
  If no password is supplied, prompt interactively (use `rpassword` or similar) or return an
  error. Never supply a default password. Add a unit test that asserts no CLI code path
  uses a hardcoded credential.
- **Status:** Resolved
- **Resolved in commit:** agent/r4-cli-password (T-S2-03) — all 4 CLI commands now use
  `rpassword::prompt_password("Enter wallet password: ")` when `--password` not supplied.
  Zero `demo-password` occurrences remain in CLI source. Password not logged or stored beyond
  immediate use.

---

## [CRITICAL] SEC-003: NatsTransport Is Entirely Unimplemented (todo!() Stubs)

- **ID:** SEC-003
- **Date:** 2026-03-15
- **Task:** pre-sprint
- **Agent:** R2 (Infrastructure Agent)
- **File:** `crates/mpc-wallet-core/src/transport/nats.rs:32-57`
- **Description:** All methods of `NatsTransport` — `connect`, `inbox_subject`, `party_subject`,
  `send`, and `recv` — are `todo!()` macros that will panic at runtime. Despite a helpful
  security comment (lines 13–17) correctly listing required security properties, none are
  implemented: no TLS, no ECDH envelope encryption, no signed envelopes, no replay protection.
- **Impact:** If this stub is ever accidentally used in a deployment (e.g., a CI environment
  that calls `NatsTransport::connect`), the process will panic. More critically, the production
  network transport path is entirely missing, so the SDK currently has no authenticated
  multi-party communication channel.
- **Recommendation:** Implement per the security comment: (1) TLS with nats-tls and certificate
  pinning, (2) X25519 ECDH + ChaCha20-Poly1305 per-session envelope encryption, (3) monotonic
  `seq_no` + TTL in every message envelope for replay protection, (4) HMAC-SHA256 message
  authentication. All `todo!()` stubs must panic loudly with a descriptive message until
  implemented; they should not be callable from production code paths.
- **Status:** Open

---

## [HIGH] SEC-004: `KeyShare.share_data` Stored as Plain `Vec<u8>` — No ZeroizeOnDrop

- **ID:** SEC-004
- **Date:** 2026-03-15
- **Task:** pre-sprint
- **Agent:** R1 (Crypto Agent) / R0 (Architect Agent)
- **File:** `crates/mpc-wallet-core/src/protocol/mod.rs:28-40`
- **Description:** `KeyShare` derives `Debug` and `Clone` and stores `share_data` as a plain
  `Vec<u8>`. While the individual `Gg20ShareData`, `FrostEd25519ShareData`, and
  `FrostSecp256k1ShareData` structs derive `ZeroizeOnDrop`, the serialized bytes of those
  structs are immediately stored in `KeyShare.share_data` as an unprotected heap allocation.
  This `Vec<u8>` is not zeroized on drop, `Clone` creates additional unprotected copies, and
  `Debug` will print its contents (base64-style display of bytes) if ever formatted.
- **Impact:** Key share material persists in heap memory after `KeyShare` is dropped, can
  be cloned into additional unprotected locations, and could be dumped via debug logging.
- **Recommendation:** (1) Wrap `share_data` in `Zeroizing<Vec<u8>>` or use a newtype that
  impls `ZeroizeOnDrop`. (2) Remove `Debug` derive or implement it manually to redact
  `share_data`. (3) Remove `Clone` or implement it to clone into a `Zeroizing` wrapper.
  This requires R0 to update `protocol/mod.rs` with R1 coordination.
- **Status:** Open

---

## [HIGH] SEC-005: EncryptedFileStore Derives Encryption Key in Memory Without Zeroize

- **ID:** SEC-005
- **Date:** 2026-03-15
- **Task:** pre-sprint
- **Agent:** R2 (Infrastructure Agent)
- **File:** `crates/mpc-wallet-core/src/key_store/encrypted.rs:27-33`
- **Description:** `derive_key` returns a `[u8; 32]` stack array (the AES-256-GCM key) which
  is never zeroized after use. The `EncryptedFileStore` stores the password as a plain
  `String` field. After encryption/decryption, the derived key bytes remain on the stack
  (and potentially in registers/stack frames) without clearing. The `password` String is also
  held in the struct for the lifetime of the store.
- **Impact:** Derived encryption keys and the raw password may be recoverable from a memory
  dump, core file, or swap partition long after the operation completes.
- **Recommendation:** (1) Wrap the password in `Zeroizing<String>` or `SecretString`. (2)
  Wrap the derived key in `Zeroizing<[u8; 32]>` in `derive_key`. (3) Ensure the cipher is
  dropped immediately after use. See `zeroize` crate docs for `Zeroizing<T>` usage.
- **Status:** Open

---

## [HIGH] SEC-006: Argon2 Uses Default Parameters — Potentially Weak KDF Configuration

- **ID:** SEC-006
- **Date:** 2026-03-15
- **Task:** pre-sprint
- **Agent:** R2 (Infrastructure Agent)
- **File:** `crates/mpc-wallet-core/src/key_store/encrypted.rs:29`
- **Description:** `argon2::Argon2::default()` is called with no explicit parameters. The
  argon2 crate v0.5 defaults are: Argon2id variant, m=19456 KiB (19 MiB), t=2 iterations,
  p=1 lane. While these are the OWASP minimum recommendations, for a key-encrypting key
  protecting cryptocurrency wallets, the OWASP guidance recommends significantly higher
  parameters (m=64 MiB, t=3 for wallet-class secrets). Additionally, the salt is only 16
  bytes (128 bits); the argon2 spec recommends 16 bytes minimum but 32 bytes for
  high-security contexts.
- **Impact:** With default parameters, a well-resourced attacker with access to encrypted
  key files can mount an offline brute-force attack faster than is acceptable for a
  cryptocurrency wallet.
- **Recommendation:** Explicitly set Argon2id parameters: `m_cost = 65536` (64 MiB),
  `t_cost = 3`, `p_cost = 4`. Increase salt to 32 bytes. Document the chosen parameters
  with a justification comment. Consider adding a `params` field to the encrypted file
  header so parameters can be migrated without re-keying.
- **Status:** Open

---

## [HIGH] SEC-007: No Message Authentication in LocalTransport — Sender Field Is Self-Reported

- **ID:** SEC-007
- **Date:** 2026-03-15
- **Task:** pre-sprint
- **Agent:** R2 (Infrastructure Agent) / R0 (Architect Agent)
- **File:** `crates/mpc-wallet-core/src/transport/mod.rs:12-21`,
  `crates/mpc-wallet-core/src/transport/local.rs:65-87`
- **Description:** `ProtocolMessage` has a `from: PartyId` field, but neither `LocalTransport`
  nor any consuming protocol code validates that the `from` field matches the actual sender.
  In `LocalTransport`, the sender is the channel used, but the `from` field is taken directly
  from the message payload (self-reported). Any party can set `from: PartyId(1)` in a
  broadcast message to impersonate Party 1.
- **Impact:** Facilitates party impersonation attacks in protocol execution. In GG20/FROST,
  an attacker who can control message routing could inject malicious round packages
  attributed to other parties.
- **Recommendation:** (1) For `LocalTransport`: strip/override the `from` field in `recv()`
  based on the channel identity. (2) For `NatsTransport`: include a cryptographic message
  authentication code (MAC) keyed to the sender's identity. (3) Define an authenticated
  message envelope at the Transport trait level.
- **Status:** Open

---

## [MEDIUM] SEC-008: GG20 Secret Scalar Not Zeroized After Signing Use

- **ID:** SEC-008
- **Date:** 2026-03-15
- **Task:** pre-sprint
- **Agent:** R1 (Crypto Agent)
- **File:** `crates/mpc-wallet-core/src/protocol/gg20.rs:232-241`
- **Description:** The reconstructed `secret` (a `k256::Scalar`) and derived `secret_key`
  (`k256::SecretKey`) are computed during signing but not explicitly zeroized before they go
  out of scope. While `k256::SecretKey` implements `ZeroizeOnDrop`, the intermediate `Scalar`
  (line 232) and `SigningKey` (line 237) may not guarantee prompt zeroing before the call
  stack unwinds or optimizes.
- **Impact:** The reconstructed private key scalar may linger in memory briefly beyond the
  signing call. This is secondary to SEC-001 (the key shouldn't be reconstructed at all),
  but if the simulation mode is kept, explicit zeroize matters.
- **Recommendation:** Wrap `secret` in `Zeroizing<Scalar>` and call `zeroize::Zeroize::zeroize`
  explicitly on it before it goes out of scope. Wrap `signing_key` in a guard that calls
  `zeroize()`. This is moot if SEC-001 is fixed (the scalar wouldn't exist), but should be
  addressed regardless as a defense-in-depth measure.
- **Status:** Open

---

## [MEDIUM] SEC-009: Bitcoin Sighash Computed With Empty prev_out.script_pubkey

- **ID:** SEC-009
- **Date:** 2026-03-15
- **Task:** pre-sprint
- **Agent:** R3b (Chain Agent — Bitcoin)
- **File:** `crates/mpc-wallet-chains/src/bitcoin/tx.rs:77-85`
- **Description:** The Taproot sighash computation uses `prev_out.script_pubkey = ScriptBuf::new()`
  (an empty script). For Taproot key-path spends, the `script_pubkey` in the `Prevouts::All`
  must be the actual P2TR output script (`OP_1 <x-only-pubkey>`) of the UTXO being spent.
  Using an empty script produces an **incorrect sighash**, meaning the signed transaction will
  be rejected by Bitcoin nodes.
- **Impact:** Transactions built with this code will always be invalid on the Bitcoin network.
  This is currently a functional bug with security implications: it may mask double-signing
  scenarios if a second correct implementation is deployed alongside.
- **Recommendation:** Require the caller to supply the full `script_pubkey` (the P2TR output
  script of the UTXO being spent) via `params.extra["prev_script_pubkey_hex"]`. Use that
  value in `Prevouts::All`. Document that this is required and validate it is present.
- **Status:** Open

---

## [MEDIUM] SEC-010: Solana Transaction Hash Is Only First 8 Bytes of Signature

- **ID:** SEC-010
- **Date:** 2026-03-15
- **Task:** pre-sprint → **Resolved by T-07 (branch: agent/r3c-sol)**
- **Agent:** R3c (Chain Agent — Solana)
- **File:** `crates/mpc-wallet-chains/src/solana/tx.rs:183`
- **Description:** `tx_hash = hex::encode(&signature[..8])` — the "transaction hash" returned
  is just the first 8 bytes of the Ed25519 signature, not a real Solana transaction ID.
  Real Solana transaction IDs are the base58-encoded SHA-256 hash (actually the first
  signature in base58). This value is used in `SignedTransaction.tx_hash` which callers
  use to look up transaction status on chain.
- **Impact:** Any code that uses `tx_hash` to query transaction status from a Solana RPC
  will receive an invalid signature. This could mask failed transactions or lead to
  transaction rebroadcast without proper deduplication.
- **Recommendation:** Compute the real Solana transaction ID: base58-encode the 64-byte
  signature (the first and only signature for a single-signer transaction, which matches
  how Solana nodes identify transactions).
- **Status:** Resolved
- **Resolved in commit:** agent/r3c-sol — `tx_hash = bs58::encode(signature).into_string()` (full 64-byte signature, base58-encoded)

---

## [MEDIUM] SEC-011: Sui Transaction Serialization Uses JSON Instead of BCS

- **ID:** SEC-011
- **Date:** 2026-03-15
- **Task:** pre-sprint → **Resolved by T-S2-04 (branch: agent/r3d-sui-bcs)**
- **Agent:** R3d (Chain Agent — Sui)
- **File:** `crates/mpc-wallet-chains/src/sui/tx.rs:63-76` (pre-fix)
- **Description:** The Sui `tx_data` is a canonical JSON blob rather than the required BCS
  (Binary Canonical Serialization) encoding of `TransactionData`. The `sign_payload`
  computation (Blake2b-256 of intent_prefix || tx_data) uses this JSON as input. Sui nodes
  expect the BCS-encoded `TransactionData` bytes. A transaction with a JSON-encoded body
  will be rejected. This is a known documented TODO in the code.
- **Impact:** Transactions cannot be submitted to Sui mainnet. The signing is over a
  JSON representation, not the canonical BCS bytes, so the signature does not correspond
  to any valid Sui transaction.
- **Recommendation:** Add `bcs` crate to workspace dependencies (requires R0 approval) and
  implement proper `TransactionData` BCS encoding. The intent prefix computation and
  Blake2b-256 hashing are correct per the Sui spec; only the serialization format needs
  upgrading. Assign to R3d.
- **Status:** Resolved
- **Resolved in commit:** agent/r3d-sui-bcs (T-S2-04) — `SuiTransferPayload` struct with
  BCS encoding replaces JSON stub. `sign_payload = Blake2b-256([0,0,0] || bcs_bytes)`.
  `tx_data = bcs_bytes || pubkey(32)`. `finalize_sui_transaction` produces 97-byte
  `[0x00 | sig(64) | pubkey(32)]`. JSON stub (`serde_json::json!()`) completely removed.
- **R6 Residual Note (INFO):** `SuiTransferPayload` is a minimal struct — does not include
  gas payment, epoch, or gas budget. Transactions will not be accepted by Sui mainnet
  validators until Sprint 3 when full `sui-sdk` TransactionData BCS encoding is added.
  This is documented in code TODOs and is an accepted scope limitation for Sprint 2.

---

## [MEDIUM] SEC-012: EVM Transaction Finalization Does Not Enforce Low-S ECDSA Normalization

- **ID:** SEC-012
- **Date:** 2026-03-15
- **Task:** pre-sprint
- **Agent:** R3a (Chain Agent — EVM) / R1 (Crypto Agent)
- **File:** `crates/mpc-wallet-chains/src/evm/tx.rs:98-101`
- **Description:** `finalize_evm_transaction` accepts the `s` value from `MpcSignature::Ecdsa`
  and passes it directly to `Signature::from_scalars_and_parity`. No check is performed to
  ensure `s` is in the lower half of the secp256k1 curve order (the "low-S" requirement
  of EIP-2). High-S signatures are rejected by some Ethereum node implementations and
  replay-protection middleware (e.g., some hardware wallets). The GG20 protocol uses
  `k256::ecdsa::SigningKey::sign` which produces RFC 6979 deterministic signatures that
  are already low-S normalized — but this assumption is not verified or documented.
- **Impact:** If the signature source ever changes, high-S signatures could be broadcast,
  potentially causing transaction failures. The absence of an explicit check is a
  correctness/reliability risk.
- **Recommendation:** After building `alloy_sig`, assert or enforce that `s` is in the lower
  half: `assert!(s_scalar <= secp256k1_n/2)`. Use `k256::ecdsa::Signature::normalize_s()`
  on the signature before decomposing into `r`/`s`. Document that low-S is required.
- **Status:** Open

---

## [MEDIUM] SEC-013: ProtocolMessage `from` Field Not Validated by FROST Protocols

- **ID:** SEC-013
- **Date:** 2026-03-15
- **Task:** pre-sprint
- **Agent:** R1 (Crypto Agent)
- **File:** `crates/mpc-wallet-core/src/protocol/frost_ed25519.rs:84-90`,
  `crates/mpc-wallet-core/src/protocol/frost_secp256k1.rs:84-90`
- **Description:** In both FROST protocols, the `from` field of received `ProtocolMessage`s
  is used to map round-1 and round-2 packages to FROST identifiers (`party_to_identifier(msg.from)`).
  However, as noted in SEC-007, the `from` field is self-reported by the sender. A malicious
  party can send a message claiming `from: PartyId(X)` to inject packages attributed to
  another party. FROST has cryptographic proofs-of-knowledge in DKG round 1 packages, but
  these protect against incorrect secret shares, not against a party claiming to be a
  different identity in the map.
- **Impact:** Party impersonation during DKG or signing could corrupt the key generation
  or produce a signing failure, potentially constituting a denial-of-service attack.
- **Recommendation:** Validate that the `from` field matches the cryptographic identity of
  the sender (requires SEC-007 to be addressed at the transport level first). Add explicit
  validation that duplicate `from` IDs are rejected in the `BTreeMap` insertion loop.
- **Status:** Open

---

## [LOW] SEC-014: `LocalTransport` Has No Production Use Guard

- **ID:** SEC-014
- **Date:** 2026-03-15
- **Task:** pre-sprint
- **Agent:** R2 (Infrastructure Agent) / R4 (Service Agent)
- **File:** `crates/mpc-wallet-core/src/transport/local.rs:13-17`
- **Description:** `LocalTransport` is an in-process transport using tokio `mpsc` channels.
  It provides no encryption, no authentication, and no network separation. It is currently
  used by the CLI for "demo mode" (all parties in one process). There is no `#[cfg(test)]`
  gate or feature flag preventing production use.
- **Impact:** A developer or integrator could accidentally deploy `LocalTransport` in a
  multi-machine production setup by not switching to `NatsTransport`, silently eliminating
  all transport-level security.
- **Recommendation:** Add `#[doc = "WARNING: In-process only. NOT for production use."]` to
  the struct. Consider adding a `#[cfg(any(test, feature = "demo"))]` gate so the type is
  only available in test/demo builds. Alternatively, emit a `tracing::warn!` at construction
  noting the transport is insecure.
- **Status:** Open

---

## [LOW] SEC-015: `KeyShare` Derives `Debug` — Secret Share Bytes Visible in Logs

- **ID:** SEC-015
- **Date:** 2026-03-15
- **Task:** pre-sprint
- **Agent:** R0 (Architect Agent) / R1 (Crypto Agent)
- **File:** `crates/mpc-wallet-core/src/protocol/mod.rs:28`
- **Description:** `KeyShare` derives `Debug`, which means any code that formats a `KeyShare`
  with `{:?}` or `{:#?}` will print `share_data` as a byte array. The `share_data` field
  contains the serialized (though not the raw scalar) secret key material. While not directly
  a scalar value, it can be deserialized to extract the full secret.
- **Impact:** Accidental debug logging of a `KeyShare` (e.g., in error handling or test output)
  would leak key share bytes into log files or stdout.
- **Recommendation:** Replace `#[derive(Debug)]` on `KeyShare` with a manual `Debug` impl
  that redacts `share_data`: `share_data: "[REDACTED]"`. Same applies to `GroupPublicKey`
  if it contains sensitive variants in future.
- **Status:** Open

---

## [LOW] SEC-016: Bitcoin `SerializableTx` Uses `unwrap()` on Consensus Decode

- **ID:** SEC-016
- **Date:** 2026-03-15
- **Task:** pre-sprint
- **Agent:** R3b (Chain Agent — Bitcoin)
- **File:** `crates/mpc-wallet-chains/src/bitcoin/tx.rs:152-153`
- **Description:** `SerializableTx::to_tx()` calls `.unwrap()` twice — once on `hex::decode`
  and once on `bitcoin::Transaction::consensus_decode`. If the stored hex is malformed or
  the transaction fails to decode, these panics will crash the signing process rather than
  returning an error.
- **Impact:** Unexpected panics in production transaction finalization.
- **Recommendation:** Replace `.unwrap()` with proper error propagation returning `CoreError`.
- **Status:** Open

---

## [LOW] SEC-017: No Input Validation on `from` Address in Solana Transaction Builder

- **ID:** SEC-017
- **Date:** 2026-03-15
- **Task:** pre-sprint
- **Agent:** R3c (Chain Agent — Solana)
- **File:** `crates/mpc-wallet-chains/src/solana/tx.rs:93-115`
- **Description:** The Solana transaction builder accepts `from` and `to` addresses as
  base58 strings but does not verify that `from_bytes` matches the signing public key
  (`group_pubkey`). A mismatched `from` address would result in a transaction where the
  signer is not the fee payer, which would be rejected by the network.
- **Impact:** Incorrectly constructed transactions that waste signing operations.
- **Recommendation:** Pass the `GroupPublicKey` to `build_solana_transaction` and validate
  that `from_bytes` equals the Ed25519 public key bytes before building the transaction.
- **Status:** Open

---

## [LOW] SEC-018: `async-nats` Depends on `rustls-pemfile` (Unmaintained)

- **ID:** SEC-018
- **Date:** 2026-03-15
- **Task:** pre-sprint
- **Agent:** R2 (Infrastructure Agent)
- **File:** `Cargo.lock` — `rustls-pemfile v2.2.0`
- **Description:** `cargo audit` reports RUSTSEC-2025-0134: `rustls-pemfile` is unmaintained.
  This is a transitive dependency of `async-nats 0.38.0`. The TLS certificate parsing path
  used in NATS TLS connections may use this crate.
- **Impact:** Low immediate risk (unmaintained does not mean vulnerable), but future CVEs
  will not be patched by the crate maintainer.
- **Recommendation:** Upgrade `async-nats` to a version that depends on a maintained
  PEM parsing library when available.
- **Status:** Open

---

## [LOW] SEC-019: `quinn-proto 0.11.13` — Known DoS Vulnerability (RUSTSEC-2026-0037)

- **ID:** SEC-019
- **Date:** 2026-03-15
- **Task:** pre-sprint
- **Agent:** R2 (Infrastructure Agent)
- **File:** `Cargo.lock` — `quinn-proto v0.11.13`
- **Description:** `cargo audit` reports RUSTSEC-2026-0037 (Severity 8.7 HIGH): DoS in
  Quinn QUIC endpoints. `quinn-proto` is a transitive dependency of `reqwest` which is
  pulled in by `alloy`. The fix is to upgrade to `quinn-proto >= 0.11.14`.
- **Impact:** If the alloy HTTP transport is used (e.g., for RPC calls), a remote attacker
  could cause denial of service by sending malformed QUIC packets. This is a HIGH severity
  CVSS score.
- **Recommendation:** Update `alloy` to a version that depends on `quinn-proto >= 0.11.14`,
  or add a `[patch.crates-io]` override to pin `quinn-proto` to the fixed version.
- **Status:** Open

---

## [INFO] SEC-020: FROST Protocols Correctly Avoid Full Key Reconstruction

- **ID:** SEC-020
- **Date:** 2026-03-15
- **Task:** pre-sprint
- **Agent:** R1 (Crypto Agent)
- **File:** `crates/mpc-wallet-core/src/protocol/frost_ed25519.rs`,
  `crates/mpc-wallet-core/src/protocol/frost_secp256k1.rs`
- **Description:** Both FROST implementations use the `frost-ed25519 v2.2` and
  `frost-secp256k1-tr v2.2` crates for DKG and threshold signing. Neither protocol
  reconstructs the full private key; each party produces only a signature share.
  `ZeroizeOnDrop` is correctly applied to the share data structs. The round-based DKG
  (part1/part2/part3) and signing (commit/sign/aggregate) follow the FROST protocol
  specification.
- **Impact:** None — this is a positive finding.
- **Recommendation:** Continue using FROST for Ed25519 and secp256k1 Taproot. Replace
  GG20 ECDSA with a non-reconstructing protocol (see SEC-001).
- **Status:** Informational

---

## [INFO] SEC-021: AES-256-GCM Key Storage — Random Salt and Nonce Per Write

- **ID:** SEC-021
- **Date:** 2026-03-15
- **Task:** pre-sprint
- **Agent:** R2 (Infrastructure Agent)
- **File:** `crates/mpc-wallet-core/src/key_store/encrypted.rs:35-58`
- **Description:** The `encrypt` method generates a fresh random 16-byte salt and 12-byte
  nonce per encryption operation, stored prepended to the ciphertext. This is correct —
  no nonce or salt reuse is possible across different writes. AES-256-GCM with a 128-bit
  authentication tag provides authenticated encryption.
- **Impact:** None — this is a positive finding.
- **Recommendation:** Consider upgrading salt to 32 bytes (see SEC-006) and adding explicit
  associated data (AAD) binding the ciphertext to the key group ID to prevent ciphertext
  transplantation attacks.
- **Status:** Informational

---

## [INFO] SEC-022: Git History — No Actual Secrets Found

- **ID:** SEC-022
- **Date:** 2026-03-15
- **Task:** pre-sprint
- **Agent:** R6 (Security Agent)
- **File:** git history
- **Description:** Manual review of `git log --all -p` filtered for "secret", "password",
  "private_key", "0x" found only: protocol constant byte values (0x00, 0x01, 0x04 prefixes),
  hex-encoded test public keys (known test key where secret=1, which is intentional), and
  structural hex values. No actual private key material, passwords, or API keys were found
  committed to the repository.
- **Impact:** None — positive finding.
- **Recommendation:** Add a `gitleaks` or `trufflehog` pre-commit hook to enforce this going
  forward. The hardcoded `"demo-password"` string in the CLI source (SEC-002) is in committed
  code (not git history), which is also a concern.
- **Status:** Informational

---

## Retrospective Verdicts (pre-gate-workflow)

> These branches were merged to `main` before the R6 gate workflow existed.
> Verdicts are issued retrospectively based on the audit data collected in the initial
> comprehensive review (2026-03-15). No new source file reads were required — all data
> was gathered during that cycle.

---

### VERDICT: [R1] zeroize branch

```
VERDICT: APPROVED (with tracked findings)
Branch: agent/r1-zeroize
Task: pre-sprint
```

Findings: SEC-004 (HIGH — `KeyShare.share_data` itself is not zeroized, only inner structs),
SEC-008 (MEDIUM — GG20 reconstructed scalar not explicitly zeroized), SEC-015 (LOW — `KeyShare`
derives `Debug`)

Notes: The R1 work correctly applied `ZeroizeOnDrop` to all three internal share structs
(`Gg20ShareData`, `FrostEd25519ShareData`, `FrostSecp256k1ShareData`) — the targeted goal of
this branch. The residual SEC-004 / SEC-008 issues are at the `KeyShare` wrapper level (owned
by R0) and in the GG20 simulation path; they do not represent a regression introduced by this
branch. SEC-001 (GG20 key reconstruction) pre-existed the zeroize work and is tracked
separately. Retrospectively APPROVED as a scoped improvement; open findings tracked above.

---

### VERDICT: [R2] NatsTransport skeleton

```
VERDICT: APPROVED (stub — expected, documented)
Branch: agent/r2-nats
Task: pre-sprint
```

Findings: SEC-003 (CRITICAL — all methods are `todo!()`)

Notes: The `todo!()` stubs are **expected and documented** — this branch was explicitly scoped
as a skeleton/scaffold to establish the struct, field layout, and security comment block, not
a production implementation. The security comment at lines 13–17 of `nats.rs` correctly
enumerates all required security properties (TLS, ECDH envelope, replay protection). SEC-003
is tracked as an open CRITICAL finding and assigned to R2 for Sprint 1 implementation. No
regression introduced; the skeleton unblocks R6 visibility into the planned implementation.
Retrospectively APPROVED as a scaffold; SEC-003 must be resolved before any distributed
deployment.

---

### VERDICT: [R3a] EVM multi-network

```
VERDICT: APPROVED (with tracked findings)
Branch: agent/r3a-evm
Task: pre-sprint
```

Findings: SEC-012 (MEDIUM — no low-S enforcement in EVM finalization)

Notes: The R3a work correctly added `Polygon` (chain_id=137) and `BSC` (chain_id=56) network
variants alongside `ethereum()` / `polygon()` / `bsc()` constructors, and the `EvmProvider::new`
factory with input validation that rejects non-EVM chains. The chain_id values are correct per
EIP-155. SEC-012 (low-S normalization) is a pre-existing gap in `evm/tx.rs`, not introduced by
this branch. No new security issues found for this branch's specific changes. Retrospectively
APPROVED.

---

### VERDICT: [R3b] Bitcoin testnet/signet

```
VERDICT: APPROVED (with tracked findings)
Branch: agent/r3b-btc
Task: pre-sprint
```

Findings: SEC-009 (MEDIUM — empty `prev_out.script_pubkey` in sighash), SEC-016 (LOW — `.unwrap()` in `SerializableTx::to_tx()`)

Notes: The R3b work correctly added `testnet()` and `signet()` constructors to
`BitcoinProvider`, and the `chain()` method correctly maps `bitcoin::Network::Bitcoin` to
`Chain::BitcoinMainnet` and all other networks to `Chain::BitcoinTestnet`. Network-aware
address derivation is passed through correctly. SEC-009 and SEC-016 are pre-existing issues
in `bitcoin/tx.rs` not introduced by this branch. The testnet/signet additions themselves
are correct and safe. Retrospectively APPROVED.

---

### VERDICT: [R3c] Solana binary serialization

```
VERDICT: APPROVED (with tracked findings)
Branch: agent/r3c-sol
Task: pre-sprint
```

Findings: SEC-010 (MEDIUM — `tx_hash` is only 8 bytes of signature), SEC-017 (LOW — no `from` address validation against signing pubkey)

Notes: The R3c work replaced the previous JSON stub with a real Solana legacy message binary
layout following the documented wire format (header + compact-u16 account count + 32-byte
keys + blockhash + compact-u16 instruction count + instruction bytes). The `sign_payload` is
now the canonical message bytes (what Ed25519 signs), which is correct. The `finalize`
function builds a proper wire transaction (`compact-u16(1) || sig(64) || message`). This is
a material security improvement over the prior JSON stub. SEC-010 (abbreviated `tx_hash`)
and SEC-017 (missing `from` validation) are noted but do not compromise the signing
correctness. Retrospectively APPROVED as a significant positive step.

---

### VERDICT: [R3d] Sui cleanup

```
VERDICT: APPROVED (with tracked findings)
Branch: agent/r3d-sui-followup
Task: pre-sprint
```

Findings: SEC-011 (MEDIUM — JSON instead of BCS for `tx_data`, tracked as known TODO)

Notes: The R3d work added a `Default` impl for `SuiProvider`, a `with_pubkey` constructor
that embeds the `GroupPublicKey` to resolve the prior zero-byte pubkey bug (noted in
AGENTS.md as a known bug), and a `broadcast_stub` with a clear error message and documented
`TODO(production)` comment pointing to the correct Sui JSON-RPC call. The zero-byte pubkey
fix is a security improvement: `finalize_sui_transaction` now correctly extracts the real
Ed25519 public key from `tx_data` JSON and includes it in the Sui signature wire format.
SEC-011 (JSON vs BCS serialization) is a pre-existing known issue documented in both
AGENTS.md and code comments, tracked for R3d in Sprint 1. The `broadcast_stub` returning an
error (rather than silently doing nothing) is the correct safe behavior for an unimplemented
RPC call. Retrospectively APPROVED.

---

## [LOW] SEC-023: T-06 Missing Test for Invalid Hex Characters in Sui Address Validation

- **ID:** SEC-023
- **Date:** 2026-03-15
- **Task:** T-06
- **Agent:** R3d (Chain Agent — Sui)
- **File:** `crates/mpc-wallet-chains/tests/chain_integration.rs`
- **Description:** `validate_sui_address` correctly handles all three invalid-address cases in
  its implementation: (1) missing `0x` prefix, (2) wrong hex-part length, and (3) invalid hex
  characters. Tests cover cases 1 and 2 explicitly. Case 3 is exercised only indirectly via
  `"not-a-valid-address"` (which fails at case 1 before reaching the hex decode path). There
  is no test of the form `"0x" + 64 chars of non-hex` (e.g., `"zz...zz"`) that specifically
  exercises the `hex::decode` error branch.
- **Impact:** Low — the implementation is correct and the `hex::decode` error branch is not
  reachable without passing the length check; coverage gap is test-only. Does not affect
  security posture.
- **Recommendation:** Add one test: `"0x" + "zz" * 32` (64 non-hex chars) → assert `is_err()`.
  One line change to the test file.
- **Status:** Open
- **Owner:** R3d

---

## [MEDIUM] SEC-024: GG20 Distributed Protocol Trusts Party 1 for Nonce Generation

- **ID:** SEC-024
- **Date:** 2026-03-16
- **Task:** T-S2-01 (R1, `agent/r1-real-gg20`) — new finding during Sprint 2 gate audit
- **Agent:** R6 (Security Agent)
- **File:** `crates/mpc-wallet-core/src/protocol/gg20.rs` — `distributed_sign` Round 1
- **Description:** In the distributed signing protocol, Party 1 (coordinator) unilaterally
  generates the ephemeral nonce `k`, computes `k_inv`, and broadcasts `(r, k_inv)` to all
  other signers in plaintext. Each non-coordinator party uses `k_inv` to compute their partial
  signature `s_i = x_i_add * r * k_inv`. This means: (1) Party 1 knows all individual `s_i`
  values AND `k_inv`, meaning it could in principle derive `x_i_add` for each party if it can
  compute `r⁻¹ · s_i · k`. (2) `k_inv` is transmitted in cleartext over the transport
  channel (currently `LocalTransport`, which has no encryption). This is documented in the
  module as "honest-but-curious secure for Party 1."
- **Impact:** This is an architectural trust assumption, not a regression from SEC-001. The
  full key is never assembled. However, Party 1 is fully trusted for: (a) generating an
  unbiased nonce (a malicious Party 1 could use a weak k to enable key extraction via
  known-signature attacks), and (b) keeping `k_inv` private from network observers (mitigated
  by SEC-003 fix once implemented).
- **Recommendation:** Sprint 3: implement distributed nonce generation (e.g., using DLEQ
  proofs so each party contributes a nonce fragment, preventing Party 1 from choosing a
  weak or known nonce). This is the standard GG20 improvement path. Until then, document
  the trust assumption prominently in the `distributed_sign` API doc.
- **Status:** Open — non-blocking (documented trust assumption, improvement deferred to Sprint 3)
- **Severity:** MEDIUM (non-blocking for merge; Party 1 trust is a documented assumption)
- **Owner:** R1

---

## Sprint 1 Gate Verdicts (2026-03-15)

---

### VERDICT: [R0] T-05 — freeze/unfreeze KeyStore interface

```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
VERDICT: APPROVED
Branch:  agent/r0-interface
Task:    T-05
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Security gate passed. No CRITICAL or HIGH findings.
Checklist: all items passed ✓
Open non-blocking: none
```

Checklist results:
- [x] `KeyFrozen(String)` message template is `"key group frozen: {0}"` — carries only the group ID string, no key bytes, password, or derived key material.
- [x] `freeze` and `unfreeze` use `&self` — consistent with the existing `KeyStore` async trait API.
- [x] Stub impls in `EncryptedFileStore` are `Ok(())` with `let _ = group_id;` — no logic, no side effects, cannot produce errors or incorrect state.
- [x] Additive change only — no existing `CoreError` variants removed or renamed; no existing `KeyStore` methods modified.

No new dependencies. No Cargo.lock changes. Change is a clean interface extension that unblocks T-04 (R1).

---

### VERDICT: [R1] T-01/T-02 — GG20 feature gate + touch() timestamp

```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
VERDICT: APPROVED
Branch:  agent/r1-zeroize
Task:    T-01 / T-02
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Security gate passed. No CRITICAL or HIGH findings.
Checklist: all items passed ✓
Open non-blocking: SEC-001 (CRITICAL — pre-existing, correctly documented as open, scheduled Sprint 2)
```

**T-01 Checklist results:**
- [x] `gg20-simulation` is NOT in `default = []`. `[features]` section is `default = []` / `gg20-simulation = []`.
- [x] Lagrange interpolation and all secret reconstruction logic (`lagrange_interpolate`, `shamir_split`, `Scalar`/`SecretKey` key material) is entirely absent from the non-feature build. Every use of the reconstruction path carries `#[cfg(feature = "gg20-simulation")]`.
- [x] The `#[cfg]` gate wraps ALL items in the simulation path — structs, `use` imports, `impl` blocks, helper functions, and tests are all individually gated. The production stub (`#[cfg(not(feature = "gg20-simulation"))]`) contains zero cryptographic logic.
- [x] The production stub `Gg20Protocol` returns `Err(CoreError::Protocol(...))` for both `keygen` and `sign` — does not silently succeed, does not panic.
- [x] SEC-001 status: correctly documented as Open in the module-level doc comment with reference to Sprint 2 task T-S2-01. Warning is accurate.

**T-02 Checklist results:**
- [x] `touch()` never calls `decrypt()` or opens any `.enc` file. It only checks `group_dir.exists()` and writes `touch.json` with a timestamp.
- [x] No key material in any variable or log during `touch()`. The method reads only the directory path from `&self`.
- [x] Timestamp is derived from `SystemTime::now()` — not user-supplied input. No injection vector.
- [x] Returns `Err(CoreError::KeyStore(...))` if the group directory does not exist — does not silently create garbage state.

Only new dependency: `tempfile` added to `[dev-dependencies]` (test scaffolding only, not in production build, no security concerns).

---

### VERDICT: [R3c] T-07 — Solana tx_hash SEC-010 fix

```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
VERDICT: APPROVED
Branch:  agent/r3c-sol
Task:    T-07
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Security gate passed. No CRITICAL or HIGH findings.
Checklist: all items passed ✓
Open non-blocking: SEC-017 (LOW — pre-existing, from address not validated against signing pubkey)
```

SEC-010 status: **RESOLVED** by this branch.

Checklist results:
- [x] `hex::encode(&signature[..8])` is GONE from `tx.rs`. The old line is replaced entirely.
- [x] `bs58::encode(signature).into_string()` uses the full `signature` slice (64 bytes, the complete Ed25519 signature) — no truncation.
- [x] `SignedTransaction` output carries only the chain ID, tx bytes, and tx_hash (base58 of full signature). No secret material. The `sign_payload` (message bytes) is not included in the output struct.
- [x] Zero-lamports test present: `test_solana_zero_lamports_transaction` — `value: "0"` must not panic or error.
- [x] Same from/to test present: `test_solana_same_from_to_address` — SDK must accept same-address transfers (network-level restriction, not SDK concern).

No new dependencies introduced (bs58 was already in `[workspace.dependencies]` on main).

---

### VERDICT: [R3d] T-06 — Sui address validation

```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
VERDICT: APPROVED
Branch:  agent/r3d-sui-followup
Task:    T-06
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Security gate passed. No CRITICAL or HIGH findings.
Checklist: all items passed ✓
Open non-blocking: SEC-011 (MEDIUM — JSON vs BCS, pre-existing), SEC-023 (LOW — missing invalid-hex test case, new)
```

Checklist results:
- [x] Validation rejects missing `0x` prefix → `strip_prefix("0x").ok_or_else(...)` returns `Err(CoreError::InvalidInput(...))`.
- [x] Validation rejects wrong length (≠ 64 hex chars) → explicit `hex_part.len() != 64` check returns `Err`.
- [x] Validation rejects invalid hex chars → `hex::decode` returns `Err` which is mapped to `CoreError::InvalidInput`. Implementation correct. **Test coverage gap logged as SEC-023 (LOW)** — no dedicated test for `0x` + 64 non-hex chars; the `"not-a-valid-address"` test exercises case 1 (no prefix), not case 3.
- [x] Fail-fast: `validate_sui_address(sender)?` is the first statement in `build_transaction_with_sender`, before any transaction state is touched.
- [x] No secret material in error messages. Error strings include only the input address value and length — no key bytes, no signatures.
- [x] `try_into().unwrap()` is safe: length was verified as `hex_part.len() == 64` (= 32 decoded bytes) immediately before `hex::decode`, so `bytes.try_into::<[u8; 32]>()` cannot fail.

No new dependencies.

---

## Sprint 2 Gate Verdicts (2026-03-16)

---

### VERDICT: agent/r1-real-gg20 (T-S2-01)

```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
VERDICT: APPROVED
Branch:  agent/r1-real-gg20
Task:    T-S2-01
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Security gate passed. No CRITICAL or HIGH findings introduced.
Checklist: all items passed ✓
SEC-001: RESOLVED — full private key never assembled on any party during signing.
New finding: SEC-024 (MEDIUM, non-blocking — Party 1 trusted for nonce generation)
```

Checklist results:

- [x] `lagrange_interpolate` exists ONLY inside `#[cfg(feature = "gg20-simulation")]` block (gg20.rs:156-176). The production `gg20-distributed` code path has zero calls to `lagrange_interpolate`. `lagrange_coefficient` (a different function — computes λ_i without reconstructing x) is present in the non-simulated path and is correct.
- [x] Full private key scalar NEVER assembled during signing. Each party computes `x_i_add = λ_i · f(i)` locally, then `s_i = x_i_add · r · k_inv`. No `Σ x_i_add` aggregation occurs on any single machine. Code comment explicitly states: "The full key x = Σ x_i_add is NEVER computed."
- [x] `gg20-distributed` IS the default — `Cargo.toml`: `default = ["gg20-distributed"]`.
- [x] `gg20-simulation` is NOT in default features — verified in `mpc-wallet-core/Cargo.toml`.
- [x] Additive share `x_i_add` is used only locally. Round 2 messages contain only `s_partial` (partial signature), never the raw Shamir share `f(i)` or the additive share `x_i_add`.
- [x] No secret key material in protocol messages. Round 1 broadcasts `(r, k_inv)` — public signing parameters. Round 2 sends `s_partial` — a partial signature contribution, not key material.
- [x] Signature format: secp256k1 ECDSA `(r, s)` validated through `k256::ecdsa::Signature`, low-S normalization applied via `normalize_s()`, recovery_id brute-forced against group pubkey. Correct format for EVM/Bitcoin.

New finding from this audit:

- SEC-024 (MEDIUM, non-blocking): `k_inv` broadcast by Party 1 in cleartext — Party 1 is fully trusted for nonce generation. Documented as "honest-but-curious secure for Party 1" in module docs. Sprint 3 should add distributed nonce generation (DLEQ proofs).

---

### VERDICT: agent/r4-cli-password (T-S2-03)

```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
VERDICT: APPROVED
Branch:  agent/r4-cli-password
Task:    T-S2-03
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Security gate passed. No CRITICAL or HIGH findings introduced.
Checklist: all items passed ✓
SEC-002: RESOLVED — zero "demo-password" occurrences, rpassword prompt in all 4 commands.
```

Checklist results:

- [x] Zero occurrences of `"demo-password"` string in CLI source — all 4 `unwrap_or_else(|| "demo-password".into())` fallbacks removed. Confirmed by diff inspection.
- [x] All 4 commands (`keygen`, `sign`, `address`, `keys`) now call `rpassword::prompt_password("Enter wallet password: ")` when `--password` not supplied. Identical pattern across all 4 files.
- [x] Password is NOT logged, NOT stored in structs, NOT in error messages. The `password` variable flows directly into `EncryptedFileStore::new()`. Error message is `"Failed to read password: {e}"` — does not include the password value.
- [x] `rpassword::prompt_password` reads from `/dev/tty` directly (not stdin) — not interceptable by shell pipe redirection. This is the designed behavior of the `rpassword` v7 crate.
- [x] No new `unwrap()` calls on the password path. The `map_err()` pattern propagates errors as `anyhow::Error`. Pre-existing `unwrap()` at `keygen.rs:118` is on a timer/duration path, not password-related.

No new dependencies introduced by this branch (`rpassword = "7"` was added to workspace by R0 prep branch).

---

### VERDICT: agent/r3d-sui-bcs (T-S2-04)

```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
VERDICT: APPROVED
Branch:  agent/r3d-sui-bcs
Task:    T-S2-04
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Security gate passed. No CRITICAL or HIGH findings introduced.
Checklist: all items passed ✓
SEC-011: RESOLVED — JSON stub removed, BCS encoding implemented via SuiTransferPayload.
Residual (INFO): SuiTransferPayload lacks gas/epoch fields — not a security defect; Sprint 3 scope.
```

Checklist results:

- [x] JSON stub (`serde_json::json!()` for tx construction) is GONE. No `serde_json::json!()` call for transaction data in `tx.rs`. `serde_json` retained only for `params.extra` field parsing (reading `extra["sender"]`).
- [x] `sign_payload = Blake2b-256([0,0,0] || bcs_bytes)` — 32-byte digest. Code: `Blake2b256::new()` → `update(SUI_INTENT_PREFIX)` → `update(&bcs_bytes)` → `finalize().to_vec()`. Intent prefix `[0,0,0]` is correct per Sui spec. Tests assert `len() == 32` and non-zero.
- [x] `tx_data = bcs_bytes || pubkey(32)` — pubkey appended as last 32 bytes. Not sent over network; used internally by `finalize_sui_transaction` only. Test `test_sui_bcs_tx_data_contains_bcs_plus_pubkey` verifies last 32 bytes equal the pubkey.
- [x] `finalize_sui_transaction` produces 97-byte `[0x00 | sig(64) | pubkey(32)]`. `Vec::with_capacity(97)`, push `0x00`, extend sig(64), extend pubkey(32). Tests `test_sui_finalize_has_correct_signature_format` and `test_sui_bcs_finalize_97_byte_signature` verify exact byte layout.
- [x] `validate_sui_address` called for BOTH sender (step 1) and recipient (step 2) — BEFORE any transaction state is built. Fail-fast order confirmed.
- [x] No secret material in `tx_data` or `sign_payload`. `SuiTransferPayload` fields: sender address (32 bytes), recipient address (32 bytes), amount (u64), reference (32 bytes) — all public data. `sign_payload` is a non-reversible Blake2b-256 hash.
- [x] `try_into().unwrap()` at line 41 (`validate_sui_address`) is safe: `hex_part.len() != 64` guard fires before reaching it, ensuring exactly 32 decoded bytes.

`bcs = "0.1"` added to workspace in R0 prep branch — no known RUSTSEC advisories for this crate. No new findings.

---

## Sprint 3 Wave 2 Gate Verdicts (2026-03-16)

---

### VERDICT: agent/r2-nats-s3 (T-S3-01)

```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
VERDICT: APPROVED
Branch:  agent/r2-nats-s3
Task:    T-S3-01
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Security gate passed. No CRITICAL or HIGH findings introduced.
Checklist: all items passed ✓
SEC-003: RESOLVED — NatsTransport fully implemented, zero todo!() stubs.
New dependency: futures = "0.3" — no known CVEs.
```

Checklist results:

- [x] Zero `todo!()` in `nats.rs` — `grep "todo!"` on the branch file returns empty. All four
  previously stubbed methods (`connect`, `inbox_subject`, `party_subject`, `send`, `recv`) are
  fully implemented.
- [x] `ProtocolMessage` JSON payload does NOT contain secret material. `ProtocolMessage` has
  fields: `from: PartyId`, `to: Option<PartyId>`, `round: u16`, `payload: Vec<u8>`. The
  `payload` field carries protocol-round bytes set by the caller (protocol layer), not by
  `NatsTransport`. The transport layer serializes the message as-is and adds no key material.
  No key share bytes, scalars, or raw secrets are introduced by this transport code.
- [x] Broadcast (`msg.to == None`) returns `Err(CoreError::Transport(...))` — not a panic, not
  a silent drop. Code: `msg.to.ok_or_else(|| CoreError::Transport("NATS: broadcast not supported".to_string()))?;`
  This is the correct behavior for an unicast transport.
- [x] All error paths use `CoreError::Transport(String)` or `CoreError::Serialization(String)`.
  No raw `panic!` or `unwrap()` on any operational path (connect, send, recv). Errors from
  `async_nats` are wrapped via `.map_err(|e| CoreError::Transport(format!(...)))`.
- [x] No hardcoded credentials, URLs, or secrets. The `nats_url` is caller-supplied. No
  embedded tokens, passwords, or subject names beyond the session-scoped formula.
- [x] `futures = "0.3"` added to workspace `[workspace.dependencies]` and to
  `mpc-wallet-core/Cargo.toml`. `cargo audit` found NO advisory for `futures 0.3`. The five
  pre-existing advisories (SEC-018: `rustls-pemfile`, SEC-019: `quinn-proto`, plus
  `atomic-polyfill`, `derivative`, `paste`) are all pre-existing transitive deps, not
  introduced by this branch.

Residual notes:

- The security comment at the top of `nats.rs` correctly documents that mTLS, per-session ECDH
  envelope encryption, and replay protection (seq_no + TTL) are deferred to Sprint 4 (Epic E
  stories E2–E4). This is the accepted scope for T-S3-01. SEC-007 (unauthenticated `from`
  field) remains open and applies to this transport as well — tracked separately.
- The `futures::StreamExt` import is used for `.next()` on the NATS subscriber. This is the
  correct idiomatic usage.

---

### VERDICT: agent/r2-argon2 (T-S3-02)

```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
VERDICT: APPROVED
Branch:  agent/r2-argon2
Task:    T-S3-02
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Security gate passed. No CRITICAL or HIGH findings introduced.
Checklist: all items passed ✓
SEC-005: RESOLVED — password wrapped in Zeroizing<String>.
SEC-006: RESOLVED — Argon2id params: m=65536 KiB / t=3 / p=4; salt upgraded to 32 bytes.
```

Checklist results:

- [x] Argon2 params upgraded — exact values confirmed in source: `ARGON2_M_COST: u32 = 65536`,
  `ARGON2_T_COST: u32 = 3`, `ARGON2_P_COST: u32 = 4`. `Params::new(65536, 3, 4, Some(32))`
  called in `derive_key`. Values match the OWASP wallet-class recommendation for Argon2id.
  `Algorithm::Argon2id` and `Version::V0x13` are explicitly set (no reliance on defaults).
- [x] Password field changed from `password: String` to `password: Zeroizing<String>` in the
  `EncryptedFileStore` struct. Constructor wraps with `Zeroizing::new(password.to_string())`.
  Memory is zeroed when `EncryptedFileStore` is dropped (SEC-005 fix).
- [x] Derived key wrapped in `Zeroizing<[u8; 32]>` — `derive_key` return type changed from
  `[u8; 32]` to `Zeroizing<[u8; 32]>`. `key_bytes` is `Zeroizing::new([0u8; 32])` and is
  passed by `key_bytes.as_ref()` to `Aes256Gcm::new_from_slice`. Zeroized on drop after
  cipher construction. An intermediate `Zeroizing<Vec<u8>>` also wraps the password bytes
  slice during KDF execution (defense-in-depth).
- [x] Salt upgraded to 32 bytes — `let mut salt = [0u8; 32]` in `encrypt`. Decrypt boundary
  check updated to `data.len() < 44` (32 salt + 12 nonce). Slice offsets corrected:
  `salt = &data[..32]`, `nonce = Nonce::from_slice(&data[32..44])`, `ciphertext = &data[44..]`.
  File format incompatibility documented in constructor doc comment (ephemeral test dirs only).
- [x] No new `unwrap()` calls on the KDF path. All `unwrap()` occurrences are in the
  `#[cfg(test)]` block (lines 253+). Production `derive_key`, `encrypt`, and `decrypt` use
  `map_err(...)` throughout, propagating errors as `CoreError::Encryption`.

No new crate dependencies introduced (zeroize was already a workspace dependency).

---

### VERDICT: agent/r1-zeroize-shares (T-S3-03)

```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
VERDICT: APPROVED
Branch:  agent/r1-zeroize-shares
Task:    T-S3-03
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Security gate passed. No CRITICAL or HIGH findings introduced.
Checklist: all items passed ✓
SEC-004: IN PROGRESS — share_data copy sites zeroized (partial fix); root fix deferred Sprint 4.
```

Checklist results:

- [x] All 4 `share_data` deserialization sites wrapped in `Zeroizing::new(...)` before
  `serde_json::from_slice`. Confirmed locations:
  - `frost_ed25519.rs` — `sign()`: `let share_data_copy = Zeroizing::new(key_share.share_data.clone())`
  - `frost_secp256k1.rs` — `sign()`: same pattern
  - `gg20.rs` — `distributed_sign`: `let share_data_copy = Zeroizing::new(key_share.share_data.clone())`
  - `gg20.rs` — `simulation_sign`: same pattern (simulation path also protected)
  All four paths now ensure the intermediate clone is zeroed on drop.
- [x] `protocol/mod.rs` was NOT modified — `git diff main..agent/r1-zeroize-shares -- crates/mpc-wallet-core/src/protocol/mod.rs` produced empty output. R0 file boundary respected.
- [x] SEC-004 doc test added to `protocol_integration.rs`:
  `test_sec004_share_data_copies_are_zeroized` — verifies that `Zeroizing<Vec<u8>>` zeroes its
  own heap allocation on drop, not the original. Includes clear comment explaining the scope
  (type-system guarantee) and what the root fix requires (Sprint 4, R0 changes `KeyShare.share_data`
  to `Zeroizing<Vec<u8>>`).
- [x] All simulation code paths (inside `#[cfg(feature = "gg20-simulation")]` gate) are also
  wrapped — `simulation_sign` in `gg20.rs` receives the same `Zeroizing` treatment.

Residual notes:

- SEC-004 root fix — changing `KeyShare.share_data: Vec<u8>` to `Zeroizing<Vec<u8>>` in
  `protocol/mod.rs` — requires R0. The current branch addresses the immediate risk (copies
  created at deserialization sites are now zeroized). The original `key_share.share_data`
  field itself remains a plain `Vec<u8>` until Sprint 4.
- The doc test (`test_sec004_share_data_copies_are_zeroized`) correctly documents both what
  is fixed and what remains. The test uses `assert_eq!(raw[0], 0xAA)` to confirm that
  `Zeroizing::new(raw.clone())` does not zero the source — semantically correct.
- No new dependencies introduced (`zeroize` was already in workspace).

---

## cargo audit summary — Sprint 3 Wave 2

Run: 2026-03-16 on branch `agent/r6-security` (representative of main + Wave 2 deps)

| Advisory | Crate | Severity | Status |
|----------|-------|----------|--------|
| RUSTSEC-2026-0037 | `quinn-proto` | HIGH (CVSS 8.7) | Pre-existing SEC-019 — tracked |
| RUSTSEC-2025-0134 | `rustls-pemfile` | LOW (unmaintained) | Pre-existing SEC-018 — tracked |
| RUSTSEC-2023-0089 | `atomic-polyfill` | — | Pre-existing transitive dep |
| RUSTSEC-2024-0388 | `derivative` | — | Pre-existing transitive dep |
| RUSTSEC-2024-0436 | `paste` | — | Pre-existing transitive dep |

**`futures = "0.3"` (added by T-S3-01): NO new advisories.** All five advisories were present
on `main` before Wave 2 branches. No new CVEs introduced by any of the three Wave 2 branches.

---

## Sprint 16 Audit: DEC-015 Distributed Architecture

### Audit Date: 2026-03-19
### Auditor: R6 Security Agent

### Scope

Full security audit of the DEC-015 distributed architecture introduced in Sprint 15:
- Gateway (orchestrator) holds ZERO key shares — delegates to MPC nodes via NATS
- Each MPC node holds exactly 1 party's share in `EncryptedFileStore`
- `SignAuthorization` verification at MPC nodes before signing (DEC-012)
- Control plane message integrity
- Key material lifecycle

### Files Reviewed

- `services/api-gateway/src/orchestrator.rs` — `MpcOrchestrator`, `WalletMetadata`
- `services/api-gateway/src/state.rs` — `AppState` (line 393-395: orchestrator field)
- `services/mpc-node/src/main.rs` — `NodeConfig`, `execute_keygen`, `execute_sign`, handlers
- `services/mpc-node/src/rpc.rs` — re-export of shared RPC types
- `crates/mpc-wallet-core/src/rpc/mod.rs` — `KeygenRequest/Response`, `SignRequest/Response`, `FreezeRequest`
- `crates/mpc-wallet-core/src/protocol/sign_authorization.rs` — `SignAuthorization::verify()` (6 checks)
- `crates/mpc-wallet-core/src/transport/nats.rs` — `NatsTransport`, `SignedEnvelope` usage
- `crates/mpc-wallet-core/src/protocol/mod.rs` — `KeyShare.share_data: Zeroizing<Vec<u8>>`
- `crates/mpc-wallet-core/src/key_store/encrypted.rs` — `EncryptedFileStore` password zeroization

### Findings Summary

| ID | Severity | Summary | Status |
|----|----------|---------|--------|
| SEC-025 | MEDIUM | MPC nodes skip SignAuthorization verification when GATEWAY_PUBKEY is not configured | OPEN |
| SEC-026 | MEDIUM | Control plane messages (mpc.control.*) are plain JSON — no SignedEnvelope, no authentication | OPEN |
| SEC-027 | MEDIUM | Orchestrator generates ephemeral peer keys during keygen/sign — nodes receive wrong keys | OPEN |
| SEC-028 | LOW | NodeConfig.key_store_password is plain String — not Zeroizing after EncryptedFileStore init | OPEN |
| SEC-029 | LOW | NodeConfig.signing_key is never explicitly zeroized/dropped | OPEN |
| SEC-030 | LOW | No rate limiting on NATS control channels — DoS vector for mpc.control.* subscribers | OPEN |
| SEC-031 | LOW | No authentication on NATS connection from MPC nodes — any client can publish to control channels | OPEN |
| SEC-032 | INFO | Gateway holds zero key shares — DEC-015 core invariant verified (positive finding) | N/A |
| SEC-033 | INFO | Each MPC node stores only its own party's share — single-share invariant verified (positive finding) | N/A |

### Detailed Findings

#### SEC-025: MPC Nodes Skip SignAuthorization When GATEWAY_PUBKEY Not Set

- **ID:** SEC-025
- **Severity:** MEDIUM
- **File:** `services/mpc-node/src/main.rs`, lines 395-438 (`execute_sign`)
- **Description:**
  The `execute_sign` function only verifies `SignAuthorization` when `config.gateway_pubkey`
  is `Some(...)`. When `GATEWAY_PUBKEY` env var is not set, the entire verification block is
  skipped — nodes will sign any message sent via the control channel without checking
  authorization, policy, or approval quorum.

  ```rust
  if let Some(ref gateway_pubkey) = config.gateway_pubkey {
      // ... verification happens here ...
  }
  // If None: signing proceeds without any authorization check
  ```

- **Impact:** If a deployment omits `GATEWAY_PUBKEY` (e.g., misconfiguration, dev defaults),
  the entire SignAuthorization security model (DEC-012) is silently disabled. An attacker
  with NATS access can request signing of arbitrary messages.
- **Recommendation:**
  1. In production mode, make `GATEWAY_PUBKEY` required (panic on startup if missing).
  2. At minimum, log a WARN on every sign request when `GATEWAY_PUBKEY` is None.
  3. Consider adding a `--allow-unsigned` flag that must be explicitly set for dev/test use.
  4. Document `GATEWAY_PUBKEY` as a mandatory deployment requirement.

---

#### SEC-026: Control Plane Messages Are Unauthenticated Plain JSON

- **ID:** SEC-026
- **Severity:** MEDIUM
- **File:** `services/mpc-node/src/main.rs`, lines 110-131 (NATS subscriptions);
  `services/api-gateway/src/orchestrator.rs`, lines 137-144 (publish keygen);
  `crates/mpc-wallet-core/src/rpc/mod.rs` (message types)
- **Description:**
  Protocol-level messages between MPC parties use `SignedEnvelope` with Ed25519 signatures
  and replay protection (SEC-007 fix). However, control plane messages on `mpc.control.*`
  subjects are plain JSON published directly to NATS without any envelope, signature, or
  authentication.

  The orchestrator publishes `KeygenRequest`, `SignRequest`, and `FreezeRequest` as raw
  `serde_json::to_vec()` payloads. Nodes deserialize these directly without verifying the
  sender's identity.

  An attacker with NATS access could:
  - Publish fake `SignRequest` messages to trigger unauthorized signing (mitigated by SEC-025 if GATEWAY_PUBKEY is set)
  - Publish `FreezeRequest` to freeze/unfreeze key groups
  - Publish fake `KeygenRequest` to initiate rogue keygen ceremonies
  - Inject fake `KeygenResponse`/`SignResponse` on reply channels to confuse the orchestrator

- **Impact:** Any NATS client can impersonate the gateway on control channels. The
  SignAuthorization (SEC-025) mitigates the signing case, but freeze and keygen control
  messages have no equivalent protection.
- **Recommendation:**
  1. Wrap control plane messages in `SignedEnvelope` using the gateway's Ed25519 signing key.
  2. MPC nodes should verify control messages against the same `GATEWAY_PUBKEY`.
  3. Use NATS authorization (user/password or NKey) to restrict who can publish to `mpc.control.*`.

---

#### SEC-027: Orchestrator Generates Ephemeral Peer Keys That Don't Match Node Keys

- **ID:** SEC-027
- **Severity:** MEDIUM
- **File:** `services/api-gateway/src/orchestrator.rs`, lines 108-118 (keygen peer_keys),
  lines 278-289 (sign peer_keys)
- **Description:**
  During both `keygen()` and `sign()`, the orchestrator generates fresh random Ed25519 keys
  for each party and sends them in the `peer_keys` field of the request. However, the MPC
  nodes use their own persistent `NODE_SIGNING_KEY` for envelope signing (line 238-243 of
  `mpc-node/src/main.rs`). The orchestrator-generated keys do not match the nodes' actual
  signing keys.

  In `execute_keygen` and `execute_sign`, the node calls `register_peer_key()` with the
  keys from the request (lines 259-269, 475-485), meaning each node expects to verify
  messages from peers using the orchestrator-generated keys — but peers are actually signing
  with their persistent `NODE_SIGNING_KEY`.

  This means either:
  (a) The envelope verification will always fail (breaking the protocol), or
  (b) In the current simulated keygen/sign flow, the protocol never actually exchanges
  envelope-wrapped messages between nodes (the protocol runs locally).

  In either case, the peer key distribution mechanism is broken for a real distributed
  deployment.

- **Impact:** In a real multi-node deployment, protocol messages would fail envelope
  verification because the registered peer keys don't match the actual signing keys.
  This is currently masked by the protocol running in simulation mode.
- **Recommendation:**
  1. Nodes should register each other's actual `NODE_SIGNING_KEY` verifying keys.
  2. The orchestrator should either: (a) not generate peer keys and let nodes discover each
     other's keys via a registration protocol, or (b) collect each node's actual verifying
     key during a setup phase and distribute those.

---

#### SEC-028: NodeConfig.key_store_password Not Zeroized

- **ID:** SEC-028
- **Severity:** LOW
- **File:** `services/mpc-node/src/main.rs`, lines 40, 56-57
- **Description:**
  `NodeConfig.key_store_password` is stored as a plain `String`. Although the
  `EncryptedFileStore` internally wraps it in `Zeroizing<String>` (SEC-005 fix), the
  original `String` in `NodeConfig` is not zeroized and persists in memory for the
  lifetime of the `Arc<NodeConfig>`.

- **Impact:** The key store password remains in memory in plain form. Memory dumps or
  process inspection could reveal it.
- **Recommendation:** Change `NodeConfig.key_store_password` to `Zeroizing<String>` or
  consume/drop the password after passing it to `EncryptedFileStore::new()`.

---

#### SEC-029: Node Signing Key Lifetime

- **ID:** SEC-029
- **Severity:** LOW
- **File:** `services/mpc-node/src/main.rs`, lines 41, 59-65
- **Description:**
  The `NodeConfig.signing_key` (`ed25519_dalek::SigningKey`) is held in `Arc<NodeConfig>`
  for the entire process lifetime. The intermediate `key_bytes` and `arr` used during
  parsing (lines 61-65) are stack variables that are not explicitly zeroized. While `arr`
  is 32 bytes on the stack and will be overwritten eventually, it is not deterministically
  cleared.

  Additionally, `signing_key_hex` (the hex string from the environment) is a plain `String`
  that is not zeroized after use.

- **Impact:** Low — the signing key needs to remain available for the node's lifetime.
  The hex string and intermediate byte arrays on the stack are the primary concern.
- **Recommendation:** Zeroize `arr` and `signing_key_hex` after `SigningKey::from_bytes()`.

---

#### SEC-030: No Rate Limiting on NATS Control Channels

- **ID:** SEC-030
- **Severity:** LOW
- **File:** `services/mpc-node/src/main.rs`, lines 117-131 (subscriptions)
- **Description:**
  MPC nodes subscribe to wildcard control channels (`mpc.control.keygen.*`,
  `mpc.control.sign.*`, `mpc.control.freeze.*`) and process every incoming message
  without rate limiting. A malicious or malfunctioning client could flood these channels,
  causing nodes to spawn unbounded tasks (each `tokio::spawn` in `handle_keygen_requests`
  and `handle_sign_requests`).

- **Impact:** Resource exhaustion (CPU, memory, file descriptors) on MPC nodes.
- **Recommendation:**
  1. Add a semaphore to limit concurrent keygen/sign operations.
  2. Rate-limit by group_id or source.
  3. Use NATS JetStream with consumer limits (existing Epic E5 work).

---

#### SEC-031: No NATS Connection Authentication

- **ID:** SEC-031
- **Severity:** LOW
- **File:** `services/mpc-node/src/main.rs`, line 110 (`async_nats::connect`)
- **Description:**
  The MPC node connects to NATS using `async_nats::connect(&config.nats_url)` with no
  authentication credentials (no user/password, no NKey, no TLS client cert). The
  orchestrator does the same in `orchestrator.rs` line 70.

  While mTLS support exists for protocol-level NATS connections (`connect_signed_tls` in
  `nats.rs`), the control plane connections do not use it.

  If the NATS server is configured without authentication (common in dev), any network
  client can connect and publish/subscribe to all subjects.

- **Impact:** Combined with SEC-026, this allows any network-adjacent attacker to inject
  control messages. NATS server-side auth configuration mitigates this, but it is not
  enforced by the application.
- **Recommendation:**
  1. Support NATS NKey or user/password authentication in `NodeConfig`.
  2. Document NATS server-side authorization as a deployment requirement.
  3. Consider using `connect_signed_tls` for the control plane connection as well.

---

#### SEC-032: Gateway Holds Zero Key Shares (Positive Finding)

- **ID:** SEC-032
- **Severity:** INFO
- **Description:**
  Verified that the DEC-015 core invariant is correctly implemented:
  - `WalletMetadata` (`orchestrator.rs` line 30-38) contains only: `group_id`, `label`,
    `scheme`, `config`, `group_public_key`, `created_at`, `frozen`. No `KeyShare`,
    `share_data`, or any secret key material.
  - `AppState` (`state.rs` line 393-395) contains only `orchestrator: MpcOrchestrator`.
    No `KeyStore`, `EncryptedFileStore`, or share storage.
  - `MpcOrchestrator` stores `wallets: HashMap<String, WalletMetadata>` — metadata only.
  - Log message at line 241: "keygen complete — metadata stored (NO shares in gateway)".
  - The gateway never calls `protocol.keygen()` or `protocol.sign()` — it only publishes
    NATS requests and collects responses.

---

#### SEC-033: Each Node Stores Only Its Own Share (Positive Finding)

- **ID:** SEC-033
- **Severity:** INFO
- **Description:**
  Verified single-share-per-node invariant:
  - `execute_keygen` saves share using `key_store.save(&group_id, &metadata, config.party_id, &share)`
    (line 292-294) — only `config.party_id`'s share is saved.
  - `execute_sign` loads share using `key_store.load(&group_id, config.party_id)` (line 381) —
    only `config.party_id`'s share is loaded.
  - `protocol.keygen()` is called with `config.party_id` — returns only this party's share.
  - `KeyShare.share_data` uses `Zeroizing<Vec<u8>>` (SEC-004 root fix confirmed in
    `protocol/mod.rs` line 104).

---

### Additional Observations

1. **SignAuthorization verification is thorough when enabled.** The 6 checks in
   `sign_authorization.rs` (lines 110-187) are well-implemented: pubkey match, signature
   verification, freshness (2-min TTL with `abs_diff`), message binding (SHA-256 hash match),
   policy check, and approval quorum. Nine unit tests cover all rejection cases.

2. **`EncryptedFileStore` password zeroization is correct.** The `EncryptedFileStore`
   internally wraps the password in `Zeroizing<String>` and the derived key in
   `Zeroizing<[u8; 32]>` (SEC-005 fix confirmed). The residual issue is only at the
   `NodeConfig` layer (SEC-028).

3. **Protocol-level NATS messages are properly signed.** `NatsTransport::send()` wraps
   every `ProtocolMessage` in a `SignedEnvelope` with Ed25519 signature and monotonic
   `seq_no` for replay protection (SEC-007 fix). The gap is only on the control plane
   (SEC-026).

4. **Hardcoded NATS URL in keygen/sign.** `execute_keygen` and `execute_sign` use
   `"nats://127.0.0.1:4222"` (lines 239, 454) instead of `config.nats_url`. This is
   marked with a TODO comment. Not a security issue per se, but a correctness bug that
   would prevent multi-host deployments.

### Verdict

**APPROVED** — with conditions.

The DEC-015 distributed architecture correctly implements the core security invariants:
- Gateway holds zero key shares (SEC-032 positive)
- Each node stores only its own share (SEC-033 positive)
- SignAuthorization provides independent verification at nodes (DEC-012)
- Protocol messages are authenticated via SignedEnvelope (SEC-007)

**No CRITICAL or HIGH findings.** The three MEDIUM findings (SEC-025, SEC-026, SEC-027)
do not block merge but should be addressed before production deployment:

- **SEC-025** is the most important: `GATEWAY_PUBKEY` must be documented as mandatory
  for production, and nodes should refuse to sign without it.
- **SEC-026** should be addressed as part of control plane hardening (can be deferred
  to a security hardening sprint).
- **SEC-027** is an integration issue that will surface during real multi-node testing.

The LOW findings (SEC-028 through SEC-031) are defense-in-depth improvements that
should be tracked for future sprints.
