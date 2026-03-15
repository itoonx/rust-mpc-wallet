# MPC Wallet — Security Findings Log

> Maintained by **R6 Security Agent**.  
> Format: CRITICAL / HIGH / MEDIUM / LOW / INFO  
> All findings are tagged with the owning agent responsible for the fix.

---

## [CRITICAL] SEC-001: GG20 Reconstructs Full Private Key on Every Signer

- **ID:** SEC-001
- **Date:** 2026-03-15
- **Agent:** R1 (Crypto Agent)
- **File:** `crates/mpc-wallet-core/src/protocol/gg20.rs:231-237`
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
- **Status:** Open

---

## [CRITICAL] SEC-002: Hardcoded Fallback Password "demo-password" in Production CLI

- **ID:** SEC-002
- **Date:** 2026-03-15
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
- **Status:** Open

---

## [CRITICAL] SEC-003: NatsTransport Is Entirely Unimplemented (todo!() Stubs)

- **ID:** SEC-003
- **Date:** 2026-03-15
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
- **Status:** Open

---

## [MEDIUM] SEC-011: Sui Transaction Serialization Uses JSON Instead of BCS

- **ID:** SEC-011
- **Date:** 2026-03-15
- **Agent:** R3d (Chain Agent — Sui)
- **File:** `crates/mpc-wallet-chains/src/sui/tx.rs:63-76`
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
- **Status:** Open (tracked by R3d — known TODO)

---

## [MEDIUM] SEC-012: EVM Transaction Finalization Does Not Enforce Low-S ECDSA Normalization

- **ID:** SEC-012
- **Date:** 2026-03-15
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
