# Standards & References

Cryptographic standards, protocols, and specifications implemented in Vaultex.

---

## MPC Protocols

| Standard | Authors / Origin | Description | Usage |
|----------|-----------------|-------------|-------|
| [GG20](https://eprint.iacr.org/2020/540) | Rosario Gennaro, Steven Goldfeder (City College of New York, Cornell Tech, 2020) | Threshold ECDSA with additive shares | Distributed secp256k1 signing — full key never assembled |
| [CGGMP21](https://eprint.iacr.org/2021/060) | Ran Canetti, Rosario Gennaro, Steven Goldfeder, Nikolaos Makriyannis, Udi Peled (2021) | UC-secure threshold ECDSA | Extended GG20 protocol basis |
| [FROST (RFC 9591)](https://www.rfc-editor.org/rfc/rfc9591.html) | Chelsea Komlo, Ian Goldberg (University of Waterloo, 2020); IETF standardized 2024 | Flexible Round-Optimized Schnorr Threshold Signatures | DKG + threshold signing for Ed25519 and Secp256k1 |
| [Feldman VSS](https://www.cs.umd.edu/~gasarch/TOPICS/secretsharing/feldmanVSS.pdf) | Paul Feldman (MIT, 1987) | Verifiable Secret Sharing via polynomial commitments | Key refresh commitment verification |
| [Shamir Secret Sharing](https://dl.acm.org/doi/10.1145/359168.359176) | Adi Shamir (Weizmann Institute, 1979) | (k,n) threshold secret splitting | Underlying share distribution for GG20 keygen |

## Elliptic Curve Cryptography

| Standard | Authors / Origin | Description | Usage |
|----------|-----------------|-------------|-------|
| **secp256k1** ([SEC 2](https://www.secg.org/sec2-v2.pdf)) | Certicom Research (now Blackberry), standardized by SECG | 256-bit Koblitz curve over F_p | EVM ECDSA + Bitcoin Schnorr |
| **Curve25519 / Ed25519** ([RFC 8032](https://www.rfc-editor.org/rfc/rfc8032.html)) | Daniel J. Bernstein (University of Illinois Chicago, 2006); IETF RFC by S. Josefsson & I. Liusvaara | Edwards-Curve Digital Signature Algorithm | Solana, Sui, audit signatures, SignedEnvelope |
| **X25519** ([RFC 7748](https://www.rfc-editor.org/rfc/rfc7748.html)) | Daniel J. Bernstein; IETF RFC by A. Langley, M. Hamburg, S. Turner | Curve25519 Diffie-Hellman key agreement | Per-session ECDH key exchange |
| **ECDSA** ([FIPS 186-5](https://csrc.nist.gov/publications/detail/fips/186/5/final)) | NIST (National Institute of Standards and Technology, U.S.) | Elliptic Curve Digital Signature Algorithm | EVM transaction signing |
| **Schnorr** ([BIP-340](https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki)) | Claus-Peter Schnorr (Goethe University Frankfurt, 1989); BIP by Pieter Wuille, Jonas Nick, Tim Ruffing (Blockstream) | Schnorr Signatures for secp256k1 | Bitcoin Taproot key-path spending |

## Encryption & Key Derivation

| Standard | Authors / Origin | Description | Usage |
|----------|-----------------|-------------|-------|
| **AES-256-GCM** ([NIST SP 800-38D](https://csrc.nist.gov/publications/detail/sp/800-38d/final)) | Joan Daemen, Vincent Rijmen (KU Leuven, 1998); GCM by David McGrew, John Viega | Authenticated encryption with associated data | Key share encryption at rest |
| **ChaCha20-Poly1305** ([RFC 8439](https://www.rfc-editor.org/rfc/rfc8439.html)) | Daniel J. Bernstein (ChaCha20, 2008); Poly1305 MAC by Bernstein; IETF RFC by Y. Nir, A. Langley | AEAD stream cipher | Per-session transport payload encryption |
| **Argon2id** ([RFC 9106](https://www.rfc-editor.org/rfc/rfc9106.html)) | Alex Biryukov, Daniel Dinu, Dmitry Khovratovich (University of Luxembourg, 2015); Winner of Password Hashing Competition (PHC) | Memory-hard password-based KDF | Password to AES key derivation (64MiB / 3 iterations / 4 parallelism) |
| **HKDF** ([RFC 5869](https://www.rfc-editor.org/rfc/rfc5869.html)) | Hugo Krawczyk (IBM Research), Pasi Eronen (Nokia) | HMAC-based Extract-and-Expand KDF | Session key derivation from X25519 ECDH shared secret |

## Hash Functions

| Standard | Authors / Origin | Description | Usage |
|----------|-----------------|-------------|-------|
| **SHA-256** ([FIPS 180-4](https://csrc.nist.gov/publications/detail/fips/180/4/final)) | NSA, standardized by NIST (2001) | Secure Hash Algorithm, 256-bit | Audit ledger hash chain, SignedEnvelope, tx fingerprint |
| **Keccak-256** | Guido Bertoni, Joan Daemen, Michael Peeters, Gilles Van Assche (STMicroelectronics, KU Leuven); SHA-3 winner (2012) | Sponge-based hash (Ethereum variant, not NIST SHA-3) | EVM address derivation: `Keccak256(pubkey)[12:]` |
| **BLAKE2b** ([RFC 7693](https://www.rfc-editor.org/rfc/rfc7693.html)) | Jean-Philippe Aumasson, Samuel Neves, Zooko Wilcox-O'Hearn, Christian Winnerlein (2012) | High-speed cryptographic hash | Sui intent-wrapped message digest |

## Ethereum Standards (EIPs)

| EIP | Authors | Name | Usage |
|-----|---------|------|-------|
| [EIP-2](https://eips.ethereum.org/EIPS/eip-2) | Vitalik Buterin (Ethereum Foundation, 2015) | Homestead — Low-S ECDSA | Auto-normalize `s > n/2` (SEC-012 fix) |
| [EIP-55](https://eips.ethereum.org/EIPS/eip-55) | Vitalik Buterin, Alex Van de Sande (2016) | Mixed-case Address Checksum | EVM address validation |
| [EIP-1559](https://eips.ethereum.org/EIPS/eip-1559) | Vitalik Buterin, Eric Conner, Rick Dudley, Matthew Slipper, Ian Norden, Abdelhamid Bakhta (2019) | Fee Market Change | Dynamic gas: base_fee + priority_fee |
| [EIP-2930](https://eips.ethereum.org/EIPS/eip-2930) | Vitalik Buterin, Martin Swende (2020) | Optional Access Lists | Supported via alloy SDK |

## Bitcoin Standards (BIPs)

| BIP | Authors | Name | Usage |
|-----|---------|------|-------|
| [BIP-340](https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki) | Pieter Wuille, Jonas Nick, Tim Ruffing (Blockstream) | Schnorr Signatures for secp256k1 | 64-byte Schnorr via FROST |
| [BIP-341](https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki) | Pieter Wuille, Jonas Nick, Anthony Towns | Taproot: SegWit version 1 | Key-path spend: `OP_1 <x-only-pubkey>` |
| [BIP-350](https://github.com/bitcoin/bips/blob/master/bip-0350.mediawiki) | Pieter Wuille (Blockstream) | Bech32m Address Encoding | Taproot address format: `bc1p...` |

## Solana Standards

| Spec | Origin | Description | Usage |
|------|--------|-------------|-------|
| [Transaction Format](https://solana.com/docs/core/transactions) | Solana Labs / Solana Foundation | Legacy + v0 versioned messages | Binary serialization with compact-u16 encoding |
| [Address Lookup Tables](https://solana.com/docs/advanced/lookup-tables) | Solana Labs (introduced v1.11) | v0 transaction account compression | Index indirection, version prefix `0x80` |
| [Ed25519 Program](https://solana.com/docs/core/transactions#signatures) | Solana Labs | Native Ed25519 signature verification | Base58-encoded signature = transaction ID |

## Sui Standards

| Spec | Origin | Description | Usage |
|------|--------|-------------|-------|
| [BCS Encoding](https://docs.sui.io/concepts/sui-move-concepts/packages/bcs) | Diem/Libra team (originally Facebook/Meta); adopted by Mysten Labs for Sui | Binary Canonical Serialization | Deterministic transaction payload encoding |
| [Intent Signing](https://docs.sui.io/concepts/cryptography/transaction-auth/intent-signing) | Mysten Labs | Domain-separated signing with intent prefix | `Blake2b-256([0x00, 0x00, 0x00] \|\| bcs_bytes)` |
| [Signature Scheme](https://docs.sui.io/concepts/cryptography) | Mysten Labs | Ed25519 wire format | `[flag:0x00] \|\| sig(64) \|\| pubkey(32)` = 97 bytes |

## Transport & Identity

| Standard | Authors / Origin | Description | Usage |
|----------|-----------------|-------------|-------|
| **TLS 1.3** ([RFC 8446](https://www.rfc-editor.org/rfc/rfc8446.html)) | Eric Rescorla (Mozilla, IETF); building on TLS 1.2 by Tim Dierks, Christopher Allen | Transport Layer Security | mTLS via rustls for NATS connections |
| **X.509** ([RFC 5280](https://www.rfc-editor.org/rfc/rfc5280.html)) | ITU-T, IETF (originally Taher Elgamal et al.) | Public Key Infrastructure certificates | CA cert + client cert for mutual authentication |
| **JWT** ([RFC 7519](https://www.rfc-editor.org/rfc/rfc7519.html)) | Michael Jones (Microsoft), John Bradley (Ping Identity), Nat Sakimura (NRI, 2015) | JSON Web Token | RBAC/ABAC authentication: RS256, ES256, HS256 |
| **NATS** ([nats.io](https://nats.io/)) | Derek Collison (Synadia, originally Apcera, 2010) | Cloud-native messaging system | Inter-party MPC protocol transport |
| **JetStream** ([docs](https://docs.nats.io/nats-concepts/jetstream)) | Synadia / NATS maintainers | Persistent streaming over NATS | Durable message streams + per-party subject ACL |

## Rust Cryptography Libraries

| Crate | Maintainers | Standard Implemented |
|-------|-------------|---------------------|
| [`frost-core`](https://crates.io/crates/frost-core) | Zcash Foundation (Chelsea Komlo et al.) | FROST RFC 9591 |
| [`k256`](https://crates.io/crates/k256) | RustCrypto team (Tony Arcieri et al.) | secp256k1, ECDSA |
| [`ed25519-dalek`](https://crates.io/crates/ed25519-dalek) | Isis Agora Lovecruft, Henry de Valence (originally dalek-cryptography) | Ed25519 (RFC 8032) |
| [`x25519-dalek`](https://crates.io/crates/x25519-dalek) | dalek-cryptography team | X25519 (RFC 7748) |
| [`aes-gcm`](https://crates.io/crates/aes-gcm) | RustCrypto team | AES-256-GCM (NIST SP 800-38D) |
| [`chacha20poly1305`](https://crates.io/crates/chacha20poly1305) | RustCrypto team | ChaCha20-Poly1305 (RFC 8439) |
| [`argon2`](https://crates.io/crates/argon2) | RustCrypto team | Argon2id (RFC 9106) |
| [`hkdf`](https://crates.io/crates/hkdf) | RustCrypto team | HKDF (RFC 5869) |
| [`rustls`](https://crates.io/crates/rustls) | Joseph Birr-Pixton, Dirkjan Ochtman (rustls team) | TLS 1.2/1.3 (RFC 8446) |
| [`alloy`](https://crates.io/crates/alloy) | Alloy contributors (Paradigm) | EVM RPC + tx types |
| [`bitcoin`](https://crates.io/crates/bitcoin) | rust-bitcoin contributors (Andrew Poelstra et al.) | Bitcoin consensus, BIP-340/341 |

---

## Security Practices We Follow

### Key Management — [NIST SP 800-57](https://csrc.nist.gov/publications/detail/sp/800-57-part-1/rev-5/final)

We follow NIST's key management lifecycle recommendations:

| NIST Phase | Vaultex Implementation |
|------------|----------------------|
| **Generation** | Distributed keygen — no single party sees the full key (GG20/FROST DKG) |
| **Storage** | AES-256-GCM at rest with Argon2id-derived keys; `Zeroizing<Vec<u8>>` in memory |
| **Distribution** | Key shares distributed via authenticated transport (SignedEnvelope + mTLS) |
| **Usage** | Threshold signing only — t-of-n parties compute partial signatures |
| **Rotation** | Proactive key refresh re-randomizes shares without changing the public key |
| **Revocation** | Key freeze/unfreeze; reshare to exclude compromised parties |
| **Destruction** | `ZeroizeOnDrop` ensures share bytes are wiped when dropped from memory |

### Password Handling — [OWASP Password Storage](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)

| OWASP Recommendation | Vaultex Implementation |
|----------------------|----------------------|
| Use Argon2id | Argon2id with 64 MiB memory, 3 iterations, 4 parallelism lanes |
| Use random salt | 32-byte cryptographically random salt per key file |
| Zeroize password after use | Password wrapped in `Zeroizing<String>` (SEC-005) |
| Never store plaintext passwords | Only Argon2id hash + AES ciphertext stored on disk |

### Memory Safety — [CWE-316](https://cwe.mitre.org/data/definitions/316.html) / [CWE-244](https://cwe.mitre.org/data/definitions/244.html)

| Weakness | Mitigation |
|----------|-----------|
| CWE-316: Cleartext storage of sensitive info in memory | All `KeyShare.share_data` uses `Zeroizing<Vec<u8>>` — wiped on drop |
| CWE-244: Improper clearing of heap memory | `ZeroizeOnDrop` derived on all internal share structs |
| CWE-200: Information exposure via Debug | Manual `Debug` impl on `KeyShare` prints `[REDACTED]` instead of share bytes (SEC-015) |

### Transport Security — Defense in Depth

Three independent protection layers, any one of which prevents eavesdropping:

| Layer | Standard | What it Protects |
|-------|----------|-----------------|
| **Layer 1: TLS** | mTLS (RFC 8446) via rustls | Network-level encryption + mutual authentication |
| **Layer 2: ECDH** | X25519 + ChaCha20-Poly1305 (RFC 8439) | Per-session application-level encryption |
| **Layer 3: Signature** | Ed25519 SignedEnvelope (RFC 8032) | Message authentication + replay protection (seq_no + TTL) |

Even if TLS is compromised (e.g., CA breach), Layer 2 ECDH still protects message confidentiality. Even if both TLS and ECDH are compromised, Layer 3 signatures prevent message forgery.

### Audit Trail — Tamper-Evident Logging

| Practice | Implementation |
|----------|---------------|
| **Append-only ledger** | Hash-chained entries — modifying any entry breaks all subsequent hashes |
| **Non-repudiation** | Each entry signed with Ed25519 service key |
| **Evidence export** | JSON evidence pack with verifying key for offline verification |
| **WORM readiness** | `WormStorageConfig` supports S3 Object Lock (compliance mode) |

### Threshold Security Model

| Property | Guarantee |
|----------|----------|
| **Key confidentiality** | Any `t-1` colluding parties learn nothing about the full key |
| **Signing liveness** | Any `t` honest parties can produce a valid signature |
| **No single point of failure** | Compromise of any single server reveals only one share |
| **Proactive security** | Key refresh periodically re-randomizes all shares |
| **Adaptive security** | Reshare can exclude a compromised party and change threshold |

---

## Academic References

1. Gennaro, R., & Goldfeder, S. (2020). *One Round Threshold ECDSA with Identifiable Abort.* Cryptology ePrint Archive, 2020/540.
2. Komlo, C., & Goldberg, I. (2020). *FROST: Flexible Round-Optimized Schnorr Threshold Signatures.* Selected Areas in Cryptography (SAC) 2020.
3. Shamir, A. (1979). *How to Share a Secret.* Communications of the ACM, 22(11), 612-613.
4. Feldman, P. (1987). *A Practical Scheme for Non-interactive Verifiable Secret Sharing.* FOCS 1987.
5. Bernstein, D. J. (2006). *Curve25519: New Diffie-Hellman Speed Records.* PKC 2006.
6. Biryukov, A., Dinu, D., & Khovratovich, D. (2016). *Argon2: New Generation of Memory-Hard Functions for Password Hashing.* IEEE EuroS&P 2016.
7. Krawczyk, H. (2010). *Cryptographic Extraction and Key Derivation: The HKDF Scheme.* CRYPTO 2010.
