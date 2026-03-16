# Standards & References

Cryptographic standards, protocols, and specifications implemented in Vaultex.

---

## MPC Protocols

| Standard | Description | Usage |
|----------|-------------|-------|
| [GG20/CGGMP](https://eprint.iacr.org/2020/540) | Threshold ECDSA with additive shares | Distributed secp256k1 signing — full key never assembled |
| [FROST (RFC 9591)](https://www.rfc-editor.org/rfc/rfc9591.html) | Flexible Round-Optimized Schnorr Threshold Signatures | DKG + threshold signing for Ed25519 and Secp256k1 |
| [Feldman VSS](https://www.cs.umd.edu/~gasarch/TOPICS/secretsharing/feldmanVSS.pdf) | Verifiable Secret Sharing | Key refresh polynomial commitment verification |
| [Shamir Secret Sharing](https://dl.acm.org/doi/10.1145/359168.359176) | Threshold secret splitting | Underlying share distribution for GG20 keygen |

## Elliptic Curve Cryptography

| Standard | Description | Usage |
|----------|-------------|-------|
| **secp256k1** ([SEC 2](https://www.secg.org/sec2-v2.pdf)) | 256-bit Koblitz curve | EVM ECDSA + Bitcoin Schnorr |
| **Ed25519** ([RFC 8032](https://www.rfc-editor.org/rfc/rfc8032.html)) | Edwards-Curve Digital Signature | Solana, Sui signing + audit signatures + SignedEnvelope |
| **X25519** ([RFC 7748](https://www.rfc-editor.org/rfc/rfc7748.html)) | Curve25519 Diffie-Hellman | Per-session ECDH key exchange |
| **ECDSA** ([FIPS 186-5](https://csrc.nist.gov/publications/detail/fips/186/5/final)) | Elliptic Curve Digital Signature | EVM transaction signing |
| **BIP-340** ([Schnorr](https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki)) | Schnorr Signatures for secp256k1 | Bitcoin Taproot key-path spending |

## Encryption & Key Derivation

| Standard | Description | Usage |
|----------|-------------|-------|
| **AES-256-GCM** ([NIST SP 800-38D](https://csrc.nist.gov/publications/detail/sp/800-38d/final)) | Authenticated encryption | Key share encryption at rest |
| **ChaCha20-Poly1305** ([RFC 8439](https://www.rfc-editor.org/rfc/rfc8439.html)) | AEAD stream cipher | Per-session transport encryption |
| **Argon2id** ([RFC 9106](https://www.rfc-editor.org/rfc/rfc9106.html)) | Memory-hard password KDF | Password → AES key derivation (64MiB/3t/4p) |
| **HKDF-SHA256** ([RFC 5869](https://www.rfc-editor.org/rfc/rfc5869.html)) | HMAC-based KDF | Session key extraction from ECDH shared secret |

## Hash Functions

| Standard | Description | Usage |
|----------|-------------|-------|
| **SHA-256** ([FIPS 180-4](https://csrc.nist.gov/publications/detail/fips/180/4/final)) | Secure Hash | Audit ledger hash chain, envelope signing, tx fingerprint |
| **Keccak-256** (SHA-3 variant) | Ethereum hash | EVM address derivation from public key |
| **BLAKE2b-256** ([RFC 7693](https://www.rfc-editor.org/rfc/rfc7693.html)) | Fast hash | Sui intent-wrapped message digest |

## Ethereum Standards (EIPs)

| EIP | Name | Usage |
|-----|------|-------|
| [EIP-2](https://eips.ethereum.org/EIPS/eip-2) | Homestead — Low-S ECDSA | Auto-normalize `s > n/2` signatures (SEC-012 fix) |
| [EIP-55](https://eips.ethereum.org/EIPS/eip-55) | Mixed-case Checksum Encoding | EVM address validation |
| [EIP-1559](https://eips.ethereum.org/EIPS/eip-1559) | Fee Market Change | Dynamic gas pricing (base_fee, priority_fee) |
| [EIP-2930](https://eips.ethereum.org/EIPS/eip-2930) | Access List Tx Type | Supported via alloy SDK |

## Bitcoin Standards (BIPs)

| BIP | Name | Usage |
|-----|------|-------|
| [BIP-340](https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki) | Schnorr Signatures | 64-byte Schnorr signatures via FROST |
| [BIP-341](https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki) | Taproot (SegWit v1) | Key-path spending with `OP_1 <x-only-pubkey>` |
| [BIP-350](https://github.com/bitcoin/bips/blob/master/bip-0350.mediawiki) | Bech32m | Taproot address encoding (`bc1p...`) |

## Solana Standards

| Spec | Description | Usage |
|------|-------------|-------|
| [Transaction Format](https://solana.com/docs/core/transactions) | Legacy + v0 versioned | Binary message serialization with compact-u16 |
| [Address Lookup Tables](https://solana.com/docs/advanced/lookup-tables) | v0 ALT compression | Account index indirection (version prefix `0x80`) |
| [Ed25519 Signing](https://solana.com/docs/core/transactions#signatures) | Transaction signatures | Base58 signature = transaction ID |

## Sui Standards

| Spec | Description | Usage |
|------|-------------|-------|
| [BCS Encoding](https://docs.sui.io/concepts/sui-move-concepts/packages/bcs) | Binary Canonical Serialization | Transaction payload encoding |
| [Intent Signing](https://docs.sui.io/concepts/cryptography/transaction-auth/intent-signing) | Intent-prefixed signing | `Blake2b-256([0x00, 0x00, 0x00] \|\| bcs_bytes)` |
| [Ed25519 Signature](https://docs.sui.io/concepts/cryptography) | Signature wire format | `[0x00] \|\| sig(64) \|\| pubkey(32)` = 97 bytes |

## Transport & Identity

| Standard | Description | Usage |
|----------|-------------|-------|
| **TLS 1.2+** ([RFC 5246](https://www.rfc-editor.org/rfc/rfc5246.html) / [RFC 8446](https://www.rfc-editor.org/rfc/rfc8446.html)) | Transport security | mTLS via rustls for NATS connections |
| **X.509** ([RFC 5280](https://www.rfc-editor.org/rfc/rfc5280.html)) | Certificate format | CA cert, client cert, client key in PEM |
| **JWT** ([RFC 7519](https://www.rfc-editor.org/rfc/rfc7519.html)) | JSON Web Token | RBAC authentication with RS256/ES256/HS256 |
| **NATS** ([nats.io](https://nats.io/)) | Cloud-native messaging | Inter-party MPC protocol transport |
| **JetStream** ([nats.io/jetstream](https://docs.nats.io/nats-concepts/jetstream)) | Persistent messaging | Durable message streams + per-party ACL |

## Security Guidelines

| Standard | Description | Usage |
|----------|-------------|-------|
| [OWASP Key Management](https://cheatsheetseries.owasp.org/cheatsheets/Key_Management_Cheat_Sheet.html) | Key handling best practices | Argon2id params, zeroization, key rotation |
| [NIST SP 800-57](https://csrc.nist.gov/publications/detail/sp/800-57-part-1/rev-5/final) | Key Management Recommendations | Key lifecycle: generate, refresh, reshare, freeze, destroy |
| [CWE-316](https://cwe.mitre.org/data/definitions/316.html) | Cleartext Storage in Memory | Mitigated via `Zeroizing<Vec<u8>>` on all key material |
