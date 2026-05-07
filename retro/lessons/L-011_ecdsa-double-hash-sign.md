# L-011: GG20/CGGMP21 sign() double-hashed the message

- **Date:** 2026-05-07
- **Category:** Cryptographic correctness
- **Severity:** Critical (silent — produced syntactically valid signatures over the wrong hash)
- **Found by:** Live Sepolia broadcast — geth recovered a sender with 0 wei despite the wallet having 0.11 ETH

## What happened

`Gg20Protocol::sign` and `Cggmp21Protocol::sign` both started with:

```rust
let hash_bytes = sha2::Sha256::digest(message);
let m_scalar = Scalar::reduce_bytes(&hash_bytes);
```

The chain provider passed `keccak256(rlp_tx)` (a 32-byte EIP-1559 signing hash) as `message`. The protocol then SHA-256-ed it again, signing `SHA256(keccak256(rlp_tx))` instead of `keccak256(rlp_tx)`.

Result on Sepolia: signature was valid, but `ecrecover` on the encoded envelope yielded a **random** address (the one that, by accident, signs the double-hashed value with this particular `r,s,v`). Geth saw "from = 0xRANDOM" with 0 wei → "insufficient funds".

The bug also explains why pre-broadcast `recover_signer()` mismatched the wallet's derived address. We added that check **as a diagnostic** while debugging this — and it caught the bug definitively.

## Root cause

`MpcProtocol::sign(message: &[u8], …)` had no documented contract for whether `message` is a raw payload (caller wants the protocol to hash it) or a 32-byte prehash (caller has already hashed). For Ed25519 (FROST), the contract is "raw message, protocol hashes internally" — that's what Ed25519 specifies. For ECDSA, the convention is the opposite: the caller hashes with the chain-native function (keccak256 for EVM, double-SHA-256 for Bitcoin), and the protocol signs the prehash directly.

Our two ECDSA protocols silently followed the Ed25519 convention.

## Fix

Both `gg20.rs` and `cggmp21.rs`: detect 32-byte input and treat as prehash:

```rust
let hash_bytes: [u8; 32] = if message.len() == 32 {
    let mut h = [0u8; 32];
    h.copy_from_slice(message);
    h
} else {
    Sha256::digest(message).into()
};
```

This preserves the legacy "auto-hash" behavior for callers that pass raw bytes, while making the protocol Ethereum-correct when it gets a prehash.

## Trade-offs

The `len == 32` heuristic is fragile: two CGGMP21 unit tests had message literals that were exactly 32 bytes long — they broke because the test verifier hashed the message but the protocol no longer did. Lengthened the test literals as a stop-gap.

The right long-term fix is an API split: `MpcProtocol::sign_prehash(prehash: [u8; 32], …)` for ECDSA callers vs `sign_message(msg: &[u8], …)` for Ed25519/FROST. Filed as a Sprint 40 follow-up.

## Takeaway

**Treat ECDSA "what to hash" as a public contract**, not a hidden detail. When a protocol takes `&[u8]`, document whether it hashes. Better: take a typed `Prehash([u8; 32])` so the type system enforces it.

When debugging a "valid sig that recovers wrong address", suspect double-hashing **first** before suspecting `recovery_id` or curve issues.

A pre-broadcast `recover_and_compare(sender)` check is non-negotiable for any production EVM signing flow — it converts a silent failure into a loud one.
