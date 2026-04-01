# MPC Wallet SDK — Performance Benchmarks

> Baseline: 2026-04-01 | Machine: macOS Darwin 24.5.0 | Rust: 1.93.1
> Run: `cargo bench --workspace --features local-transport`

## Protocol Benchmarks (2-of-3 threshold, LocalTransport)

| Operation | Protocol | Time (median) |
|-----------|----------|---------------|
| **Keygen** | GG20 ECDSA | ~179 ms |
| **Keygen** | FROST Ed25519 | ~1.08 ms |
| **Keygen** | FROST Secp256k1-tr | ~1.05 ms |
| **Sign** | GG20 ECDSA (MtA) | ~47.4 ms |
| **Sign** | FROST Ed25519 | ~597 µs |
| **Sign** | FROST Secp256k1-tr | ~592 µs |

## Crypto Primitive Benchmarks

| Operation | Time (median) |
|-----------|---------------|
| ECDH X25519 key exchange | ~3.7 µs |
| HKDF-SHA256 derive | ~930 ns |
| ChaCha20-Poly1305 encrypt (1KB) | ~455 ns |
| ChaCha20-Poly1305 decrypt (1KB) | ~1.21 µs |
| Argon2id derive (64MiB/3t/4p) | ~24 µs |
| AES-256-GCM encrypt | ~230 ns |
| AES-256-GCM decrypt | ~584 ns |
| Signature verification | ~79 ns |

## Chain Simulation Benchmarks

| Operation | Time (median) |
|-----------|---------------|
| EVM simulate | ~27.6 ns |
| Bitcoin simulate | ~14.6 ns |
| Solana simulate | ~26.9 ns |

## Missing Protocols (TODO Sprint 33)

- CGGMP21 keygen/sign (expected: keygen ~10s due to Paillier, sign ~50ms)
- BLS12-381 keygen/sign
- Sr25519 keygen/sign
- Stark Threshold keygen/sign

## Notes

- GG20 keygen is ~179ms (includes Paillier keypair generation with cached 1024-bit test keys)
- FROST protocols are ~170x faster than GG20 for keygen, ~80x faster for signing
- All benchmarks use `LocalTransport` (in-memory, no network overhead)
- Production with NATS will add ~1-5ms per round trip
- Criterion reports: `target/criterion/` for HTML reports
