# DEC-001: Real GG20 vs Alternative ECDSA TSS Library

- **Date:** 2026-03-15
- **Status:** Decided
- **Context:** Initial GG20 implementation reconstructed full private key (SEC-001). Need genuinely distributed ECDSA signing.
- **Options:**
  1. `multi-party-ecdsa` (Zengo GG20/CGGMP21) — battle-tested, heavy deps
  2. FROST secp256k1-tr — already integrated, but Schnorr not ECDSA (fatal for EVM)
  3. `tss-lib` (Binance) — Go, not Rust
  4. Custom k256 two-round — semi-honest only, not production-safe
  5. Custom k256 distributed ECDSA — bridge solution while evaluating GG20
- **Decision:** Option 5 as bridge (Sprint 1), Option 1 as target (Sprint 2, see DEC-004)
- **Consequences:** Sprint 1 delivers semi-honest distributed signing. Sprint 2 locks GG20 integration as hard goal.
