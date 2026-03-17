# L-001: GG20 Trusted-Dealer = Not Real MPC

- **Date:** 2026-03-15
- **Category:** Security
- **Severity:** Critical
- **Found by:** R6 during initial security audit
- **Related finding:** SEC-001

## What happened

The initial GG20 implementation used a trusted-dealer model. During `sign()`, every participating party called `lagrange_interpolate()` on all collected shares — reconstructing the **full private key** in memory. This completely negates the MPC security guarantee.

## Root cause

The implementation prioritized getting a working signing flow quickly. Lagrange interpolation was the simplest path but violated the fundamental MPC property: no single party should ever hold the complete key.

## Fix

Sprint 2 (DEC-004): Replaced with distributed additive-share signing. No party ever reconstructs the full key. The signing protocol now operates on partial shares and combines only the final signature components.

## Takeaway

"Working" is not "secure." When implementing MPC protocols, always verify the core security invariant (no full key reconstruction) before declaring the feature complete. Add an assertion or test that no single memory space contains the full private key material.
