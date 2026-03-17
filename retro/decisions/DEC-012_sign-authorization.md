# DEC-012: Sign Authorization — MPC Node Independent Verification

- **Date:** 2026-03-17
- **Status:** Decided + Implemented (core module)
- **Context:** Gateway is a single point of trust for sign requests. If compromised, attacker can sign any transaction because MPC nodes blindly trust the gateway.

## Decision

Add `SignAuthorization` — a signed proof that the gateway produces after auth + policy + approvals.
Each MPC node independently verifies this proof before participating in signing.

## Key Design Choices

1. **Ed25519 signature** over authorization payload — binds requester, message, policy, and approvals
2. **Message hash binding** — authorization is valid only for the specific message
3. **2-minute TTL** — prevents replay of old authorizations
4. **Gateway pubkey pinning** — each MPC node knows the expected gateway pubkey at startup
5. **Approval evidence included** — node can verify quorum was met without trusting gateway

## What It Doesn't Solve (Remaining Trust)

- If attacker has the gateway's Ed25519 signing key, they can forge authorizations
- Solution: keep signing key in HSM / secure enclave
- Clock drift between gateway and MPC nodes must be < 2 minutes

## Consequences

- MPC nodes need `GATEWAY_PUBKEY` configured at startup
- Sign request flow adds ~1ms overhead for Ed25519 verify
- Gateway must produce `SignAuthorization` before every sign request
- Breaking change: MPC nodes refuse to sign without valid authorization
