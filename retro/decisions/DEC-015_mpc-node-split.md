# DEC-015: Split MPC Nodes from Gateway — True Distributed Architecture

- **Date:** 2026-03-18
- **Status:** Proposed
- **Context:** WalletStore holds ALL key shares in gateway memory — violates core MPC principle ("no single point holds the complete key")

## Problem

Current `WalletStore` stores `Vec<KeyShare>` (all parties' shares) in a single gateway process. If gateway is compromised, attacker has all shares and can reconstruct the full private key. This defeats the purpose of MPC.

## Decision

Split into proper distributed architecture:

```
API Gateway (orchestrator only — NO shares)
    │
    │ NATS (signed envelopes)
    │
    ├── MPC Node 1 (holds share 1 only, EncryptedFileStore)
    ├── MPC Node 2 (holds share 2 only, EncryptedFileStore)
    └── MPC Node 3 (holds share 3 only, EncryptedFileStore)
```

## Implementation Phases

### Phase A: MPC Node Service (new crate)
- `services/mpc-node/` — standalone binary
- Connects to NATS, listens for keygen/sign requests
- Holds exactly 1 party's share via `KeyStore` trait
- Verifies `SignAuthorization` before signing

### Phase B: NATS RPC Protocol
- Define request/response messages for keygen/sign/freeze
- Gateway publishes requests, nodes subscribe and respond
- Control channel: `mpc.control.{group_id}`
- Protocol channel: `mpc.{session_id}.party.{party_id}` (existing)

### Phase C: Gateway Refactor
- Remove `WalletStore` (no more shares in gateway)
- Gateway becomes pure orchestrator:
  - Sends keygen request → waits for nodes to report completion
  - Sends sign request with `SignAuthorization` → collects signature from coordinator
  - Stores only metadata (group_id, label, scheme, group_pubkey) — NOT shares

### Phase D: Integration Testing
- Docker compose: 3 real node processes + NATS + gateway
- E2E: create wallet → 3 nodes keygen → sign → verify
- Prove: no single process holds more than 1 share

## Consequences

- **Security:** Proper MPC isolation — compromise of 1 node reveals only 1 share
- **Complexity:** New binary, NATS RPC protocol, distributed coordination
- **Operations:** Must deploy and manage N node processes
- **Testing:** E2E tests require real multi-process setup
