# L-003: ProtocolMessage.from Unauthenticated

- **Date:** 2026-03-15
- **Category:** Security
- **Severity:** High
- **Found by:** R6 during Sprint 5 audit
- **Related finding:** SEC-007

## What happened

`ProtocolMessage` had a `from` field that was self-reported by the sender. Any party could claim to be any other party. The NATS transport layer accepted messages without verifying the sender's identity.

## Root cause

The initial transport was a stub (`todo!()` everywhere). When real NATS was implemented in Sprint 3, message authentication was not added — the focus was on "make it work" rather than "make it secure."

## Fix

Sprint 6: Implemented `SignedEnvelope` — every message is Ed25519 signed with the sender's key. `NatsTransport` maintains a peer key registry and verifies signatures + monotonic sequence numbers on every recv(). Replay protection via seq_no.

## Takeaway

Transport-layer authentication must be part of the initial implementation, not bolted on later. Self-reported identity fields are never trustworthy. Always sign messages with the sender's key and verify on receipt.
