# Sign Authorization — Independent MPC Node Verification

## Problem

The API gateway is a **single point of trust** for sign requests. Currently:

```
Client → Gateway (auth + policy + approvals) → MPC Nodes (sign blindly)
```

If the gateway is compromised, an attacker can sign any transaction — MPC nodes have no way to
distinguish a legitimate sign request from a fraudulent one. This violates defense-in-depth:
the security of the entire system depends on a single component.

## Solution: Sign Authorization Proof

Each MPC node **independently verifies** a cryptographic proof before participating in signing.
The gateway must produce a `SignAuthorization` — an Ed25519-signed proof that:

1. **Who** — the requester was authenticated (user ID, roles)
2. **What** — which message is being signed and what policy was evaluated
3. **Policy** — the policy check passed
4. **Approvals** — the required quorum of approvals was collected
5. **When** — the authorization is fresh (< 2 minutes old)
6. **Binding** — the message hash in the proof matches the message being signed

```
┌──────────────────────┐       ┌──────────────────────────┐
│    API Gateway        │       │     MPC Node (Party i)   │
│                       │       │                          │
│ 1. Auth user          │       │ Receive SignAuthorization │
│ 2. Check policy       │       │                          │
│ 3. Collect approvals  │       │ Verify:                  │
│ 4. Create payload:    │       │ ✓ Gateway pubkey matches  │
│    - requester_id     │       │ ✓ Signature valid         │
│    - message_hash     │──────►│ ✓ Not expired (< 2 min)  │
│    - policy_passed    │       │ ✓ Message hash matches    │
│    - approval_count   │       │ ✓ Policy passed           │
│    - approvers[]      │       │ ✓ Approval quorum met     │
│ 5. Ed25519 sign       │       │                          │
│ 6. Send to MPC node   │       │ IF all pass → sign()     │
│                       │       │ IF any fail → refuse     │
└──────────────────────┘       └──────────────────────────┘
```

## Data Structures

### AuthorizationPayload

```rust
pub struct AuthorizationPayload {
    pub requester_id: String,       // Who requested (from AuthContext)
    pub wallet_id: String,          // Which wallet
    pub message_hash: String,       // SHA-256(message_to_sign), hex
    pub policy_hash: String,        // SHA-256(policy_config), hex
    pub policy_passed: bool,        // Did policy check pass?
    pub approval_count: u32,        // How many approvals collected
    pub approval_required: u32,     // How many required (quorum)
    pub approvers: Vec<ApproverEvidence>, // Evidence per approver
    pub timestamp: u64,             // UNIX seconds
    pub session_id: String,         // For correlation
}
```

### SignAuthorization

```rust
pub struct SignAuthorization {
    pub payload: AuthorizationPayload,
    pub gateway_signature: Vec<u8>,  // Ed25519 sig over SHA-256(payload)
    pub gateway_pubkey: Vec<u8>,     // 32-byte Ed25519 pubkey
}
```

## Verification at MPC Node

Each MPC node must:

1. **Know the expected gateway pubkey** — configured at startup (from `GATEWAY_PUBKEY` env or file)
2. **Receive a `SignAuthorization`** alongside the sign request
3. **Call `authorization.verify(expected_pubkey, message)`** before calling `sign()`
4. **Refuse to sign** if verification fails

### What Each Check Prevents

| Check | Attack Prevented |
|-------|-----------------|
| Gateway pubkey match | Rogue gateway impersonation |
| Ed25519 signature valid | Payload tampering after signing |
| Timestamp fresh (< 2 min) | Replay of old authorizations |
| Message hash matches | Message substitution (sign wrong tx) |
| Policy passed | Bypassing policy engine |
| Approval quorum met | Bypassing approval workflow |

## Security Analysis

### Attacks This Prevents

**Compromised Gateway:**
- Attacker controls gateway but doesn't have the gateway's Ed25519 signing key
- Cannot forge `SignAuthorization` → MPC nodes refuse
- **Mitigation:** Keep `SERVER_SIGNING_KEY` in HSM or separate secure storage

**Rogue Gateway:**
- Attacker spins up a fake gateway
- MPC nodes verify gateway pubkey against expected value → reject
- **Mitigation:** Each MPC node has the legitimate gateway's pubkey pre-configured

**Replay Attack:**
- Attacker captures a valid `SignAuthorization` and replays it
- `timestamp` check rejects authorizations older than 2 minutes
- `message_hash` binding means replayed auth can only sign the same message
- **Mitigation:** 2-minute TTL + message binding

**Message Substitution:**
- Attacker has valid authorization for message A, tries to sign message B
- `message_hash` mismatch → MPC node refuses
- **Mitigation:** Authorization is bound to the specific message

### Remaining Trust Assumptions

- **Gateway signing key must be secure.** If attacker gets the gateway's Ed25519 key, they can forge authorizations. Use HSM or secure enclave for this key.
- **MPC node must know the correct gateway pubkey.** Configured at startup, not dynamic.
- **Clock synchronization** between gateway and MPC nodes (within 2 minutes).

## Integration Points

### Gateway Side (produces authorization)

```rust
// After auth + policy + approvals succeed:
let payload = AuthorizationPayload {
    requester_id: ctx.user_id.clone(),
    wallet_id: wallet_id.clone(),
    message_hash: hex::encode(Sha256::digest(&message)),
    policy_hash: hex::encode(policy_store.current_hash()),
    policy_passed: true,
    approval_count: approvals.len() as u32,
    approval_required: required_approvals,
    approvers: approvals.iter().map(|a| ApproverEvidence { ... }).collect(),
    timestamp: unix_now(),
    session_id: session_id.clone(),
};
let authorization = SignAuthorization::create(payload, &server_signing_key);

// Send authorization + message to MPC nodes
```

### MPC Node Side (verifies authorization)

```rust
// Before calling protocol.sign():
let expected_gateway_pubkey = load_gateway_pubkey(); // from config
authorization.verify(&expected_gateway_pubkey, &message)?;

// Only after verification succeeds:
let signature = protocol.sign(&key_share, &signers, &message, &transport).await?;
```

## Implementation

**File:** `crates/mpc-wallet-core/src/protocol/sign_authorization.rs`

- `SignAuthorization::create()` — gateway creates signed proof
- `SignAuthorization::verify()` — MPC node verifies before signing
- 9 unit tests covering: valid auth, wrong key, tampered payload, wrong message, expired, policy fail, insufficient approvals, forged signature, zero approvals
