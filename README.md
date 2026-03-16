<div align="center">
<pre>
 __   __  _______  __   __  __   _______  _______  __   __
|  | |  ||   _   ||  | |  ||  | |       ||       ||  |_|  |
|  |_|  ||  |_|  ||  | |  ||  | |_     _||    ___||       |
|       ||       ||  |_|  ||  |   |   |  |   |___ |       |
|       ||       ||       ||  |   |   |  |    ___| |     |
 |     | |   _   ||       ||  |   |   |  |   |___ |   _   |
  |___|  |__| |__||_______||__|   |___|  |_______||__| |__|

 __   __  _______  __   __  ______      ___   _  _______  __   __  _______
|  | |  ||       ||  | |  ||    _ |    |   | | ||       ||  | |  ||       |
|  |_|  ||   _   ||  | |  ||   | ||    |   |_| ||    ___||  |_|  ||  _____|
|       ||  | |  ||  |_|  ||   |_||_   |      _||   |___ |       || |_____
|_     _||  |_|  ||       ||    __  |   |     |_ |    ___||_     _||_____  |
  |   |  |       ||       ||   |  | |   |    _  ||   |___   |   |   _____| |
  |___|  |_______||_______||___|  |_|   |___| |_||_______|  |___|  |_______|

 ____   _         _         _  _           _           _            _
|    \ |_| ___  _| |_  ___ |_|| |__  _ _ _| |_  ___  _| |     /|  | |
|  |  || ||_ -||_   _||  _|| || '_ \| | ||_   _|| -_|| . |    _|_ |_|
|____/ |_||___/  |_|  |_|  |_||_.__/|___/  |_|  |___||___|   |_|  |_|

 _    _                _                                 _      _
| |  | |              | |                               | |    | |
| |  | | _ __   ___  _| |_  ___   _ __   _ __    __ _  | |__  | |  ___
| |  | || '_ \ / __|| '_  |/ _ \ | '_ \ | '_ \  / _` || '_ \ | | / _ \
| |__| || | | |\__ \| |_| || (_) || |_) || |_) || (_| || |_) || ||  __/
 \____/ |_| |_||___/ \____||\___/ | .__/ | .__/  \__,_||_.__/ |_| \___|
                                  |_|    |_|
</pre>
</div>

<p align="center">
  <strong>Threshold MPC Wallet SDK</strong> — No single party ever holds a complete private key.
  <br/>
  <sub>EVM | Bitcoin | Solana | Sui &mdash; 233 tests | 14 sprints | All epics complete</sub>
</p>

<p align="center">
  <a href="#quickstart">Quickstart</a> &bull;
  <a href="#architecture">Architecture</a> &bull;
  <a href="#features">Features</a> &bull;
  <a href="#contributing">Contributing</a> &bull;
  <a href="#security">Security</a>
</p>

---

## What is Vaultex?

Vaultex is a **Rust workspace** for building enterprise-grade **threshold multi-party computation (MPC) wallets**. The full private key is **never assembled** in memory — not during key generation, not during signing, not ever.

```
                    ┌─────────┐
                    │  Party 1 │ ← holds share s₁
                    └────┬────┘
                         │
   ┌─────────┐      ┌───┴───┐      ┌─────────┐
   │  Party 2 │──────│  NATS  │──────│  Party 3 │
   │  share s₂│      │  mTLS  │      │  share s₃│
   └─────────┘      └───┬───┘      └─────────┘
                         │
                    ┌────┴────┐
                    │ Signature│ ← valid ECDSA/Schnorr/EdDSA
                    │  (r, s)  │   full key x never computed
                    └─────────┘
```

**Why Vaultex?**

- **Zero single point of failure** — compromise 1 server, attacker gets nothing
- **Multi-chain** — EVM (ETH/Polygon/BSC), Bitcoin (Taproot), Solana, Sui
- **Enterprise controls** — RBAC, policy engine, approval workflows, audit trail
- **Proactive security** — key refresh rotates shares without changing addresses

---

## Quickstart

```bash
# Clone
git clone https://github.com/itoonx/rust-mpc-wallet.git
cd rust-mpc-wallet

# Build & test
cargo build --workspace
cargo test --workspace     # 233 tests, ~4 seconds

# Run CLI
cargo run -p mpc-wallet-cli -- --help
```

### CLI Commands

```bash
# Generate a distributed key (2-of-3 threshold)
mpc-wallet keygen --threshold 2 --parties 3

# Sign a transaction
mpc-wallet sign --group-id <id> --chain ethereum --to 0x... --value 1000000

# Simulate before signing (risk assessment)
mpc-wallet simulate --chain ethereum --to 0x... --value 1000000

# Verify audit trail integrity
mpc-wallet audit-verify --pack-file evidence.json

# List stored key groups
mpc-wallet list-keys

# Export chain address from key group
mpc-wallet export-address --group-id <id> --chain solana
```

---

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    mpc-wallet-cli                        │
│  keygen | sign | simulate | audit-verify | list-keys     │
└──────────────────────┬──────────────────────────────────┘
                       │
┌──────────────────────┴──────────────────────────────────┐
│                  mpc-wallet-chains                       │
│  ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐       │
│  │   EVM   │ │ Bitcoin │ │ Solana  │ │   Sui   │       │
│  │ EIP-1559│ │ Taproot │ │   v0    │ │  BCS    │       │
│  └────┬────┘ └────┬────┘ └────┬────┘ └────┬────┘       │
│       └──────┬─────┴──────────┴─────┬──────┘            │
│         ChainProvider trait    ChainRegistry              │
└──────────────────────┬──────────────────────────────────┘
                       │
┌──────────────────────┴──────────────────────────────────┐
│                  mpc-wallet-core                         │
│                                                          │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐              │
│  │ Protocol │  │Transport │  │ KeyStore │              │
│  │  GG20    │  │  NATS    │  │  AES-GCM │              │
│  │  FROST   │  │  mTLS    │  │  Argon2  │              │
│  │  Ed25519 │  │  ECDH    │  │  Zeroize │              │
│  └──────────┘  └──────────┘  └──────────┘              │
│                                                          │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐              │
│  │  Policy  │  │Approvals │  │  Audit   │              │
│  │ velocity │  │ quorum   │  │hashchain │              │
│  │ signed   │  │  SoD     │  │ Ed25519  │              │
│  │templates │  │  MFA     │  │   WORM   │              │
│  └──────────┘  └──────────┘  └──────────┘              │
│                                                          │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐              │
│  │ Identity │  │  RBAC    │  │   Ops    │              │
│  │   JWT    │  │ 3 roles  │  │ failover │              │
│  │  ABAC    │  │  guards  │  │  chaos   │              │
│  │   MFA    │  │          │  │   DR     │              │
│  └──────────┘  └──────────┘  └──────────┘              │
└─────────────────────────────────────────────────────────┘
```

### Core Traits (Plugin Boundaries)

| Trait | Purpose | Implementations |
|-------|---------|----------------|
| `MpcProtocol` | Distributed keygen, sign, refresh, reshare | GG20 ECDSA, FROST Ed25519, FROST Secp256k1-Taproot |
| `Transport` | Inter-party messaging | NATS (mTLS + ECDH + SignedEnvelope), Local (testing) |
| `KeyStore` | Encrypted share persistence | EncryptedFileStore (AES-256-GCM + Argon2id) |
| `ChainProvider` | Chain-specific tx building | EVM, Bitcoin, Solana, Sui |

---

## Features

### Cryptography

| Feature | Detail |
|---------|--------|
| **Distributed ECDSA (GG20)** | Additive shares — full key `x` never assembled |
| **FROST Ed25519** | Threshold EdDSA for Solana/Sui |
| **FROST Secp256k1** | Threshold Schnorr + Taproot tweaks for Bitcoin |
| **Key Refresh** | Re-randomize shares without changing on-chain address |
| **Key Resharing** | Change threshold (2-of-3 → 3-of-5) or add/remove parties |
| **Zeroization** | `Zeroizing<Vec<u8>>` on all key material, wiped on drop |

### Transport Security

| Layer | Protection |
|-------|-----------|
| **TLS** | mTLS with rustls — mutual certificate authentication |
| **ECDH** | Per-session X25519 + ChaCha20-Poly1305 — defense in depth |
| **SignedEnvelope** | Ed25519 signature + monotonic seq_no + TTL replay protection |
| **JetStream** | ACL per-party subject isolation |

### Enterprise Controls

| Feature | Detail |
|---------|--------|
| **RBAC** | 3 roles: `initiator`, `approver`, `admin` |
| **ABAC** | JWT attributes: `dept`, `cost_center`, `risk_tier` |
| **MFA** | Step-up enforcement for admin actions (policy, freeze, export) |
| **Policy Engine** | Allowlists, per-tx limits, daily velocity, signed bundles |
| **Policy Templates** | Exchange, Treasury, Custodian presets |
| **Approvals** | M-of-N quorum, maker/checker/approver SoD |
| **Audit Ledger** | Hash-chained, Ed25519 signed, evidence pack export |
| **Tx Simulation** | Pre-sign risk scoring for all 4 chains |

### Operations

| Feature | Detail |
|---------|--------|
| **Multi-cloud** | Node distribution constraints across providers/regions |
| **Quorum Risk** | Real-time assessment of signing availability |
| **RPC Failover** | Priority-based endpoint pool with health tracking |
| **Chaos Framework** | Kill party, network partition, message delay/corruption |
| **Disaster Recovery** | Recovery plan generation from node health data |

---

## Project Structure

```
crates/
  mpc-wallet-core/     ← Protocols, transport, key store, policy, identity
  mpc-wallet-chains/   ← Chain adapters: EVM, Bitcoin, Solana, Sui
  mpc-wallet-cli/      ← CLI binary (demo/testing)
docs/
  AGENTS.md            ← Agent roles & ownership map
  SPRINT.md            ← Sprint history & task specs
  SECURITY_FINDINGS.md ← Security audit trail
  PRD.md               ← Product requirements
  EPICS.md             ← Epic A-J breakdown
  DECISIONS.md         ← Decision log (DEC-001..009)
```

---

## Security

### Threat Model

Vaultex assumes **honest-but-curious** adversaries:

- Any `t-1` parties can collude without compromising the key
- The coordinator (Party 1 in GG20) holds the ephemeral nonce `k`
- Transport is authenticated (SignedEnvelope) and encrypted (ECDH + TLS)

### Resolved Findings

| Severity | Resolved | Open |
|----------|----------|------|
| CRITICAL | 4 | 0 |
| HIGH | 8 | 0 |
| MEDIUM/LOW | ~15 | Non-blocking |

All CRITICAL and HIGH findings have been resolved. See [`docs/SECURITY_FINDINGS.md`](docs/SECURITY_FINDINGS.md) for the full audit trail.

### Responsible Disclosure

Found a vulnerability? Please email the maintainer directly. Do **not** open a public issue for security bugs.

---

## Contributing

We welcome contributions from humans and LLMs alike.

### For Humans

```bash
# 1. Fork & clone
git clone https://github.com/<you>/rust-mpc-wallet.git
cd rust-mpc-wallet

# 2. Create a feature branch
git checkout -b feat/your-feature

# 3. Make changes & test
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all

# 4. Open a PR against `main`
```

### For LLMs / AI Agents

This project was built by a team of AI agents using Claude Code. If you're an LLM and want to contribute:

1. **Read `CLAUDE.md`** first — it's the shared agent memory with full project context
2. **Read `docs/AGENTS.md`** — find which files you're allowed to touch
3. **Read `LESSONS.md`** — learn from past bugs so you don't repeat them
4. **Follow the checkpoint commit rule:**
   ```
   [R{N}] checkpoint: {what changed} — tests pass
   ```
5. **Never** commit without `cargo test` passing first
6. **Never** modify files outside your owned list

### Agent Roles (for reference)

| Role | ID | Owns |
|------|----|------|
| Architect | R0 | traits, types, error, Cargo.toml |
| Crypto | R1 | protocol/*.rs |
| Infra | R2 | transport/, key_store/, audit/, ops/ |
| EVM | R3a | chains/evm/ |
| Bitcoin | R3b | chains/bitcoin/ |
| Solana | R3c | chains/solana/ |
| Sui | R3d | chains/sui/ |
| Service | R4 | services/, cli/, policy/, identity/, rbac/ |
| QA | R5 | tests/, .github/workflows/ |
| Security | R6 | docs/SECURITY*.md |
| PM | R7 | docs/PRD.md, EPICS.md, SPRINT.md |

### Good First Issues

Look for issues labeled `good-first-issue` or pick from:

- [ ] Add Avalanche C-Chain support (EVM-compatible, follow `evm/` pattern)
- [ ] Add Cosmos/IBC chain adapter
- [ ] Implement FROST Ed25519 reshare with group key preservation
- [ ] Add `--output json` flag to all CLI commands
- [ ] Write integration test with live NATS server
- [ ] Add Prometheus metrics export for quorum risk monitoring

### CI Requirements

All PRs must pass:

```
cargo fmt --all -- --check      # formatting
cargo clippy --workspace -- -D warnings  # lint
cargo test --workspace          # 233+ tests
cargo audit                     # security advisory check
```

---

## Metrics

```
┌─────────────────────────────────────────┐
│  Tests:     233 pass | 1 ignored        │
│  LOC:       13,800+ lines of Rust       │
│  Files:     61 source files             │
│  Sprints:   14 complete                 │
│  Commits:   165+                        │
│  Epics:     10/10 (100%)                │
│  CI:        fmt + clippy + test + audit │
│  Findings:  0 CRITICAL | 0 HIGH open   │
└─────────────────────────────────────────┘
```

---

## License

MIT

---

<p align="center">
  <sub>
    Built with <a href="https://claude.com/claude-code">Claude Code</a> by a team of AI agents.
    <br/>
    No keys were harmed in the making of this SDK.
  </sub>
</p>
