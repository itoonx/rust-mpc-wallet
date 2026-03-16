# Vaultex CLI Guide

```
          ██╗   ██╗ █████╗ ██╗   ██╗██╗  ████████╗███████╗██╗  ██╗
          ██║   ██║██╔══██╗██║   ██║██║  ╚══██╔══╝██╔════╝╚██╗██╔╝
          ██║   ██║███████║██║   ██║██║     ██║   █████╗   ╚███╔╝
          ╚██╗ ██╔╝██╔══██║██║   ██║██║     ██║   ██╔══╝   ██╔██╗
           ╚████╔╝ ██║  ██║╚██████╔╝███████╗██║   ███████╗██╔╝ ██╗
            ╚═══╝  ╚═╝  ╚═╝ ╚═════╝ ╚══════╝╚═╝   ╚══════╝╚═╝  ╚═╝
```

Complete guide to the `mpc-wallet` command-line tool.

---

## Table of Contents

- [Setup](#setup)
- [Global Options](#global-options)
- [Commands](#commands)
  - [keygen](#keygen--generate-distributed-keys)
  - [sign](#sign--threshold-signing)
  - [export-address](#export-address--derive-chain-address)
  - [list-keys](#list-keys--show-stored-key-groups)
  - [simulate](#simulate--pre-sign-risk-assessment)
  - [audit-verify](#audit-verify--verify-audit-trail)
- [Output Formats](#output-formats)
- [Storage & Configuration](#storage--configuration)
- [Examples: Full Workflow](#examples-full-workflow)

---

## Setup

### Prerequisites

- **Rust toolchain** (1.75+ recommended)
- **cargo** (comes with Rust)

### Install from Source

```bash
# Clone the repository
git clone https://github.com/itoonx/vaultex-mpc-rust.git
cd vaultex-mpc-rust

# Build in release mode
cargo build --release

# The binary is at:
./target/release/mpc-wallet

# Or install system-wide:
cargo install --path crates/mpc-wallet-cli
```

### Verify Installation

```bash
$ mpc-wallet --version
mpc-wallet 0.1.0

$ mpc-wallet --help
MPC wallet CLI — threshold signatures for multi-chain

Usage: mpc-wallet [OPTIONS] <COMMAND>

Commands:
  keygen          Generate a new distributed key
  sign            Sign a message using MPC
  export-address  Export a chain-specific address from a key group
  list-keys       List stored key groups
  audit-verify    Verify an audit evidence pack file
  simulate        Simulate a transaction and assess risk

Options:
      --format <FORMAT>  Output format [default: text] [possible values: text, json]
  -v, --verbose          Enable verbose logging
  -h, --help             Print help
  -V, --version          Print version
```

---

## Global Options

These options work with **all** commands:

| Option | Values | Default | Description |
|--------|--------|---------|-------------|
| `--format` | `text`, `json` | `text` | Output format |
| `-v, --verbose` | - | off | Enable debug-level logging |
| `-h, --help` | - | - | Show help for command |

### Text Mode (default)

```
[success] Generated 2-of-3 gg20-ecdsa key group 'my-wallet'
{
  "group_id": "a1b2c3d4-e5f6-...",
  "scheme": "gg20-ecdsa",
  "threshold": 2,
  "total_parties": 3
}
```

### JSON Mode (`--format json`)

```json
{
  "status": "success",
  "message": "Generated 2-of-3 gg20-ecdsa key group 'my-wallet'",
  "data": {
    "group_id": "a1b2c3d4-e5f6-...",
    "scheme": "gg20-ecdsa",
    "threshold": 2,
    "total_parties": 3
  }
}
```

---

## Commands

### `keygen` — Generate Distributed Keys

Generate a new threshold key group. All parties run key generation locally (demo mode).

#### Usage

```bash
mpc-wallet keygen \
  --threshold <T> \
  --parties <N> \
  --scheme <SCHEME> \
  --label <LABEL> \
  [--password <PASSWORD>]
```

#### Arguments

| Argument | Required | Description |
|----------|----------|-------------|
| `-t, --threshold` | Yes | Minimum signers needed (e.g., `2` for 2-of-3) |
| `-n, --parties` | Yes | Total number of parties |
| `--scheme` | Yes | Crypto scheme (see below) |
| `--label` | Yes | Human-readable name for this key group |
| `--password` | No | Wallet password. If omitted, prompts interactively |

#### Supported Schemes

| Scheme | Value | Chains |
|--------|-------|--------|
| GG20 ECDSA | `gg20-ecdsa` | Ethereum, Polygon, BSC |
| FROST Schnorr | `frost-secp256k1-tr` | Bitcoin (Taproot) |
| FROST EdDSA | `frost-ed25519` | Solana, Sui |

#### Example

```bash
$ mpc-wallet keygen --threshold 2 --parties 3 --scheme gg20-ecdsa --label "hot-wallet"
Enter wallet password: ********

[success] Generated 2-of-3 gg20-ecdsa key group 'hot-wallet'
{
  "group_id": "f47ac10b-58cc-4372-a567-0e02b2c3d479",
  "scheme": "gg20-ecdsa",
  "threshold": 2,
  "total_parties": 3,
  "label": "hot-wallet"
}
```

#### What Happens Internally

1. Validates threshold <= parties
2. Creates N local transport channels
3. Spawns N concurrent key generation tasks
4. Each party generates its secret share — **full key is never assembled**
5. Encrypts each share with AES-256-GCM (key derived via Argon2id: 64MiB / 3 iterations / 4 parallelism)
6. Saves to `~/.local/share/mpc-wallet/keys/<group_id>/party_N.enc`

---

### `sign` — Threshold Signing

Sign a message using a threshold subset of key shares.

#### Usage

```bash
mpc-wallet sign \
  --key-group <GROUP_ID> \
  --party <PARTY_ID> \
  --signers <ID1,ID2,...> \
  --message <HEX_MESSAGE> \
  [--password <PASSWORD>]
```

#### Arguments

| Argument | Required | Description |
|----------|----------|-------------|
| `--key-group` | Yes | Key group UUID from `keygen` |
| `--party` | Yes | This party's ID (1-indexed) |
| `--signers` | Yes | Comma-separated signer IDs (e.g., `1,2`) |
| `--message` | Yes | Message to sign (hex-encoded) |
| `--password` | No | Wallet password |

#### Example: ECDSA Signature (EVM)

```bash
$ mpc-wallet sign \
    --key-group f47ac10b-58cc-4372-a567-0e02b2c3d479 \
    --party 1 \
    --signers 1,2 \
    --message "68656c6c6f"
Enter wallet password: ********

[success] Message signed successfully
{
  "signature": "r=3045...a1b2 s=3045...c3d4 v=0",
  "scheme": "gg20-ecdsa",
  "signers": [1, 2]
}
```

#### Example: EdDSA Signature (Solana)

```bash
$ mpc-wallet sign \
    --key-group b2c3d4e5-... \
    --party 1 \
    --signers 1,3 \
    --message "deadbeef"
Enter wallet password: ********

[success] Message signed successfully
{
  "signature": "a1b2c3d4e5f6...64bytes...hex",
  "scheme": "frost-ed25519",
  "signers": [1, 3]
}
```

#### What Happens Internally

1. Loads encrypted key shares for each signer from disk
2. Decrypts with password (Argon2id + AES-256-GCM)
3. Spawns concurrent signing tasks (one per signer)
4. Each party computes its **partial signature** using its share
5. Coordinator (Party 1) aggregates partials into final signature
6. **Full private key never exists** — only partial contributions are combined

---

### `export-address` — Derive Chain Address

Derive a blockchain address from a key group's public key.

#### Usage

```bash
mpc-wallet export-address \
  --key-group <GROUP_ID> \
  --chain <CHAIN> \
  [--password <PASSWORD>]
```

#### Arguments

| Argument | Required | Description |
|----------|----------|-------------|
| `--key-group` | Yes | Key group UUID |
| `--chain` | Yes | Target chain (see below) |
| `--password` | No | Wallet password |

#### Supported Chains

| Chain | Value | Address Format |
|-------|-------|---------------|
| Ethereum | `ethereum` | `0x` + 40 hex chars (EIP-55 checksum) |
| Polygon | `polygon` | Same as Ethereum |
| BSC | `bsc` | Same as Ethereum |
| Bitcoin | `bitcoin` | `bc1p...` (Taproot bech32m) |
| Bitcoin Testnet | `bitcoin-testnet` | `tb1p...` |
| Solana | `solana` | Base58 (32-byte Ed25519 pubkey) |
| Sui | `sui` | `0x` + 64 hex chars |

#### Example

```bash
$ mpc-wallet export-address \
    --key-group f47ac10b-58cc-4372-a567-0e02b2c3d479 \
    --chain ethereum
Enter wallet password: ********

[success] Address for f47ac10b-... on ethereum
{
  "address": "0x742d35Cc6634C0532925a3b844Bc9e7595f2bD28",
  "chain": "ethereum",
  "group_id": "f47ac10b-58cc-4372-a567-0e02b2c3d479"
}
```

```bash
$ mpc-wallet export-address --key-group b2c3d4e5-... --chain solana
Enter wallet password: ********

[success] Address for b2c3d4e5-... on solana
{
  "address": "7v91N7iZ9mNicL8WfG6cgSCKyRXydQjLh6UYBWwm6y1Q",
  "chain": "solana",
  "group_id": "b2c3d4e5-..."
}
```

---

### `list-keys` — Show Stored Key Groups

List all key groups saved in the encrypted key store.

#### Usage

```bash
mpc-wallet list-keys [--verbose] [--password <PASSWORD>]
```

#### Arguments

| Argument | Required | Description |
|----------|----------|-------------|
| `-v, --verbose` | No | Show file paths for each party's encrypted share |
| `--password` | No | Wallet password |

#### Example

```bash
$ mpc-wallet list-keys
Enter wallet password: ********

[success] Found 2 key group(s)
[
  {
    "group_id": "f47ac10b-58cc-4372-a567-0e02b2c3d479",
    "label": "hot-wallet",
    "scheme": "gg20-ecdsa",
    "threshold": 2,
    "total_parties": 3,
    "created_at": 1710547200
  },
  {
    "group_id": "b2c3d4e5-f6a7-4321-b890-1234567890ab",
    "label": "sol-vault",
    "scheme": "frost-ed25519",
    "threshold": 2,
    "total_parties": 3,
    "created_at": 1710547300
  }
]
```

#### Example (Verbose — show share file paths)

```bash
$ mpc-wallet list-keys --verbose
Enter wallet password: ********

[success] Found 1 key group(s)
[
  {
    "group_id": "f47ac10b-...",
    "label": "hot-wallet",
    "scheme": "gg20-ecdsa",
    "threshold": 2,
    "total_parties": 3,
    "created_at": 1710547200,
    "share_paths": [
      "/home/user/.local/share/mpc-wallet/keys/f47ac10b-.../party_1.enc",
      "/home/user/.local/share/mpc-wallet/keys/f47ac10b-.../party_2.enc",
      "/home/user/.local/share/mpc-wallet/keys/f47ac10b-.../party_3.enc"
    ]
  }
]
```

#### Example (Empty store)

```bash
$ mpc-wallet list-keys
Enter wallet password: ********

[success] No key groups found
```

---

### `simulate` — Pre-Sign Risk Assessment

Simulate a transaction before signing to assess risk. Checks value limits, program allowlists, gas budgets, and other chain-specific rules.

#### Usage

```bash
mpc-wallet simulate \
  --chain <CHAIN> \
  --to <ADDRESS> \
  --value <AMOUNT> \
  [--data <HEX_CALLDATA>] \
  [--extra <JSON>]
```

#### Arguments

| Argument | Required | Description |
|----------|----------|-------------|
| `--chain` | Yes | Target chain: `solana`, `sui` |
| `--to` | Yes | Recipient address |
| `--value` | Yes | Amount in base units (lamports, mist, etc.) |
| `--data` | No | Hex calldata (EVM-only, `0x` prefix OK) |
| `--extra` | No | Extra params as JSON string |

#### Risk Flags

| Flag | Chain | Trigger |
|------|-------|---------|
| `high_value` | All | Value exceeds chain threshold |
| `unknown_program` | Solana | Program ID not in allowlist |
| `excessive_gas_budget` | Sui | Gas budget exceeds max |
| `contract_interaction` | EVM | Transaction includes calldata |
| `proxy_detected` | EVM | Target is a known proxy contract |
| `dust_output` | Bitcoin | Output below 546 sat dust limit |
| `high_fee_rate` | Bitcoin | Fee rate > 500 sat/vB |
| `excessive_fee` | Bitcoin | Total fee > 0.01 BTC |

#### Risk Score

- **0–49**: `[success]` — low risk, safe to sign
- **50–255**: `[warning]` — elevated risk, review before signing

#### Example: Safe Solana Transfer

```bash
$ mpc-wallet simulate \
    --chain solana \
    --to 11111111111111111111111111111112 \
    --value 1000000000

[success] risk_score=0, flags=[]
{
  "success": true,
  "risk_score": 0,
  "risk_flags": [],
  "gas_used": 0
}
```

#### Example: High-Value Sui Transfer (Warning)

```bash
$ mpc-wallet simulate \
    --chain sui \
    --to "0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890" \
    --value 5000000000000

[warning] risk_score=50, flags=[high_value]
{
  "success": true,
  "risk_score": 50,
  "risk_flags": ["high_value"],
  "gas_used": 0
}
```

#### Example: Solana Unknown Program

```bash
$ mpc-wallet simulate \
    --chain solana \
    --to 11111111111111111111111111111112 \
    --value 1000 \
    --extra '{"program_id": "UnknownProgram111111111111111111111111111"}'

[warning] risk_score=40, flags=[unknown_program]
{
  "success": true,
  "risk_score": 40,
  "risk_flags": ["unknown_program"],
  "gas_used": 0
}
```

---

### `audit-verify` — Verify Audit Trail

Verify the integrity of an exported audit evidence pack. Checks the hash chain and Ed25519 service signatures for tampering.

#### Usage

```bash
mpc-wallet audit-verify --pack-file <PATH>
```

#### Arguments

| Argument | Required | Description |
|----------|----------|-------------|
| `--pack-file` | Yes | Path to evidence pack JSON file |

#### Evidence Pack Format

The pack is exported by `AuditLedger::export_evidence_pack()`:

```json
{
  "schema_version": 1,
  "generated_at": 1710547200,
  "entry_count": 5,
  "service_verifying_key_hex": "a1b2c3d4...",
  "entries": [
    {
      "index": 0,
      "prev_hash": "0000...0000",
      "event": "session_created",
      "session_id": "sess-001",
      "details": null,
      "timestamp": 1710547100,
      "service_signature": "deadbeef..."
    },
    ...
  ]
}
```

#### Example: Valid Pack

```bash
$ mpc-wallet audit-verify --pack-file evidence.json

[success] Audit ledger verified: 5 entries, hash chain intact
{
  "verified": true,
  "entry_count": 5
}
```

#### Example: Tampered Pack

```bash
$ mpc-wallet audit-verify --pack-file tampered.json

[error] Audit verification failed: signature invalid at entry 2
{
  "verified": false,
  "error": "audit error: signature invalid at entry 2"
}
```

#### Example: File Not Found

```bash
$ mpc-wallet audit-verify --pack-file missing.json

Error: Failed to read pack file 'missing.json': No such file or directory (os error 2)
```

---

## Output Formats

All commands support `--format text` (default) and `--format json`.

### Text Format

Human-friendly, one status line + pretty-printed data:

```
[success] Generated 2-of-3 gg20-ecdsa key group 'my-wallet'
{
  "group_id": "f47ac10b-..."
}
```

### JSON Format

Machine-parseable, single JSON object:

```bash
$ mpc-wallet list-keys --format json --password mypass
```

```json
{
  "status": "success",
  "message": "Found 2 key group(s)",
  "data": [
    {
      "group_id": "f47ac10b-...",
      "label": "hot-wallet",
      "scheme": "gg20-ecdsa",
      "threshold": 2,
      "total_parties": 3,
      "created_at": 1710547200
    }
  ]
}
```

Use `--format json` for scripting and automation:

```bash
# Extract group_id with jq
GROUP_ID=$(mpc-wallet keygen \
  --threshold 2 --parties 3 \
  --scheme gg20-ecdsa --label test \
  --password mypass --format json \
  | jq -r '.data.group_id')

echo "Created key group: $GROUP_ID"
```

---

## Storage & Configuration

### Key Store Location

| OS | Path |
|----|------|
| Linux | `~/.local/share/mpc-wallet/keys/` |
| macOS | `~/Library/Application Support/mpc-wallet/keys/` |
| Fallback | `./.mpc-wallet/keys/` |

### Directory Structure

```
~/.local/share/mpc-wallet/
  keys/
    f47ac10b-58cc-4372-a567-0e02b2c3d479/
      metadata.json          # Key group metadata (label, scheme, config)
      party_1.enc            # Encrypted share for party 1
      party_2.enc            # Encrypted share for party 2
      party_3.enc            # Encrypted share for party 3
    b2c3d4e5-.../
      metadata.json
      party_1.enc
      ...
```

### Encryption Details

| Parameter | Value |
|-----------|-------|
| Cipher | AES-256-GCM |
| KDF | Argon2id |
| Memory | 64 MiB |
| Iterations | 3 |
| Parallelism | 4 |
| Salt | 32 bytes (random per file) |
| Nonce | 12 bytes (random per file) |

Each `.enc` file contains: `salt (32B) || nonce (12B) || ciphertext || auth_tag (16B)`

---

## Examples: Full Workflow

### Workflow 1: EVM (Ethereum) Wallet

```bash
# Step 1: Generate a 2-of-3 ECDSA key group
$ mpc-wallet keygen -t 2 -n 3 --scheme gg20-ecdsa --label "eth-hot-wallet"
Enter wallet password: ********
[success] Generated 2-of-3 gg20-ecdsa key group 'eth-hot-wallet'
# => group_id: f47ac10b-...

# Step 2: Export Ethereum address
$ mpc-wallet export-address --key-group f47ac10b-... --chain ethereum
Enter wallet password: ********
[success] Address for f47ac10b-... on ethereum
# => address: 0x742d35Cc6634C0532925a3b844Bc9e7595f2bD28

# Step 3: Fund the address on Ethereum

# Step 4: Sign a transaction hash (parties 1 and 2)
$ mpc-wallet sign \
    --key-group f47ac10b-... \
    --party 1 \
    --signers 1,2 \
    --message "a1b2c3d4e5f6789012345678901234567890abcdef1234567890abcdef12345678"
Enter wallet password: ********
[success] Message signed successfully
# => signature with (r, s, v)

# Step 5: List all key groups
$ mpc-wallet list-keys
Enter wallet password: ********
[success] Found 1 key group(s)
```

### Workflow 2: Solana Wallet with Simulation

```bash
# Step 1: Generate EdDSA key group for Solana
$ mpc-wallet keygen -t 2 -n 3 --scheme frost-ed25519 --label "sol-treasury"
Enter wallet password: ********
[success] Generated 2-of-3 frost-ed25519 key group 'sol-treasury'
# => group_id: b2c3d4e5-...

# Step 2: Get Solana address
$ mpc-wallet export-address --key-group b2c3d4e5-... --chain solana
Enter wallet password: ********
[success] Address for b2c3d4e5-... on solana
# => address: 7v91N7iZ9mNicL8WfG6cgSCKyRXydQjLh6UYBWwm6y1Q

# Step 3: Simulate before signing (risk check)
$ mpc-wallet simulate \
    --chain solana \
    --to 11111111111111111111111111111112 \
    --value 5000000000
[success] risk_score=0, flags=[]
# => Safe to sign!

# Step 4: Sign the transaction
$ mpc-wallet sign \
    --key-group b2c3d4e5-... \
    --party 1 \
    --signers 1,3 \
    --message "deadbeefcafebabe..."
Enter wallet password: ********
[success] Message signed successfully
```

### Workflow 3: Audit Verification

```bash
# Step 1: Export evidence pack from your audit system
# (this is done programmatically via AuditLedger::export_evidence_pack())

# Step 2: Verify the pack
$ mpc-wallet audit-verify --pack-file /path/to/evidence-2024-Q1.json
[success] Audit ledger verified: 1,247 entries, hash chain intact

# Step 3: If tampered — investigate
$ mpc-wallet audit-verify --pack-file /path/to/suspicious.json
[error] Audit verification failed: hash-chain broken at entry 42
# => Entry 42 was modified after signing!
```

---

## Troubleshooting

### Common Errors

| Error | Cause | Fix |
|-------|-------|-----|
| `password required` | No password provided and stdin not a TTY | Use `--password` flag |
| `key group not found` | Invalid group ID or shares deleted | Check with `list-keys` |
| `threshold > parties` | Invalid threshold config | Ensure threshold <= parties |
| `policy required` | No signing policy loaded (API-level) | Load policy before signing |
| `simulation not yet supported` | Chain not supported for simulation | Use `solana` or `sui` |

### Debug Logging

```bash
# Enable verbose output for debugging
$ mpc-wallet -v keygen -t 2 -n 3 --scheme gg20-ecdsa --label test
# Shows debug-level tracing output
```

### Environment Variables

```bash
# Override log filter
RUST_LOG=debug mpc-wallet list-keys

# Custom log format
RUST_LOG=mpc_wallet_core=trace mpc-wallet sign ...
```

---

<p align="center">
  <sub>
    Part of the <a href="../README.md">Vaultex</a> project.
    Built with <a href="https://claude.com/claude-code">Claude Code</a>.
  </sub>
</p>
