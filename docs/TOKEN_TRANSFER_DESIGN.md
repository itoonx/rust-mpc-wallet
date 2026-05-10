# Token Transfer Design — Standard Fungible Tokens Across All Live Chains

> **Status:** Sprint 44 deliverable — research + schema proposal. No production code changes in this sprint.
> **Audience:** Anyone implementing Sprints 45–49 (per-chain token rollouts) or reviewing the schema before code lands.
> **Scope:** Fungible tokens only. NFTs (ERC-721/1155, Sui NFT objects, Aptos digital assets) are deferred — the schema reserves room for them but they're out of scope until fungible support is proven on every chain.

---

## 1. Per-Chain Token-Standard Survey

This section catalogs how each of our 6 live chains expresses a *standard fungible token transfer* on the wire, with the upstream spec citation each implementation must mirror byte-for-byte.

### 1.1 EVM (ERC-20)

**Standard:** [EIP-20](https://eips.ethereum.org/EIPS/eip-20) (Fabian Vogelsteller, Vitalik Buterin, 2015).

**Wire format:** Standard EIP-1559 transaction with:
- `to` = the token contract address (NOT the recipient)
- `value` = `0` (no native ETH moves)
- `data` = ABI-encoded call `transfer(address,uint256)`:
  ```
  selector = keccak256("transfer(address,uint256)")[0..4] = 0xa9059cbb
  data = 0xa9059cbb
       ‖ pad32(recipient_address)   // left-padded to 32 bytes
       ‖ pad32(amount_uint256)       // big-endian
  ```
  Total calldata: exactly 68 bytes.

**Decimals:** Out-of-band — fetched via `eth_call` to `decimals() returns (uint8)` (selector `0x313ce567`). The chain itself doesn't enforce decimals; it's a UX convention.

**Address derivation:** No new derivation — the recipient is a normal EVM EOA or contract, validated by EIP-55 checksum (already implemented in `evm/address.rs`).

**Reference vector source:** [`@openzeppelin/contracts/token/ERC20`](https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/contracts/token/ERC20/ERC20.sol) — the canonical interface; viem/ethers both produce identical calldata.

**Already supported in our codebase?** Implicitly — `TransactionParams.data` plumbs raw calldata all the way through `build_evm_transaction` (`evm/tx.rs:65`). The user can hand-encode and pass it via `--data 0xa9059cbb...`. Sprint 45 adds the ABI encoder + CLI ergonomics so users don't have to.

---

### 1.2 Solana (SPL Token + Token-2022)

**Standard:**
- SPL Token Program: [`spl-token`](https://github.com/solana-program/token), program ID `TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA` (legacy, immutable).
- Token-2022: [`spl-token-2022`](https://github.com/solana-program/token-2022), program ID `TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb` (extension-rich, upgrade path).

**Wire format:** A normal Solana transaction whose first (only) instruction targets the token program. Two variants exist:

**`Transfer` (instruction discriminator = 3, deprecated for new code):**
```
data = [0x03] ‖ amount_le_u64       // 9 bytes
accounts = [
    source       (writable, signer optional — the holder's token account),
    destination  (writable),
    authority    (signer if not multisig),
]
```

**`TransferChecked` (discriminator = 12, recommended):**
```
data = [0x0C] ‖ amount_le_u64 ‖ decimals_u8   // 10 bytes
accounts = [
    source       (writable),
    mint         (read-only — checked against decimals),
    destination  (writable),
    authority    (signer),
]
```

`TransferChecked` is preferred because the program verifies the supplied decimals match the mint, catching a class of UI / off-by-decimal bugs.

**Address derivation — Associated Token Account (ATA):** SPL transfers don't move tokens between *wallet addresses*; they move between *token accounts*, which are PDAs derived from `(owner, token_program, mint)`:

```
ata = find_program_address(
    seeds = [owner_pubkey, token_program_id, mint_pubkey],
    program_id = ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL,    // ASSOCIATED_TOKEN_PROGRAM_ID
)
```

This means **every fungible-token transfer requires deriving two ATAs** (sender's and recipient's) before assembling the instruction.

**Recipient ATA may not exist yet** — Solana doesn't auto-create them. The standard pattern is to prepend a `CreateAssociatedTokenAccountIdempotent` instruction (`spl-associated-token-account` program) so a single tx both creates (if needed) and transfers. Idempotent variant is safe to include even if the ATA already exists (no-op).

**Reference vector source:** [`@solana/spl-token`](https://github.com/solana-program/token/tree/main/clients/js-legacy) — the official JS client. We'll capture instruction bytes via `createTransferCheckedInstruction(...)` and `getAssociatedTokenAddressSync(...)`.

**New derivation helper required:** `solana/ata.rs` exposing `derive_ata(owner, mint, program) -> Pubkey` using the `find_program_address` algorithm (BumpSeed search via SHA-256). Spec: [Solana PDA derivation](https://solana.com/docs/core/pda).

---

### 1.3 Bitcoin (out of scope — see §6)

---

### 1.4 Sui (`Coin<T>`)

**Standard:** Sui's coin model is a Move generic — every fungible token is `0x2::coin::Coin<T>` for some type `T`. Native SUI is `Coin<0x2::sui::SUI>`; USDC on Sui is `Coin<0x...::usdc::USDC>` (the actual type tag depends on the issuer's package). Same `Coin<T>` wrapper means **the same transfer machinery works for native and tokens**, just with a different type argument.

**Spec:** [`sui-framework/coin.move`](https://github.com/MystenLabs/sui/blob/main/crates/sui-framework/packages/sui-framework/sources/coin.move) — the `coin::transfer` and `coin::split` Move modules.

**Wire format options:**

**Option A — `0x2::pay::split_and_transfer<T>`** (single MoveCall):
```
ProgrammableTransaction {
    inputs: [
        Pure(coin_object_ref),     // the source Coin<T>
        Pure(amount_u64),
        Pure(recipient_address),
    ],
    commands: [
        MoveCall {
            package:  "0x2",
            module:   "pay",
            function: "split_and_transfer",
            type_args: [T],
            args:     [Input(0), Input(1), Input(2)],
        }
    ]
}
```

**Option B — manual `SplitCoins` + `TransferObjects`** (mirrors what we already do for native SUI, but with a different source coin):
```
ProgrammableTransaction {
    inputs: [
        Object(coin_object_ref),   // the source Coin<T> — a separately-owned coin object
        Pure(amount_u64),
        Pure(recipient_address),
    ],
    commands: [
        SplitCoins(Input(0), [Input(1)]),                  // split coin → NestedResult(0,0)
        TransferObjects([NestedResult(0,0)], Input(2)),    // transfer to recipient
    ]
}
```

**We'll use Option B** because it reuses the proven Sprint 41 PTB structure verbatim and only swaps the input coin from `GasCoin` (special) to a normal `Object(coin_ref)`. The MoveCall path (Option A) requires plumbing type-arg parsing and a different reference-vector capture.

**Note:** When `T = 0x2::sui::SUI` and we want to spend gas + transfer in one shot, our existing native flow uses the special `Argument::GasCoin` input. For non-SUI coins, we use a normal object reference and pay gas separately from the `gas_payment_object_id` (which still must be a SUI Coin).

**Address derivation:** No new derivation. Recipient is a normal Sui address.

**Coin object selection:** Sui's `getCoins` RPC returns all `Coin<T>` objects owned by an address, filtered by type. We pick the coin with the largest balance (or aggregate small coins if the largest is insufficient — out of scope for round 1; assume single coin covers the transfer). Existing `SuiRpcClient::get_owned_coins` (in `sui/rpc_client.rs`) defaults to `Coin<SUI>`; needs a type-tag filter parameter.

**Reference vector source:** [`@mysten/sui/transactions`](https://github.com/MystenLabs/sui/tree/main/sdk/typescript/src/transactions) — `Transaction.splitCoins(coin, [amount])` + `transferObjects([result], recipient)` for arbitrary coin types.

---

### 1.5 Aptos — Coin (legacy) + Fungible Asset (new)

Aptos has **two parallel token standards**, both in production. Wallets need to support both.

#### 1.5.1 Aptos Coin (legacy, `0x1::coin`)

**Standard:** [`aptos-framework/coin.move`](https://github.com/aptos-labs/aptos-core/blob/main/aptos-move/framework/aptos-framework/sources/coin.move).

**Wire format:** Same `RawTransaction` as our Sprint 42 native APT flow, with a different `EntryFunction`:
```
EntryFunction {
    module:    "0x1::coin",
    function:  "transfer",
    ty_args:   [TypeTag::Struct(StructTag { address, module, name, type_args: [] })],
    args: [
        bcs(recipient_address),    // 32 bytes
        bcs(amount_u64),            // 8 bytes LE
    ],
}
```

The `ty_args` carries the `T` of `coin::transfer<T>`. For USDC-on-Aptos:
```
ty_args = [Struct {
    address: 0xbae207659db88bea0cbead6da0ed00aac12edcdda169e591cd41c94180b46f3b,
    module:  "usdc",
    name:    "USDC",
    type_args: [],
}]
```

**Already supported in our codebase?** The `EntryFunction` struct (`aptos/types.rs:74`) is fully generic — `module`, `function`, `ty_args`, `args` are all `Vec` / `Identifier`. Only the *convenience constructor* (`EntryFunction::aptos_account_transfer` at `types.rs:117`) hardcodes the path. Sprint 46 adds a `EntryFunction::coin_transfer<T>` constructor and `RawTransaction::new_coin_transfer` plumbing.

**Reference vector source:** [`@aptos-labs/ts-sdk`](https://github.com/aptos-labs/aptos-ts-sdk) — `aptos.transferCoinTransaction({ ... typeArguments: [coinType] })`.

#### 1.5.2 Aptos Fungible Asset (new, `0x1::primary_fungible_store`)

**Standard:** [Aptos Fungible Asset standard](https://aptos.dev/en/build/smart-contracts/fungible-asset) — replaces Coin going forward; the framework recommends new tokens use FA. USDC on Aptos mainnet has migrated to FA.

**Wire format:**
```
EntryFunction {
    module:    "0x1::primary_fungible_store",
    function:  "transfer",
    ty_args:   [TypeTag::Struct(StructTag { address: "0x1", module: "fungible_asset", name: "Metadata", type_args: [] })],
    args: [
        bcs(metadata_address),     // 32 bytes — the FA metadata Object<Metadata>
        bcs(recipient_address),    // 32 bytes
        bcs(amount_u64),            // 8 bytes LE
    ],
}
```

The first argument is the **FA metadata object address** — a unique on-chain Object that identifies the token (analogous to Solana's mint pubkey or EVM's contract address). It's *not* a type argument; it's a runtime address passed as data. The single `ty_args` is always `0x1::fungible_asset::Metadata` because the framework's `transfer<T: key>` is generic over the metadata's type, and the canonical metadata is `Metadata`.

**Critical difference from Coin:** With Coin, the token identity lives in the type system (`Coin<USDC>`); with FA, it lives in the data (the metadata Object address). This affects how we serialize the `TokenIdentifier` and how we look up token metadata.

**Reference vector source:** [`@aptos-labs/ts-sdk`](https://github.com/aptos-labs/aptos-ts-sdk) — `aptos.transferFungibleAsset({ fungibleAssetMetadataAddress, recipient, amount })`.

---

### 1.6 TRON (TRC-20)

**Standard:** [TRC-20](https://tronprotocol.github.io/documentation-en/contracts/trc20/) — ABI-compatible with ERC-20. The calldata format is identical (`0xa9059cbb ‖ pad32(recipient) ‖ pad32(amount)`); only the wire-level transaction container differs.

**Wire format:** A `TriggerSmartContract` (ContractType=31) instead of `TransferContract` (ContractType=1). Protobuf field map ([`Tron.proto`](https://github.com/tronprotocol/protocol/blob/master/core/contract/smart_contract.proto)):
```
message TriggerSmartContract {
    bytes owner_address    = 1;   // 21 bytes — caller's T-address (0x41 ‖ hash160)
    bytes contract_address = 2;   // 21 bytes — TRC-20 contract T-address
    int64 call_value       = 3;   // sun — must be 0 for transfer (no TRX moves)
    bytes data             = 4;   // ABI calldata — same shape as ERC-20
    int64 call_token_value = 5;   // optional — for TRC-10 wrapped value, leave 0
    int64 token_id         = 6;   // optional — TRC-10 token id, leave 0
}
```

**Recipient address transformation:** TRON addresses are 21 bytes (`0x41 ‖ hash160`). The TRC-20 calldata, being ERC-20-compatible, expects a 20-byte EVM-style address. **Strip the `0x41` prefix when encoding the calldata** — TVM's internal address representation drops it. Same for the contract address in calldata if any cross-contract calls reference it (not relevant for plain transfer).

**`fee_limit` requirement:** Unlike `TransferContract` (which omits fee_limit per L-017), `TriggerSmartContract` **requires** `fee_limit` to be set in `Transaction.raw` (field 18) — this is the energy/bandwidth cap, denominated in sun. A reasonable default is 100 TRX (`100_000_000` sun).

**Address derivation:** No new derivation. Both the contract and recipient are normal T-addresses.

**Reference vector source:** [`tronweb`](https://github.com/tronprotocol/tronweb) — `tronWeb.transactionBuilder.triggerSmartContract(contractAddress, "transfer(address,uint256)", { feeLimit }, [{ type: "address", value: to }, { type: "uint256", value: amount }])`.

---

## 2. Generic `TokenIdentifier` Schema

### 2.1 The enum

```rust
// crates/mpc-wallet-chains/src/token.rs (new — proposed)

/// Identifies a token for transfer. Serialized as JSON into
/// `TransactionParams.extra["token"]`. Each chain provider's
/// `build_transaction` reads its own variant; cross-chain dispatch
/// stays at the CLI layer.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum TokenIdentifier {
    /// Move the chain's native gas token. Default; equivalent to `extra["token"]` absent.
    Native,

    /// EVM ERC-20/721/1155. ERC-20 is the only Sprint-45 target; 721/1155 reserved.
    Evm {
        contract: String,                  // 0x... checksummed
        standard: EvmTokenStandard,        // Erc20 (Sprint 45) | Erc721 | Erc1155 (deferred)
        #[serde(default)]
        token_id: Option<String>,          // for NFTs only
    },

    /// Solana SPL Token / Token-2022. Either the legacy program or the 2022 extension program.
    Spl {
        mint: String,                       // base58 mint pubkey
        program: SplProgram,                // SplToken | Token2022
        decimals: u8,                       // for TransferChecked discriminator
    },

    /// Sui Coin<T> — any fungible coin including USDC, etc.
    Sui {
        type_tag: String,                   // e.g. "0xdba34672e30cb065b1f93e3ab55318768fd6fef66c15942c9f7cb846e2f900e7::usdc::USDC"
    },

    /// Aptos has two parallel standards in production. Both must be supported.
    Aptos {
        kind: AptosTokenKind,
    },

    /// TRON TRC-20 (TVM smart contract).
    Tron {
        contract: String,                   // T-address (base58check)
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvmTokenStandard {
    Erc20,
    Erc721,
    Erc1155,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SplProgram {
    SplToken,    // legacy Token program
    Token2022,   // extension-rich
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum AptosTokenKind {
    /// Legacy Coin standard — `0x1::coin::transfer<T>`.
    Coin {
        type_tag: String,                   // e.g. "0xbae...::usdc::USDC"
    },
    /// Fungible Asset standard — `0x1::primary_fungible_store::transfer`.
    FungibleAsset {
        metadata: String,                   // Object<Metadata> address (0x... 32 bytes)
    },
}
```

### 2.2 Where it lives

The enum lives in a new `crates/mpc-wallet-chains/src/token.rs` module. Reasons:

1. **Chain providers parse their own variant.** No cross-chain dispatch in the chain crate — each provider does `let tok = extra.get("token").and_then(|v| serde_json::from_value::<TokenIdentifier>(v.clone()).ok()).unwrap_or(TokenIdentifier::Native);` and matches on its variant. Variant mismatch (e.g. `Spl` on EVM) is a hard error.

2. **Schema is part of the public SDK contract.** External integrators using the SDK (not the CLI) need the enum to construct token transfers; CLI-only would force them to hand-write JSON.

3. **Backwards-compatible.** Existing native-only callers don't need to change anything — `TransactionParams.extra["token"]` is optional, and absence means `Native`.

### 2.3 CLI shorthand syntax

The CLI accepts `--token <spec>` with a chain-aware shorthand parser:

| Shorthand | Expanded |
|-----------|----------|
| `native` (default) | `{"kind":"native"}` |
| `erc20:0x...` | `{"kind":"evm","contract":"0x...","standard":"erc20"}` |
| `spl:<mint>:<decimals>` | `{"kind":"spl","mint":"...","program":"spl_token","decimals":N}` |
| `spl-2022:<mint>:<decimals>` | … with `program: "token2022"` |
| `sui-coin:0x...::module::Type` | `{"kind":"sui","type_tag":"..."}` |
| `aptos-coin:0x...::module::Type` | `{"kind":"aptos","kind":{"type":"coin","type_tag":"..."}}` |
| `aptos-fa:0x...` | `{"kind":"aptos","kind":{"type":"fungible_asset","metadata":"..."}}` |
| `trc20:T...` | `{"kind":"tron","contract":"T..."}` |
| `--token-json '<full json>'` | escape hatch for power users / SDK integrators |

The shorthand is **CLI-layer only** — the canonical wire format is always the JSON. Tests use the JSON directly so they don't double-test the parser.

### 2.4 Decimals & UX

`amount` always stays as **smallest-unit decimal string** (consistent with current `--value`). The CLI optionally fetches decimals via the relevant RPC (`eth_call decimals()` for ERC-20/TRC-20, mint account parse for SPL, `0x1::coin::decimals<T>` for Aptos Coin, `fungible_asset::decimals` for FA, package metadata for Sui Coin) **only for display purposes** (printing "≈ 1.5 USDC" alongside the raw amount). Decimals never become part of the wire format except for SPL `TransferChecked`.

---

## 3. CLI Surface

**Decision: extend `mpc-wallet send` rather than a new subcommand.** The existing send pipeline already does keygen-or-load → derive address → fetch presign extras → build → sign → broadcast. Token transfers fit cleanly into that loop — they only differ in `build_transaction` and (for Solana) preflight ATA checks.

New flag: `--token <shorthand-or-json>`. Default `native`. `--token-json` accepts raw JSON for power users.

**Pre-flight changes:**
- **Balance check** becomes token-aware: `--token erc20:0x...` queries `balanceOf(sender)` on the contract instead of native balance.
- **Solana**: derive sender ATA, check exists + funded; check recipient ATA — if missing, prepend `CreateAssociatedTokenAccountIdempotent` and warn user about extra ~0.002 SOL rent.

**Post-sign verification:** unchanged in spirit — sig still recovers/verifies against sender's wallet pubkey. Extra check: decode the signed tx and confirm the token destination/amount match what the user requested (prevents a sig from being misapplied to wrong calldata if RPC poisons extras).

**Explorer URLs:** unchanged — same chain-level `tx_hash` + chain explorer.

---

## 4. Reference Vector & Live-Test Strategy

Each chain gets one new companion script per token standard, mirroring the proven Sprint 41/42/43 methodology:

| Chain | Script | What it captures | Live test target |
|-------|--------|------------------|------------------|
| EVM Sepolia | `scripts/evm-erc20-ref-vector.mjs` | viem-encoded `transfer(address,uint256)` calldata | Sepolia USDC (`0x1c7D4B196Cb0C7B01d743Fbc6116a902379C7238`) — official Circle testnet |
| Solana devnet | `scripts/solana-spl-ref-vector.mjs` | `@solana/spl-token` `createTransferCheckedInstruction` + `getAssociatedTokenAddressSync` | Devnet USDC (`4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU`) |
| Sui testnet | `scripts/sui-coin-ref-vector.mjs` | `@mysten/sui` PTB with non-SUI Coin<T> input | Testnet USDC (Wormhole or native — TBD by recipient) |
| Aptos testnet | `scripts/aptos-coin-ref-vector.mjs` | `@aptos-labs/ts-sdk` `transferCoinTransaction` with type arg | Testnet USDC (Coin variant) |
| Aptos testnet | `scripts/aptos-fa-ref-vector.mjs` | `@aptos-labs/ts-sdk` `transferFungibleAsset` | Testnet FA (deploy a test FA if no public testnet exists) |
| TRON Shasta | `scripts/tron-trc20-ref-vector.mjs` | `tronweb.transactionBuilder.triggerSmartContract` with `transfer(address,uint256)` ABI | Shasta JST (`TF17BgPaZYbz8oxbjhriubPDsA7ArKoLX3`) — official testnet stablecoin |

**Each implementation sprint includes:**
1. Capture the upstream-SDK reference bytes via the script.
2. Pin them as a hardcoded test constant in the chain's integration test.
3. Assert byte-for-byte parity against our Rust builder.
4. Live broadcast a real testnet token transfer, record tx hash + explorer URL.
5. Add the funded test wallet to `tests/e2e/funded-wallets.local.json`.

**Why not unit tests of the encoder alone?** Sprint 43 L-017 proved that encoder correctness is necessary but not sufficient — TonGrid silently rejected our valid bytes because the broadcast envelope was wrong. Live-broadcast tests catch envelope/RPC issues that pure encoder tests cannot.

---

## 5. Implementation Roadmap

Sprints sequenced by complexity — easiest first to validate the schema before harder chains escalate cost of a wrong design:

### Sprint 45 — EVM ERC-20 (validates schema)
- Add `crates/mpc-wallet-chains/src/token.rs` with `TokenIdentifier` enum.
- Add `evm/erc20.rs` with `encode_transfer_calldata(recipient, amount) -> Vec<u8>` (32 LOC).
- Wire `evm/tx.rs::build_evm_transaction` to detect `extra["token"]`, redirect `to`/`value`/`data` for ERC-20.
- Add token-aware balance preflight in `cli/send.rs` (calls `balanceOf` via existing `EvmRpcClient`).
- CLI shorthand parser for `--token erc20:0x...`.
- Live tx: USDC-Sepolia send with funded `sepolia-test` wallet. Record tx hash.
- 1 new retro lesson if anything surprises us; otherwise just CLAUDE.md sprint entry.

**Deliverables:** ~150 LOC + 1 ref-vector script + CLI ergonomics + 1 live tx.

### Sprint 46 — Sui Coin<T> + Aptos Coin (Move-style batch)
- Sui: extend `SuiRpcClient::get_owned_coins` with a `coin_type_filter: Option<&str>` parameter; add `sui/tx.rs` Coin<T> path that uses `Object(coin_ref)` instead of `Argument::GasCoin` as split source.
- Aptos: add `EntryFunction::coin_transfer<T>` constructor + `RawTransaction::new_coin_transfer` plumbing.
- Both chains: ref-vector capture + integration test + live testnet USDC transfer.

**Deliverables:** ~250 LOC + 2 ref-vector scripts + 2 live txs.

### Sprint 47 — Aptos Fungible Asset
- Add `EntryFunction::primary_fungible_store_transfer` constructor with the metadata Object address as first arg.
- Update `aptos/tx.rs::build_aptos_transaction` to dispatch on `AptosTokenKind::FungibleAsset`.
- Ref-vector + integration test + live testnet FA transfer.

**Deliverables:** ~120 LOC + 1 ref-vector script + 1 live tx.

### Sprint 48 — TRON TRC-20
- Extend `tron/proto.rs` with `encode_trigger_smart_contract` + `encode_contract_trigger` (proto field map: ContractType=31, owner_address, contract_address, call_value, data, call_token_value, token_id).
- Add `tron/abi.rs` with `encode_erc20_transfer(recipient_T_addr, amount) -> Vec<u8>` (note: strips `0x41` prefix for calldata).
- Update `build_tron_transaction` to dispatch on `TokenIdentifier::Tron`. Re-include `fee_limit` (required for TriggerSmartContract).
- Ref-vector + integration test + live Shasta JST or USDT transfer.

**Deliverables:** ~200 LOC + 1 ref-vector script + 1 live tx.

### Sprint 49 — Solana SPL (highest complexity)
- New `solana/instruction.rs` with generic `Instruction { program_id, accounts: Vec<AccountMeta>, data }` struct.
- Refactor `solana/tx.rs::build_message_bytes_v0` to take `Vec<Instruction>` instead of hardcoding system transfer.
- New `solana/ata.rs` exposing `derive_ata(owner, mint, program) -> Pubkey` (PDA via `find_program_address`).
- New `solana/spl.rs` with `encode_transfer_checked(amount, decimals) -> Vec<u8>` and `encode_create_ata_idempotent(...) -> Instruction`.
- Build flow: optional CreateATA (idempotent) + TransferChecked, in that order.
- Ref-vector + integration test + live devnet USDC transfer.

**Deliverables:** ~400 LOC + 1 ref-vector script + 1 live tx.

### Estimated cumulative

| Sprint | New LOC | Live txs | Schedule |
|--------|---------|----------|----------|
| 45 | 150 | 1 | 1 sitting |
| 46 | 250 | 2 | 1–2 sittings |
| 47 | 120 | 1 | 1 sitting |
| 48 | 200 | 1 | 1 sitting |
| 49 | 400 | 1 | 2 sittings |
| **Total** | **~1120** | **6** | **~6–7 sittings** |

After Sprint 49, every live chain supports both native and standard token transfers. NFT support (deferred §7) becomes a follow-on roadmap.

---

## 6. Out of Scope: Bitcoin

Bitcoin's UTXO model has no native fungible-token primitive. Three "Bitcoin token" ecosystems exist, none of which fit a generic-wallet abstraction:

- **BRC-20** (ordinals/inscriptions) — tokens encoded as JSON inscribed in witness data of taproot outputs. Transfers require a 2-tx flow (inscribe transfer → spend the inscribed UTXO). Indexers, not the protocol, track balances. No widely-deployed wallet SDK we can mirror byte-for-byte.
- **Runes** (Casey Rodarmor, post-Taproot) — native runes protocol using `OP_RETURN` edicts. Modest adoption; stable spec since v1.0 in 2024. Could be in scope for a later sprint if user requests.
- **Lightning** — payment channels; entirely separate protocol stack (BOLT specs).

**Recommendation:** defer Bitcoin tokens entirely until a specific user request names BRC-20 or Runes. The 5 chains above cover the bulk of stablecoin custody volume and validate the schema; revisiting Bitcoin requires a separate design round that's not blocking.

---

## 7. Deferred: NFTs

The schema reserves `EvmTokenStandard::Erc721 | Erc1155` and an `Aptos::DigitalAsset` variant could be added without breaking changes. Implementation deferred until fungible support is proven on every live chain. NFT-specific UX (token IDs, metadata fetch, royalty enforcement) deserves its own design round.

---

## 8. Open Design Questions (need user input before Sprint 45 starts)

| # | Question | Default proposal |
|---|----------|------------------|
| Q1 | Auto-fetch token decimals/symbol from RPC, or require user to specify? | **Auto-fetch.** `--decimals N` override flag for offline / unusual cases. Decimals are display-only except for SPL `TransferChecked`. |
| Q2 | Solana SPL: auto-create recipient ATA if missing, or fail? | **Auto-create** via `CreateAssociatedTokenAccountIdempotent`. Costs sender ~0.002 SOL rent; vastly better UX than "go fund this address first." Print a one-line warning when this happens so it's not silent. |
| Q3 | `TokenIdentifier` location: chain crate (`mpc-wallet-chains`) or CLI-only? | **Chain crate.** SDK integrators need it; CLI is just one consumer. New module `crates/mpc-wallet-chains/src/token.rs`. |
| Q4 | Sprint sequencing: as proposed (45→49 EVM-first), or different order? | **As proposed.** EVM is trivial → validates schema; Solana last because ATA/CreateATA is the highest variance. User can override. |
| Q5 | Test recipient: send-to-self (we control both sides) or external? | **Send-to-self.** Same pattern as native sprints — keeps faucet drain to zero and avoids needing a known external testnet recipient. |
| Q6 | TRC-20 fee_limit default for TRON Sprint 48 | **100 TRX (`100_000_000` sun)**. Refunded if unused; high enough that contract calls don't run out of energy. Override via `--extra '{"fee_limit": N}'`. |

User: please mark each row with your decision (`OK` / `change to: …`) before Sprint 45 begins.

---

## 9. Citations Index

| Spec | URL |
|------|-----|
| EIP-20 | https://eips.ethereum.org/EIPS/eip-20 |
| SPL Token | https://github.com/solana-program/token |
| SPL Token-2022 | https://github.com/solana-program/token-2022 |
| Solana ATA | https://github.com/solana-program/associated-token-account |
| Solana PDA | https://solana.com/docs/core/pda |
| Sui Coin module | https://github.com/MystenLabs/sui/blob/main/crates/sui-framework/packages/sui-framework/sources/coin.move |
| Aptos Coin | https://github.com/aptos-labs/aptos-core/blob/main/aptos-move/framework/aptos-framework/sources/coin.move |
| Aptos Fungible Asset | https://aptos.dev/en/build/smart-contracts/fungible-asset |
| TRON TRC-20 | https://tronprotocol.github.io/documentation-en/contracts/trc20/ |
| TRON proto (smart_contract) | https://github.com/tronprotocol/protocol/blob/master/core/contract/smart_contract.proto |
