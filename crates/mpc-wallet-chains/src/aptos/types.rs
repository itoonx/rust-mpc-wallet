//! Hand-rolled BCS structs that match Aptos's
//! `aptos-types::transaction::RawTransaction` wire format byte-for-byte.
//! Used so we can sign canonical Aptos transactions without pulling the
//! full `aptos-types` dependency.
//!
//! Variant ordering for `TransactionPayload` matches upstream:
//! `Script(0) / ModuleBundle(1, deprecated) / EntryFunction(2) / Multisig(3)`.
//! Verified byte-for-byte against the @aptos-labs/ts-sdk reference vector
//! captured by `scripts/aptos-ref-vector.mjs` and asserted by
//! `bcs_matches_aptos_sdk_reference` in `tests/chain_aptos_integration.rs`.

use serde::{Deserialize, Serialize};

/// 32-byte Aptos account address.
pub type AccountAddress = [u8; 32];

/// BCS `Identifier` is just a length-prefixed UTF-8 string. We use `String`
/// directly — `serde` + `bcs` produce the same wire shape as upstream's
/// `move_core_types::identifier::Identifier(String)` newtype.
pub type Identifier = String;

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct RawTransaction {
    pub sender: AccountAddress,
    pub sequence_number: u64,
    pub payload: TransactionPayload,
    pub max_gas_amount: u64,
    pub gas_unit_price: u64,
    pub expiration_timestamp_secs: u64,
    pub chain_id: u8,
}

/// Variant order is upstream-canonical; deprecated `ModuleBundle` keeps slot 1
/// so `EntryFunction` correctly serializes as variant index 2.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub enum TransactionPayload {
    /// variant 0 — bytecode script
    Script(Script),
    /// variant 1 — deprecated; keeps slot for variant-index alignment
    ModuleBundle(ModuleBundle),
    /// variant 2 — Move entry function call (the only path we actually emit)
    EntryFunction(EntryFunction),
    /// variant 3 — multisig invocation
    Multisig(Multisig),
}

/// Placeholder for the deprecated ModuleBundle variant — we never emit one.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct ModuleBundle {
    pub codes: Vec<Vec<u8>>,
}

/// Placeholder for the Script variant — never emitted.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct Script {
    pub code: Vec<u8>,
    pub ty_args: Vec<TypeTag>,
    pub args: Vec<Vec<u8>>,
}

/// Placeholder for the Multisig variant — never emitted.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct Multisig {
    pub multisig_address: AccountAddress,
    pub transaction_payload: Option<MultisigTransactionPayload>,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub enum MultisigTransactionPayload {
    EntryFunction(EntryFunction),
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct EntryFunction {
    pub module: ModuleId,
    pub function: Identifier,
    pub ty_args: Vec<TypeTag>,
    /// Each element is the BCS encoding of a single argument value.
    pub args: Vec<Vec<u8>>,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct ModuleId {
    pub address: AccountAddress,
    pub name: Identifier,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub enum TypeTag {
    Bool,
    U8,
    U64,
    U128,
    Address,
    Signer,
    Vector(Box<TypeTag>),
    Struct(Box<StructTag>),
    U16,
    U32,
    U256,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct StructTag {
    pub address: AccountAddress,
    pub module: Identifier,
    pub name: Identifier,
    pub type_args: Vec<TypeTag>,
}

// ─── Convenience constructors ──────────────────────────────────────────────

impl EntryFunction {
    /// Build the canonical `0x1::aptos_account::transfer(recipient, amount)`
    /// entry function. Each argument is BCS-encoded into the `Vec<u8>` slot
    /// the wire format expects.
    pub fn aptos_account_transfer(recipient: AccountAddress, amount: u64) -> Self {
        // module address = 0x0000…0001
        let mut module_address = [0u8; 32];
        module_address[31] = 0x01;
        Self {
            module: ModuleId {
                address: module_address,
                name: "aptos_account".to_string(),
            },
            function: "transfer".to_string(),
            ty_args: vec![],
            args: vec![
                bcs::to_bytes(&recipient).expect("BCS encode AccountAddress is infallible"),
                bcs::to_bytes(&amount).expect("BCS encode u64 is infallible"),
            ],
        }
    }

    /// Build `0x1::primary_fungible_store::transfer<T>(metadata, recipient, amount)`
    /// for the Aptos Fungible Asset standard (newer than Coin — replaces it
    /// going forward; native APT and most production tokens have migrated).
    ///
    /// `metadata` is the on-chain `Object<Metadata>` address — a 32-byte
    /// account address that uniquely identifies the FA. Unlike Coin, where
    /// the token identity lives in the type system (`Coin<USDC>`), FA
    /// puts it in the **data** (the metadata Object address). The single
    /// `ty_arg` is always `0x1::fungible_asset::Metadata` — the canonical
    /// type of the metadata Object that `T: key` resolves to.
    pub fn primary_fungible_store_transfer(
        metadata: AccountAddress,
        recipient: AccountAddress,
        amount: u64,
    ) -> Self {
        let mut module_address = [0u8; 32];
        module_address[31] = 0x01;
        let mut metadata_type_addr = [0u8; 32];
        metadata_type_addr[31] = 0x01;
        Self {
            module: ModuleId {
                address: module_address,
                name: "primary_fungible_store".to_string(),
            },
            function: "transfer".to_string(),
            ty_args: vec![TypeTag::Struct(Box::new(StructTag {
                address: metadata_type_addr,
                module: "fungible_asset".to_string(),
                name: "Metadata".to_string(),
                type_args: vec![],
            }))],
            args: vec![
                bcs::to_bytes(&metadata).expect("BCS encode metadata is infallible"),
                bcs::to_bytes(&recipient).expect("BCS encode recipient is infallible"),
                bcs::to_bytes(&amount).expect("BCS encode amount is infallible"),
            ],
        }
    }

    /// Build `0x1::coin::transfer<T>(recipient, amount)` for an arbitrary
    /// `T = StructTag`. `T` must satisfy the `Coin<T>` newtype requirement
    /// — for native APT, `T = 0x1::aptos_coin::AptosCoin`. The function
    /// signature is the same as `aptos_account::transfer` (recipient, amount)
    /// so the args slot is identical; only `ty_args` and the module differ.
    pub fn coin_transfer(coin_type: StructTag, recipient: AccountAddress, amount: u64) -> Self {
        let mut module_address = [0u8; 32];
        module_address[31] = 0x01;
        Self {
            module: ModuleId {
                address: module_address,
                name: "coin".to_string(),
            },
            function: "transfer".to_string(),
            ty_args: vec![TypeTag::Struct(Box::new(coin_type))],
            args: vec![
                bcs::to_bytes(&recipient).expect("BCS encode AccountAddress is infallible"),
                bcs::to_bytes(&amount).expect("BCS encode u64 is infallible"),
            ],
        }
    }
}

impl StructTag {
    /// Parse a Move struct tag of the form `0x<addr>::<module>::<name>`.
    /// The address is hex-decoded and zero-padded to 32 bytes (Aptos accepts
    /// short forms like `0x1`). Generic parameters (`<T,U>`) are NOT parsed —
    /// pass an empty `type_args` vec and add nesting later if a use case
    /// emerges (e.g. `Coin<Coin<X>>` is not a real Move pattern).
    pub fn parse(tag: &str) -> Result<Self, String> {
        let parts: Vec<&str> = tag.splitn(3, "::").collect();
        if parts.len() != 3 {
            return Err(format!("expected `<addr>::<module>::<name>`, got `{tag}`"));
        }
        let addr_str = parts[0].trim_start_matches("0x");
        if addr_str.is_empty() || addr_str.len() > 64 {
            return Err(format!("address `{}` invalid length", parts[0]));
        }
        let padded = format!("{:0>64}", addr_str);
        let bytes = hex::decode(&padded).map_err(|e| format!("address hex: {e}"))?;
        let mut address = [0u8; 32];
        address.copy_from_slice(&bytes);
        Ok(Self {
            address,
            module: parts[1].to_string(),
            name: parts[2].to_string(),
            type_args: vec![],
        })
    }
}

impl RawTransaction {
    /// Build a `RawTransaction` for `0x1::aptos_account::transfer`.
    #[allow(clippy::too_many_arguments)]
    pub fn new_transfer(
        sender: AccountAddress,
        sequence_number: u64,
        recipient: AccountAddress,
        amount: u64,
        max_gas_amount: u64,
        gas_unit_price: u64,
        expiration_timestamp_secs: u64,
        chain_id: u8,
    ) -> Self {
        Self {
            sender,
            sequence_number,
            payload: TransactionPayload::EntryFunction(EntryFunction::aptos_account_transfer(
                recipient, amount,
            )),
            max_gas_amount,
            gas_unit_price,
            expiration_timestamp_secs,
            chain_id,
        }
    }

    /// Build a `RawTransaction` for `0x1::primary_fungible_store::transfer`
    /// — Aptos Fungible Asset standard (Sprint 47). `metadata` is the FA's
    /// on-chain Object<Metadata> address; the type arg is always
    /// `0x1::fungible_asset::Metadata`.
    #[allow(clippy::too_many_arguments)]
    pub fn new_fungible_asset_transfer(
        sender: AccountAddress,
        sequence_number: u64,
        metadata: AccountAddress,
        recipient: AccountAddress,
        amount: u64,
        max_gas_amount: u64,
        gas_unit_price: u64,
        expiration_timestamp_secs: u64,
        chain_id: u8,
    ) -> Self {
        Self {
            sender,
            sequence_number,
            payload: TransactionPayload::EntryFunction(
                EntryFunction::primary_fungible_store_transfer(metadata, recipient, amount),
            ),
            max_gas_amount,
            gas_unit_price,
            expiration_timestamp_secs,
            chain_id,
        }
    }

    /// Build a `RawTransaction` for `0x1::coin::transfer<T>` — works for any
    /// Coin standard token (legacy, pre-Fungible-Asset). `coin_type` is the
    /// `T` of `Coin<T>`.
    #[allow(clippy::too_many_arguments)]
    pub fn new_coin_transfer(
        sender: AccountAddress,
        sequence_number: u64,
        coin_type: StructTag,
        recipient: AccountAddress,
        amount: u64,
        max_gas_amount: u64,
        gas_unit_price: u64,
        expiration_timestamp_secs: u64,
        chain_id: u8,
    ) -> Self {
        Self {
            sender,
            sequence_number,
            payload: TransactionPayload::EntryFunction(EntryFunction::coin_transfer(
                coin_type, recipient, amount,
            )),
            max_gas_amount,
            gas_unit_price,
            expiration_timestamp_secs,
            chain_id,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Reference vector captured via `node scripts/aptos-ref-vector.mjs`.
    /// Inputs: sender=0x11×32, recipient=0x22×32, amount=100_000 octas,
    /// sequence=7, max_gas=2000, gas_price=100, expiration=99_999_999_999,
    /// chain_id=2 (testnet).
    const REF_BCS_HEX: &str = "111111111111111111111111111111111111111111111111111111111111111107000000000000000200000000000000000000000000000000000000000000000000000000000000010d6170746f735f6163636f756e74087472616e73666572000220222222222222222222222222222222222222222222222222222222222222222208a086010000000000d0070000000000006400000000000000ffe776481700000002";

    /// Reference vector captured via `node scripts/aptos-coin-ref-vector.mjs`.
    /// Same inputs as `bcs_matches_aptos_sdk_reference` (sender/recipient/
    /// sequence/gas/expiration/chain_id) but the payload calls
    /// `0x1::coin::transfer<0x1::aptos_coin::AptosCoin>(recipient, amount)`
    /// instead of `0x1::aptos_account::transfer`. 211 bytes — 46 longer than
    /// native because of the extra type arg encoding.
    const REF_BCS_HEX_COIN: &str = "1111111111111111111111111111111111111111111111111111111111111111070000000000000002000000000000000000000000000000000000000000000000000000000000000104636f696e087472616e73666572010700000000000000000000000000000000000000000000000000000000000000010a6170746f735f636f696e094170746f73436f696e000220222222222222222222222222222222222222222222222222222222222222222208a086010000000000d0070000000000006400000000000000ffe776481700000002";

    #[test]
    fn bcs_matches_aptos_sdk_coin_reference() {
        let sender: AccountAddress = [0x11; 32];
        let recipient: AccountAddress = [0x22; 32];
        let coin_type = StructTag::parse("0x1::aptos_coin::AptosCoin").unwrap();

        let tx = RawTransaction::new_coin_transfer(
            sender,
            7,
            coin_type,
            recipient,
            100_000,
            2000,
            100,
            99_999_999_999,
            2,
        );
        let bytes = bcs::to_bytes(&tx).expect("BCS encode");
        let actual = hex::encode(&bytes);
        assert_eq!(
            actual, REF_BCS_HEX_COIN,
            "Coin<T> BCS bytes diverge from @aptos-labs/ts-sdk reference vector"
        );
        assert_eq!(bytes.len(), 211);
    }

    /// Reference vector captured via `node scripts/aptos-fa-ref-vector.mjs`.
    /// Same outer fields (sender/recipient/sequence/gas/expiration/chain_id)
    /// as the Coin tests, but payload is `0x1::primary_fungible_store::
    /// transfer<0x1::fungible_asset::Metadata>(metadata=0x33×32, recipient,
    /// amount)`. 265 bytes — 54 longer than Coin because of the longer
    /// module name + extra metadata arg.
    const REF_BCS_HEX_FA: &str = "11111111111111111111111111111111111111111111111111111111111111110700000000000000020000000000000000000000000000000000000000000000000000000000000001167072696d6172795f66756e6769626c655f73746f7265087472616e73666572010700000000000000000000000000000000000000000000000000000000000000010e66756e6769626c655f6173736574084d65746164617461000320333333333333333333333333333333333333333333333333333333333333333320222222222222222222222222222222222222222222222222222222222222222208a086010000000000d0070000000000006400000000000000ffe776481700000002";

    #[test]
    fn bcs_matches_aptos_sdk_fa_reference() {
        let sender: AccountAddress = [0x11; 32];
        let recipient: AccountAddress = [0x22; 32];
        let metadata: AccountAddress = [0x33; 32];

        let tx = RawTransaction::new_fungible_asset_transfer(
            sender,
            7,
            metadata,
            recipient,
            100_000,
            2000,
            100,
            99_999_999_999,
            2,
        );
        let bytes = bcs::to_bytes(&tx).expect("BCS encode");
        let actual = hex::encode(&bytes);
        assert_eq!(
            actual, REF_BCS_HEX_FA,
            "FA BCS bytes diverge from @aptos-labs/ts-sdk reference vector"
        );
        assert_eq!(bytes.len(), 265);
    }

    #[test]
    fn struct_tag_parse_short_address() {
        let tag = StructTag::parse("0x1::coin::CoinStore").unwrap();
        assert_eq!(tag.address[31], 0x01);
        assert!(tag.address[..31].iter().all(|&b| b == 0));
        assert_eq!(tag.module, "coin");
        assert_eq!(tag.name, "CoinStore");
        assert!(tag.type_args.is_empty());
    }

    #[test]
    fn struct_tag_parse_full_address() {
        let tag = StructTag::parse(
            "0xbae207659db88bea0cbead6da0ed00aac12edcdda169e591cd41c94180b46f3b::usdc::USDC",
        )
        .unwrap();
        assert_eq!(tag.module, "usdc");
        assert_eq!(tag.name, "USDC");
    }

    #[test]
    fn struct_tag_parse_rejects_malformed() {
        assert!(StructTag::parse("0x1::coin").is_err());
        assert!(StructTag::parse("notatag").is_err());
    }

    #[test]
    fn bcs_matches_aptos_sdk_reference() {
        let sender: AccountAddress = [0x11; 32];
        let recipient: AccountAddress = [0x22; 32];
        let tx = RawTransaction::new_transfer(
            sender,
            7,
            recipient,
            100_000,
            2000,
            100,
            99_999_999_999,
            2,
        );
        let bytes = bcs::to_bytes(&tx).expect("BCS encode");
        let actual = hex::encode(&bytes);
        assert_eq!(
            actual, REF_BCS_HEX,
            "BCS bytes diverge from @aptos-labs/ts-sdk reference vector"
        );
        assert_eq!(
            bytes.len(),
            165,
            "expected 165-byte canonical RawTransaction"
        );
    }

    #[test]
    fn bcs_roundtrip_idempotent() {
        let tx =
            RawTransaction::new_transfer([1u8; 32], 0, [2u8; 32], 500, 1000, 100, 1_000_000, 1);
        let a = bcs::to_bytes(&tx).unwrap();
        let decoded: RawTransaction = bcs::from_bytes(&a).unwrap();
        let b = bcs::to_bytes(&decoded).unwrap();
        assert_eq!(a, b, "encode → decode → encode must be byte-identical");
        assert_eq!(tx, decoded, "decoded value must equal original");
    }
}
