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
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Reference vector captured via `node scripts/aptos-ref-vector.mjs`.
    /// Inputs: sender=0x11×32, recipient=0x22×32, amount=100_000 octas,
    /// sequence=7, max_gas=2000, gas_price=100, expiration=99_999_999_999,
    /// chain_id=2 (testnet).
    const REF_BCS_HEX: &str = "111111111111111111111111111111111111111111111111111111111111111107000000000000000200000000000000000000000000000000000000000000000000000000000000010d6170746f735f6163636f756e74087472616e73666572000220222222222222222222222222222222222222222222222222222222222222222208a086010000000000d0070000000000006400000000000000ffe776481700000002";

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
