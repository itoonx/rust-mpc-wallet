//! Hand-rolled BCS structs that match Sui's `sui-types::transaction::TransactionData::V1`
//! wire format byte-for-byte. Used so we can sign canonical Sui transactions
//! without pulling the full `sui-sdk-types` / `sui-types` dependency.
//!
//! Variant ordering is enforced by `#[derive(Serialize)]` against `bcs`,
//! which encodes the variant index as ULEB128 in declaration order. Order
//! here is taken from the upstream Sui repo and verified byte-for-byte
//! against a deterministic reference vector captured via the @mysten/sui
//! TypeScript SDK (see `scripts/sui-ref-vector.mjs` and the
//! `test_sui_bcs_matches_reference` integration test).

use serde::{Deserialize, Serialize};

/// 32-byte Sui address (Blake2b-256 of `flag ‖ pubkey`).
pub type SuiAddress = [u8; 32];

/// 32-byte object digest (Blake2b output).
///
/// Upstream Sui encodes the digest as a length-prefixed byte vector (BCS
/// `Vec<u8>` wire shape) rather than a fixed array, even though the value
/// is always 32 bytes. We mirror that by using `Vec<u8>` here — the
/// `bcs_matches_mysten_sdk_reference` test catches any drift.
pub type ObjectDigest = Vec<u8>;

/// 32-byte ObjectID.
pub type ObjectId = [u8; 32];

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub enum TransactionData {
    /// variant 0
    V1(TransactionDataV1),
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct TransactionDataV1 {
    pub kind: TransactionKind,
    pub sender: SuiAddress,
    pub gas_data: GasData,
    pub expiration: TransactionExpiration,
}

/// Only the variants we serialize are listed by name; other variants must
/// keep their slot in the declaration order even if we never emit them.
/// We use unit dummies for the unsupported ones so the indices line up
/// without dragging in their payload types.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub enum TransactionKind {
    /// variant 0
    ProgrammableTransaction(ProgrammableTransaction),
    // The remaining variants exist in upstream Sui (ChangeEpoch, Genesis,
    // ConsensusCommitPrologue, AuthenticatorStateUpdate,
    // EndOfEpochTransaction, RandomnessStateUpdate,
    // ConsensusCommitPrologueV2, ConsensusCommitPrologueV3,
    // ProgrammableSystemTransaction). We never emit them; deserializing
    // such a payload from a non-Programmable tx is out of scope.
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct ProgrammableTransaction {
    pub inputs: Vec<CallArg>,
    pub commands: Vec<Command>,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub enum CallArg {
    /// variant 0 — opaque BCS-encoded primitive (u64 amount, address, etc.)
    Pure(Vec<u8>),
    /// variant 1
    Object(ObjectArg),
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub enum ObjectArg {
    /// variant 0 — owned or immutable object reference
    ImmOrOwnedObject(ObjectRef),
    /// variant 1 — shared object (mutable consensus)
    SharedObject {
        id: ObjectId,
        initial_shared_version: u64,
        mutable: bool,
    },
    /// variant 2 — receiving (post-1.x); we never emit but slot must be reserved
    Receiving(ObjectRef),
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct ObjectRef {
    pub object_id: ObjectId,
    pub version: u64,
    pub digest: ObjectDigest,
}

/// Upstream order (verified against ref vector — SplitCoins is variant 2,
/// TransferObjects is variant 1). Variants we don't emit still occupy their
/// declaration slot.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub enum Command {
    /// variant 0 — Move function call
    MoveCall(MoveCall),
    /// variant 1 — transfer a list of objects to an address
    TransferObjects(Vec<Argument>, Argument),
    /// variant 2 — split coins off a single coin (e.g. gas) by amounts
    SplitCoins(Argument, Vec<Argument>),
    /// variant 3 — merge a list of coins into one
    MergeCoins(Argument, Vec<Argument>),
    /// variant 4 — publish a Move package
    Publish(Vec<Vec<u8>>, Vec<ObjectId>),
    /// variant 5 — assemble a vec<T> from arguments of homogeneous type
    MakeMoveVec(Option<TypeTag>, Vec<Argument>),
    /// variant 6 — upgrade a Move package
    Upgrade(Vec<Vec<u8>>, Vec<ObjectId>, ObjectId, Argument),
}

/// Type tag — placeholder for the few `TypeTag` variants we never emit.
/// Encoded only when `MakeMoveVec` is used; for our transfer flow this is
/// unreachable, but we still need the type to exist for `Command` to derive.
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
    pub address: SuiAddress,
    pub module: String,
    pub name: String,
    pub type_params: Vec<TypeTag>,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct MoveCall {
    pub package: ObjectId,
    pub module: String,
    pub function: String,
    pub type_arguments: Vec<TypeTag>,
    pub arguments: Vec<Argument>,
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
pub enum Argument {
    /// variant 0 — the gas coin object
    GasCoin,
    /// variant 1 — index into ProgrammableTransaction.inputs
    Input(u16),
    /// variant 2 — index into the result list
    Result(u16),
    /// variant 3 — `(command_index, sub_index)`
    NestedResult(u16, u16),
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct GasData {
    pub payment: Vec<ObjectRef>,
    pub owner: SuiAddress,
    pub price: u64,
    pub budget: u64,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub enum TransactionExpiration {
    /// variant 0 — never expires by epoch
    None,
    /// variant 1 — invalid after the given epoch
    Epoch(u64),
}

// ─── Convenience constructors ──────────────────────────────────────────────

impl ProgrammableTransaction {
    /// Build the canonical `transferSui` PTB:
    ///   inputs:  [Pure(amount), Pure(recipient)]
    ///   cmds:    [SplitCoins(GasCoin, [Input(0)]),
    ///             TransferObjects([NestedResult(0,0)], Input(1))]
    pub fn transfer_sui(amount: u64, recipient: SuiAddress) -> Self {
        let amount_bcs = bcs::to_bytes(&amount).expect("u64 BCS encode is infallible");
        let recipient_bcs = bcs::to_bytes(&recipient).expect("[u8;32] BCS encode is infallible");
        Self {
            inputs: vec![CallArg::Pure(amount_bcs), CallArg::Pure(recipient_bcs)],
            commands: vec![
                Command::SplitCoins(Argument::GasCoin, vec![Argument::Input(0)]),
                Command::TransferObjects(vec![Argument::NestedResult(0, 0)], Argument::Input(1)),
            ],
        }
    }
}

impl TransactionData {
    /// Build a `TransactionData::V1` for a SUI coin transfer.
    pub fn new_transfer_sui(
        sender: SuiAddress,
        recipient: SuiAddress,
        amount: u64,
        gas_payment: ObjectRef,
        gas_price: u64,
        gas_budget: u64,
    ) -> Self {
        TransactionData::V1(TransactionDataV1 {
            kind: TransactionKind::ProgrammableTransaction(ProgrammableTransaction::transfer_sui(
                amount, recipient,
            )),
            sender,
            gas_data: GasData {
                payment: vec![gas_payment],
                owner: sender,
                price: gas_price,
                budget: gas_budget,
            },
            expiration: TransactionExpiration::None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Reference vector captured via `node scripts/sui-ref-vector.mjs`.
    /// Inputs: sender=0x11×32, recipient=0x22×32, amount=100_000_000 MIST,
    /// gas_object=0x33×32 version=42 digest=base58("A"×44),
    /// gas_price=1000, gas_budget=10_000_000.
    const REF_BCS_HEX: &str = "000002000800e1f5050000000000202222222222222222222222222222222222222222222222222222222222222222020200010100000101030000000001010011111111111111111111111111111111111111111111111111111111111111110133333333333333333333333333333333333333333333333333333333333333332a00000000000000208811c3b52fc29a3f25ba593ce7f39b5ee628922e2e60354406be2af286bca1af1111111111111111111111111111111111111111111111111111111111111111e803000000000000809698000000000000";

    #[test]
    fn bcs_matches_mysten_sdk_reference() {
        let sender: SuiAddress = [0x11; 32];
        let recipient: SuiAddress = [0x22; 32];
        let gas_object: ObjectId = [0x33; 32];

        // Decoded from base58("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
        // — 44 base58 chars = 32 bytes, see the JS reference script.
        let gas_digest: ObjectDigest = bs58::decode("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
            .into_vec()
            .unwrap();
        assert_eq!(
            gas_digest.len(),
            32,
            "ObjectDigest must be exactly 32 bytes"
        );

        let tx = TransactionData::new_transfer_sui(
            sender,
            recipient,
            100_000_000,
            ObjectRef {
                object_id: gas_object,
                version: 42,
                digest: gas_digest,
            },
            1000,
            10_000_000,
        );

        let bytes = bcs::to_bytes(&tx).expect("BCS encode");
        let actual_hex = hex::encode(&bytes);
        assert_eq!(
            actual_hex, REF_BCS_HEX,
            "BCS bytes diverge from @mysten/sui SDK reference vector"
        );
        assert_eq!(bytes.len(), 219, "expected 219-byte canonical TransferSui");
    }

    #[test]
    fn bcs_roundtrip_idempotent() {
        let tx = TransactionData::new_transfer_sui(
            [1u8; 32],
            [2u8; 32],
            500,
            ObjectRef {
                object_id: [3u8; 32],
                version: 7,
                digest: vec![4u8; 32],
            },
            100,
            1000,
        );
        let a = bcs::to_bytes(&tx).unwrap();
        let decoded: TransactionData = bcs::from_bytes(&a).unwrap();
        let b = bcs::to_bytes(&decoded).unwrap();
        assert_eq!(a, b, "encode → decode → encode must be byte-identical");
        assert_eq!(tx, decoded, "decoded value must equal original");
    }
}
