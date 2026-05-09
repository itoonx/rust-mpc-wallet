// Sui transaction serialization using BCS encoding.
//
// Builds a real `TransactionData::V1` (see `sui::types`) for a SUI coin
// transfer using the canonical SplitCoins+TransferObjects PTB pattern. The
// BCS bytes are byte-for-byte compatible with @mysten/sui SDK output —
// verified by the `bcs_matches_mysten_sdk_reference` test.
//
// Sign payload: `Blake2b-256(SUI_INTENT_PREFIX ‖ bcs_bytes)`.
// Wire format:  `[0x00] ‖ sig(64) ‖ pubkey(32) = 97 bytes` (0x00 = Ed25519).

use mpc_wallet_core::error::CoreError;
use mpc_wallet_core::protocol::{GroupPublicKey, MpcSignature};

use super::types::{ObjectRef, TransactionData};
use crate::provider::{Chain, SignedTransaction, TransactionParams, UnsignedTransaction};

/// Validate a Sui address string.
/// A valid Sui address is `0x` followed by exactly 64 lowercase hex characters (32 bytes).
pub fn validate_sui_address(addr: &str) -> Result<[u8; 32], CoreError> {
    let hex_part = addr.strip_prefix("0x").ok_or_else(|| {
        CoreError::InvalidInput(format!("Sui address must start with '0x', got: {addr}"))
    })?;
    if hex_part.len() != 64 {
        return Err(CoreError::InvalidInput(format!(
            "Sui address must be 0x + 64 hex chars (32 bytes), got {} hex chars",
            hex_part.len()
        )));
    }
    let bytes = hex::decode(hex_part)
        .map_err(|e| CoreError::InvalidInput(format!("Sui address contains invalid hex: {e}")))?;
    Ok(bytes.try_into().unwrap()) // safe: we checked len == 64 hex = 32 bytes
}

/// Sui intent prefix for transaction signing: `[intent_scope=0, version=0, app_id=0]`.
const SUI_INTENT_PREFIX: [u8; 3] = [0, 0, 0];

/// Verify a Sui Ed25519 MPC signature against the wallet's group public key.
/// Used as a pre-broadcast invariant by the CLI: catches a bad sig before
/// burning gas. Mirrors `solana::tx::verify_solana_signature`.
pub fn verify_sui_signature(
    group_pubkey: &GroupPublicKey,
    sig: &MpcSignature,
    sign_payload: &[u8],
) -> Result<(), CoreError> {
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};
    let pubkey_bytes: [u8; 32] = match group_pubkey {
        GroupPublicKey::Ed25519(b) if b.len() == 32 => {
            let mut a = [0u8; 32];
            a.copy_from_slice(b);
            a
        }
        _ => {
            return Err(CoreError::InvalidInput(
                "Sui requires 32-byte Ed25519 group key".into(),
            ))
        }
    };
    let MpcSignature::EdDsa { signature } = sig else {
        return Err(CoreError::InvalidInput(
            "Sui requires EdDsa signature".into(),
        ));
    };
    let sig_arr: [u8; 64] = signature
        .as_slice()
        .try_into()
        .map_err(|_| CoreError::Crypto("Sui sig must be 64 bytes".into()))?;
    let vk = VerifyingKey::from_bytes(&pubkey_bytes)
        .map_err(|e| CoreError::Crypto(format!("invalid Sui pubkey: {e}")))?;
    let ed_sig = Signature::from_bytes(&sig_arr);
    vk.verify(sign_payload, &ed_sig)
        .map_err(|e| CoreError::Crypto(format!("Sui Ed25519 verify failed: {e}")))?;
    Ok(())
}

/// Sui object digests are 32-byte Blake2b outputs serialised by base58.
fn parse_object_digest(s: &str) -> Result<Vec<u8>, CoreError> {
    let raw = bs58::decode(s)
        .into_vec()
        .map_err(|e| CoreError::InvalidInput(format!("invalid base58 digest: {e}")))?;
    if raw.len() != 32 {
        return Err(CoreError::InvalidInput(format!(
            "Sui object digest must decode to 32 bytes, got {}",
            raw.len()
        )));
    }
    Ok(raw)
}

/// Build an unsigned Sui transaction using a real `TransactionData::V1`.
///
/// Required `params.extra` keys:
/// - `sender`               — `0x` + 64 hex (32 bytes)
/// - `gas_payment_object_id` — `0x` + 64 hex (32 bytes), the SUI coin to use for gas
/// - `gas_payment_version`  — u64
/// - `gas_payment_digest`   — base58 string decoding to 32 bytes
/// - `gas_price`            — u64 (MIST per gas unit)
/// - `gas_budget`           — u64 (MIST)
///
/// Encodes the canonical `transferSui` PTB (SplitCoins(GasCoin, [amount]) →
/// TransferObjects([split], recipient)) and computes
/// `sign_payload = Blake2b-256(SUI_INTENT_PREFIX ‖ bcs(TransactionData))`.
///
/// `tx_data` carries `bcs_bytes ‖ pubkey(32)` so `finalize_sui_transaction`
/// can pack the wire-format signature without extra parameters.
pub async fn build_sui_transaction(
    params: TransactionParams,
    group_pubkey: &GroupPublicKey,
) -> Result<UnsignedTransaction, CoreError> {
    let extra = params
        .extra
        .as_ref()
        .ok_or_else(|| CoreError::InvalidInput("Sui send requires extra params".to_string()))?;

    // ── Sender / recipient ────────────────────────────────────────────────
    let sender_hex = extra["sender"]
        .as_str()
        .ok_or_else(|| CoreError::InvalidInput("Sui: missing 'sender' in extra".to_string()))?;
    let sender = validate_sui_address(sender_hex)?;
    let recipient = validate_sui_address(&params.to)?;
    let amount: u64 = params
        .value
        .parse()
        .map_err(|_| CoreError::InvalidInput(format!("invalid amount: {}", params.value)))?;

    // ── Gas payment object ref ────────────────────────────────────────────
    let gas_object_id_hex = extra["gas_payment_object_id"].as_str().ok_or_else(|| {
        CoreError::InvalidInput("Sui: missing 'gas_payment_object_id' in extra".to_string())
    })?;
    let gas_object_id = validate_sui_address(gas_object_id_hex)?;
    let gas_version = extra["gas_payment_version"].as_u64().ok_or_else(|| {
        CoreError::InvalidInput("Sui: missing 'gas_payment_version' (u64) in extra".to_string())
    })?;
    let gas_digest_b58 = extra["gas_payment_digest"].as_str().ok_or_else(|| {
        CoreError::InvalidInput("Sui: missing 'gas_payment_digest' (base58) in extra".to_string())
    })?;
    let gas_digest = parse_object_digest(gas_digest_b58)?;
    let gas_price = extra["gas_price"]
        .as_u64()
        .ok_or_else(|| CoreError::InvalidInput("Sui: missing 'gas_price' (u64) in extra".into()))?;
    let gas_budget = extra["gas_budget"].as_u64().ok_or_else(|| {
        CoreError::InvalidInput("Sui: missing 'gas_budget' (u64) in extra".into())
    })?;

    // ── Build TransactionData::V1 + BCS encode ────────────────────────────
    let tx = TransactionData::new_transfer_sui(
        sender,
        recipient,
        amount,
        ObjectRef {
            object_id: gas_object_id,
            version: gas_version,
            digest: gas_digest,
        },
        gas_price,
        gas_budget,
    );
    let bcs_bytes =
        bcs::to_bytes(&tx).map_err(|e| CoreError::Protocol(format!("BCS encoding failed: {e}")))?;

    // ── sign_payload = Blake2b-256(intent ‖ bcs) ─────────────────────────
    let sign_payload = {
        use blake2::{Blake2b, Digest};
        type Blake2b256 = Blake2b<blake2::digest::consts::U32>;
        let mut hasher = Blake2b256::new();
        hasher.update(SUI_INTENT_PREFIX);
        hasher.update(&bcs_bytes);
        hasher.finalize().to_vec()
    };

    // ── Validate group pubkey, pack into tx_data ──────────────────────────
    let pubkey_bytes = match group_pubkey {
        GroupPublicKey::Ed25519(b) if b.len() == 32 => {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(b);
            arr
        }
        GroupPublicKey::Ed25519(_) => {
            return Err(CoreError::InvalidInput(
                "Ed25519 pubkey must be 32 bytes".into(),
            ))
        }
        _ => return Err(CoreError::InvalidInput("Sui requires Ed25519 key".into())),
    };

    let mut tx_data = bcs_bytes;
    tx_data.extend_from_slice(&pubkey_bytes);

    Ok(UnsignedTransaction {
        chain: Chain::Sui,
        sign_payload,
        tx_data,
    })
}

/// Finalize a Sui transaction with an EdDSA signature.
///
/// Expects `unsigned.tx_data` in the format written by `build_sui_transaction`:
///   `bcs_bytes || pubkey(32)`
///
/// Builds the Sui serialized-signature format:
///   `[0x00] || signature(64 bytes) || pubkey(32 bytes)` = 97 bytes
///
/// where `0x00` is the Ed25519 scheme flag defined by Sui.
///
/// # Errors
/// - `CoreError::InvalidInput` — non-EdDSA signature or `tx_data` too short
pub fn finalize_sui_transaction(
    unsigned: &UnsignedTransaction,
    sig: &MpcSignature,
) -> Result<SignedTransaction, CoreError> {
    // Extract signature bytes
    let sig_bytes = match sig {
        MpcSignature::EdDsa { signature } => *signature,
        _ => {
            return Err(CoreError::InvalidInput(
                "Sui requires EdDsa signature".to_string(),
            ))
        }
    };

    // tx_data layout (set by build_sui_transaction): `bcs_bytes ‖ pubkey(32)`.
    if unsigned.tx_data.len() < 32 {
        return Err(CoreError::Protocol("tx_data too short".to_string()));
    }
    let (bcs_bytes, pubkey_bytes) = unsigned.tx_data.split_at(unsigned.tx_data.len() - 32);
    let mut pubkey_arr = [0u8; 32];
    pubkey_arr.copy_from_slice(pubkey_bytes);

    // raw_tx layout (consumed by SuiProvider::broadcast): `bcs_bytes ‖ [0x00 ‖ sig(64) ‖ pubkey(32)]`.
    // The broadcast splits at len-97 to recover the BCS body and the 97-byte
    // serialized signature for `sui_executeTransactionBlock`.
    let mut raw_tx = Vec::with_capacity(bcs_bytes.len() + 97);
    raw_tx.extend_from_slice(bcs_bytes);
    raw_tx.push(0x00u8); // Ed25519 flag
    raw_tx.extend_from_slice(&sig_bytes);
    raw_tx.extend_from_slice(&pubkey_arr);

    // tx_hash = hex of the Blake2b-256 sign_payload (the intent-wrapped digest).
    let tx_hash = hex::encode(&unsigned.sign_payload);

    Ok(SignedTransaction {
        chain: Chain::Sui,
        raw_tx,
        tx_hash,
    })
}
