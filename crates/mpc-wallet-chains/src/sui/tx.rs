// Sui transaction serialization using BCS encoding.
//
// This module implements:
//   1. `SuiTransferPayload` — minimal BCS-serializable struct for a Sui coin transfer.
//   2. `build_sui_transaction` — encodes the payload with BCS, computes the Blake2b-256
//      intent-wrapped signing payload, and stores `bcs_bytes || pubkey(32)` in `tx_data`.
//   3. `finalize_sui_transaction` — extracts the pubkey suffix from `tx_data` and builds
//      the Sui serialized-signature: [0x00 | sig(64) | pubkey(32)] = 97 bytes.
//
// Sui signature wire format: [0x00] || signature(64 bytes) || pubkey(32 bytes)
//   flag 0x00 = Ed25519
//
// NOTE: Current BCS payload covers coin transfer. Full `sui-sdk` TransactionData
// (gas payment, epoch, validator fields) is a future enhancement.

use bcs;
use serde::{Deserialize, Serialize};

use mpc_wallet_core::error::CoreError;
use mpc_wallet_core::protocol::{GroupPublicKey, MpcSignature};

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
    let bytes = hex::decode(hex_part).map_err(|e| {
        CoreError::InvalidInput(format!("Sui address contains invalid hex: {e}"))
    })?;
    Ok(bytes.try_into().unwrap()) // safe: we checked len == 64 hex = 32 bytes
}

/// Minimal representation of a Sui coin transfer for BCS encoding.
/// This is a simplified (but structurally correct) subset of Sui's TransactionData.
///
/// NOTE: Minimal BCS payload for coin transfer. Full sui-sdk TransactionData
/// (gas payment, epoch, validator fields) is a future enhancement.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SuiTransferPayload {
    /// Sender address as 32 bytes
    pub sender: [u8; 32],
    /// Recipient address as 32 bytes
    pub recipient: [u8; 32],
    /// Amount in MIST (1 SUI = 1_000_000_000 MIST)
    pub amount: u64,
    /// Recent object digest / reference epoch (32 bytes, zeros if not available)
    pub reference: [u8; 32],
}

/// Sui intent prefix for transaction signing: [intent_scope=0, version=0, app_id=0]
const SUI_INTENT_PREFIX: [u8; 3] = [0, 0, 0];

/// Build an unsigned Sui transaction using BCS encoding.
///
/// Encodes a `SuiTransferPayload` with BCS, computes:
///   `sign_payload = Blake2b-256(SUI_INTENT_PREFIX || bcs_bytes)`
///
/// Stores `bcs_bytes || pubkey(32)` in `tx_data` so that `finalize_sui_transaction`
/// can recover the Ed25519 public key without an extra parameter not present in the
/// `ChainProvider` trait.
///
/// # Errors
/// - `CoreError::InvalidInput` — missing/invalid sender or recipient address, or non-Ed25519 key
/// - `CoreError::Protocol` — BCS encoding failure
pub async fn build_sui_transaction(
    params: TransactionParams,
    group_pubkey: &GroupPublicKey,
) -> Result<UnsignedTransaction, CoreError> {
    // 1. Extract and validate sender from extra["sender"] — fail fast
    let sender_hex = params
        .extra
        .as_ref()
        .and_then(|e| e["sender"].as_str())
        .ok_or_else(|| CoreError::InvalidInput("Sui: missing sender in extra".to_string()))?;
    let sender_bytes = validate_sui_address(sender_hex)?;

    // 2. Validate and decode recipient
    let recipient_bytes = validate_sui_address(&params.to)?;

    // 3. Parse amount
    let amount: u64 = params
        .value
        .parse()
        .map_err(|_| CoreError::InvalidInput(format!("invalid amount: {}", params.value)))?;

    // 4. Build payload struct
    let payload = SuiTransferPayload {
        sender: sender_bytes,
        recipient: recipient_bytes,
        amount,
        reference: [0u8; 32], // placeholder — real object reference from RPC in production
    };

    // 5. BCS-encode the payload
    let bcs_bytes = bcs::to_bytes(&payload)
        .map_err(|e| CoreError::Protocol(format!("BCS encoding failed: {e}")))?;

    // 6. Compute sign_payload: Blake2b-256(intent_prefix || bcs_bytes)
    //    Sui intent prefix for transaction: [0, 0, 0]
    let sign_payload = {
        use blake2::{Blake2b, Digest};
        type Blake2b256 = Blake2b<blake2::digest::consts::U32>;
        let mut hasher = Blake2b256::new();
        hasher.update(SUI_INTENT_PREFIX);
        hasher.update(&bcs_bytes);
        hasher.finalize().to_vec()
    };

    // 7. Validate Ed25519 public key
    let pubkey_bytes = match group_pubkey {
        GroupPublicKey::Ed25519(ref b) => {
            if b.len() != 32 {
                return Err(CoreError::InvalidInput(
                    "Ed25519 pubkey must be 32 bytes".to_string(),
                ));
            }
            let mut arr = [0u8; 32];
            arr.copy_from_slice(b);
            arr
        }
        _ => return Err(CoreError::InvalidInput("Sui requires Ed25519 key".to_string())),
    };

    // 8. Store: tx_data = bcs_bytes || pubkey(32)
    //    The pubkey suffix allows finalize_sui_transaction to recover it without JSON.
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
        _ => return Err(CoreError::InvalidInput("Sui requires EdDsa signature".to_string())),
    };

    // tx_data = bcs_bytes || pubkey(32)
    // Pubkey is always the last 32 bytes
    if unsigned.tx_data.len() < 32 {
        return Err(CoreError::Protocol("tx_data too short".to_string()));
    }
    let (_, pubkey_bytes) = unsigned.tx_data.split_at(unsigned.tx_data.len() - 32);
    let mut pubkey_arr = [0u8; 32];
    pubkey_arr.copy_from_slice(pubkey_bytes);

    // Build Sui signature: [0x00 | sig(64) | pubkey(32)] = 97 bytes
    let mut raw_sig = Vec::with_capacity(97);
    raw_sig.push(0x00u8); // Ed25519 flag
    raw_sig.extend_from_slice(&sig_bytes);
    raw_sig.extend_from_slice(&pubkey_arr);

    // tx_hash = hex of the Blake2b-256 sign_payload (the intent-wrapped digest)
    let tx_hash = hex::encode(&unsigned.sign_payload);

    Ok(SignedTransaction {
        chain: Chain::Sui,
        raw_tx: raw_sig,
        tx_hash,
    })
}
