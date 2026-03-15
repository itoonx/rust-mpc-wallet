use mpc_wallet_core::error::CoreError;
use mpc_wallet_core::protocol::MpcSignature;

use crate::provider::{Chain, SignedTransaction, TransactionParams, UnsignedTransaction};

/// Encode a value as Solana compact-u16.
/// For values < 128 this is a single byte.
fn encode_compact_u16(val: u16) -> Vec<u8> {
    if val < 0x80 {
        vec![val as u8]
    } else {
        // Two-byte encoding for 128..=16383
        let low = (val & 0x7f) as u8 | 0x80;
        let high = (val >> 7) as u8;
        vec![low, high]
    }
}

/// Build the Solana message bytes for a simple SOL transfer (legacy v0).
///
/// Layout:
///   [1]   num_required_signatures  = 1
///   [1]   num_readonly_signed      = 0
///   [1]   num_readonly_unsigned    = 1  (system program)
///   [cu16] num_account_keys        = 3
///   [32]  account_key_0  (from / signer)
///   [32]  account_key_1  (to)
///   [32]  account_key_2  (system program, all-zeros)
///   [32]  recent_blockhash
///   [cu16] num_instructions        = 1
///     [1]   program_id_index       = 2
///     [cu16] num_accounts          = 2
///       [1] account_idx_0          = 0 (from)
///       [1] account_idx_1          = 1 (to)
///     [cu16] instruction_data_len  = 12
///     [4]   instruction_type       = [2,0,0,0]  (SystemInstruction::Transfer)
///     [8]   lamports               (little-endian u64)
fn build_message_bytes(
    from_bytes: &[u8; 32],
    to_bytes: &[u8; 32],
    lamports: u64,
    recent_blockhash: &[u8; 32],
) -> Vec<u8> {
    let mut msg = Vec::with_capacity(200);

    // Header
    msg.push(1u8); // num_required_signatures
    msg.push(0u8); // num_readonly_signed
    msg.push(1u8); // num_readonly_unsigned (system program)

    // Account keys: 3 accounts
    msg.extend_from_slice(&encode_compact_u16(3));
    msg.extend_from_slice(from_bytes);
    msg.extend_from_slice(to_bytes);
    msg.extend_from_slice(&[0u8; 32]); // system program (11111111...1 = all zeros)

    // Recent blockhash
    msg.extend_from_slice(recent_blockhash);

    // Instructions: 1 instruction
    msg.extend_from_slice(&encode_compact_u16(1));

    // Instruction: SystemProgram::Transfer
    msg.push(2u8); // program_id_index = 2 (system program)

    // Account indices: 2 accounts
    msg.extend_from_slice(&encode_compact_u16(2));
    msg.push(0u8); // from (index 0)
    msg.push(1u8); // to (index 1)

    // Instruction data: 12 bytes
    msg.extend_from_slice(&encode_compact_u16(12));
    msg.extend_from_slice(&[2u8, 0u8, 0u8, 0u8]); // SystemInstruction::Transfer = 2
    msg.extend_from_slice(&lamports.to_le_bytes()); // 8 bytes, little-endian

    msg
}

/// Decode a base58 string into exactly 32 bytes.
fn decode_base58_32(s: &str, field: &str) -> Result<[u8; 32], CoreError> {
    let bytes = bs58::decode(s)
        .into_vec()
        .map_err(|e| CoreError::InvalidInput(format!("invalid base58 for {field}: {e}")))?;
    bytes
        .try_into()
        .map_err(|_| CoreError::InvalidInput(format!("{field} must decode to exactly 32 bytes")))
}

/// Build an unsigned Solana transaction using the real binary message format.
///
/// The `sign_payload` is the raw message bytes (what Ed25519 signs).
/// The `tx_data` is JSON metadata needed to reconstruct the final transaction.
pub async fn build_solana_transaction(
    params: TransactionParams,
) -> Result<UnsignedTransaction, CoreError> {
    // Parse sender from params.extra["from"]
    let from_str = params
        .extra
        .as_ref()
        .and_then(|e| e.get("from"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| CoreError::InvalidInput("missing 'from' in extra".into()))?;

    // Parse recipient
    let to_str = params.to.as_str();

    // Parse lamports
    let lamports: u64 = params
        .value
        .parse()
        .map_err(|e| CoreError::InvalidInput(format!("invalid lamports value: {e}")))?;

    // Decode public keys
    let from_bytes = decode_base58_32(from_str, "from")?;
    let to_bytes = decode_base58_32(to_str, "to")?;

    // Decode or default recent_blockhash
    let recent_blockhash: [u8; 32] = if let Some(bh_str) = params
        .extra
        .as_ref()
        .and_then(|e| e.get("recent_blockhash"))
        .and_then(|v| v.as_str())
    {
        decode_base58_32(bh_str, "recent_blockhash")?
    } else {
        [0u8; 32]
    };

    // Build binary message
    let message_bytes = build_message_bytes(&from_bytes, &to_bytes, lamports, &recent_blockhash);

    // tx_data carries the hex-encoded message plus metadata for finalize
    let tx_data_json = serde_json::json!({
        "message_bytes": hex::encode(&message_bytes),
        "from": from_str,
        "to": to_str,
        "lamports": lamports,
    });
    let tx_data = serde_json::to_vec(&tx_data_json)
        .map_err(|e| CoreError::Serialization(e.to_string()))?;

    Ok(UnsignedTransaction {
        chain: Chain::Solana,
        sign_payload: message_bytes,
        tx_data,
    })
}

/// Finalize a Solana transaction with an EdDSA signature.
///
/// Wire format:
///   [compact-u16]  num_signatures  = 1  → 0x01
///   [64 bytes]     signature
///   [...message bytes...]
pub fn finalize_solana_transaction(
    unsigned: &UnsignedTransaction,
    sig: &MpcSignature,
) -> Result<SignedTransaction, CoreError> {
    let MpcSignature::EdDsa { signature } = sig else {
        return Err(CoreError::InvalidInput(
            "Solana requires EdDSA signature".into(),
        ));
    };

    // Recover message bytes from tx_data JSON
    let meta: serde_json::Value = serde_json::from_slice(&unsigned.tx_data)
        .map_err(|e| CoreError::Serialization(format!("invalid tx_data JSON: {e}")))?;

    let msg_hex = meta["message_bytes"]
        .as_str()
        .ok_or_else(|| CoreError::Serialization("missing message_bytes in tx_data".into()))?;

    let message_bytes = hex::decode(msg_hex)
        .map_err(|e| CoreError::Serialization(format!("invalid message_bytes hex: {e}")))?;

    // Build signed transaction: compact-u16(1) || sig(64) || message
    let mut raw_tx = Vec::with_capacity(1 + 64 + message_bytes.len());
    raw_tx.push(0x01u8); // compact-u16 encoding of 1 signature
    raw_tx.extend_from_slice(signature);
    raw_tx.extend_from_slice(&message_bytes);

    // tx_hash = full base58-encoded signature (matches Solana's convention
    // where the transaction ID is the base58 encoding of the first signature)
    let tx_hash = bs58::encode(signature).into_string();

    Ok(SignedTransaction {
        chain: Chain::Solana,
        raw_tx,
        tx_hash,
    })
}
