use mpc_wallet_core::error::CoreError;
use mpc_wallet_core::protocol::MpcSignature;

use crate::provider::{Chain, SignedTransaction, TransactionParams, UnsignedTransaction};
use crate::solana::ata::{derive_ata, TOKEN_2022_PROGRAM_ID, TOKEN_PROGRAM_ID};
use crate::solana::instruction::{
    build_message, AccountMeta, Instruction, MessageVersion as IxMessageVersion,
};
use crate::solana::spl;
use crate::token::{SplProgram, TokenIdentifier};

/// Solana transaction message version.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SolanaMessageVersion {
    /// Legacy message format (no version prefix byte).
    Legacy,
    /// Version 0 message format with Address Lookup Table support.
    V0,
}

/// An address lookup table reference for v0 versioned transactions.
///
/// Each ALT allows instructions to reference accounts by u8 index
/// instead of including the full 32-byte public key, reducing tx size.
#[derive(Debug, Clone)]
pub struct AddressLookupTable {
    /// The on-chain address of the lookup table account (32 bytes).
    pub address: [u8; 32],
    /// Indices of writable accounts in this lookup table.
    pub writable_indices: Vec<u8>,
    /// Indices of read-only accounts in this lookup table.
    pub readonly_indices: Vec<u8>,
}

// Removed in Sprint 49: hardcoded `build_message_bytes` / `build_message_bytes_v0`
// encoders. Native SOL transfer now flows through `instruction::build_message`
// via `system_transfer_instruction` below — keeps account-ordering rules in
// one place and lets SPL token transfers reuse the same path.

/// Parse address lookup tables from JSON value.
fn parse_lookup_tables(
    val: Option<&serde_json::Value>,
) -> Result<Vec<AddressLookupTable>, CoreError> {
    let Some(arr) = val.and_then(|v| v.as_array()) else {
        return Ok(Vec::new());
    };

    let mut tables = Vec::with_capacity(arr.len());
    for item in arr {
        let address_str = item["address"]
            .as_str()
            .ok_or_else(|| CoreError::InvalidInput("ALT missing 'address'".into()))?;
        let address = decode_base58_32(address_str, "lookup_table_address")?;

        let writable_indices: Vec<u8> = item
            .get("writable_indices")
            .and_then(|v| v.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|v| v.as_u64().map(|n| n as u8))
                    .collect()
            })
            .unwrap_or_default();

        let readonly_indices: Vec<u8> = item
            .get("readonly_indices")
            .and_then(|v| v.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|v| v.as_u64().map(|n| n as u8))
                    .collect()
            })
            .unwrap_or_default();

        tables.push(AddressLookupTable {
            address,
            writable_indices,
            readonly_indices,
        });
    }

    Ok(tables)
}

/// Build the system program `Transfer` instruction (lamports between two
/// accounts). System program ID = all-zeros (32 bytes).
fn system_transfer_instruction(from: [u8; 32], to: [u8; 32], lamports: u64) -> Instruction {
    let mut data = Vec::with_capacity(12);
    data.extend_from_slice(&[2u8, 0, 0, 0]); // SystemInstruction::Transfer = 2 (u32 LE)
    data.extend_from_slice(&lamports.to_le_bytes());
    Instruction {
        program_id: [0u8; 32],
        accounts: vec![
            AccountMeta::writable(from, true),
            AccountMeta::writable(to, false),
        ],
        data,
    }
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

    // Determine version
    let version_str = params
        .extra
        .as_ref()
        .and_then(|e| e.get("version"))
        .and_then(|v| v.as_str());
    let ix_version = match version_str {
        Some("v0") => IxMessageVersion::V0,
        _ => IxMessageVersion::Legacy,
    };
    let lookup_tables = if ix_version == IxMessageVersion::V0 {
        parse_lookup_tables(params.extra.as_ref().and_then(|e| e.get("lookup_tables")))?
    } else {
        Vec::new()
    };

    // Token-aware instruction list. Native = single SystemProgram::Transfer.
    // SPL = optional CreateATAIdempotent (recipient ATA) + TransferChecked.
    let token =
        TokenIdentifier::from_extra(params.extra.as_ref()).map_err(CoreError::InvalidInput)?;
    let instructions = match token {
        TokenIdentifier::Native => {
            vec![system_transfer_instruction(from_bytes, to_bytes, lamports)]
        }
        TokenIdentifier::Spl {
            mint,
            program,
            decimals,
        } => {
            let mint_bytes = decode_base58_32(&mint, "mint")?;
            let token_program = match program {
                SplProgram::SplToken => TOKEN_PROGRAM_ID,
                SplProgram::Token2022 => TOKEN_2022_PROGRAM_ID,
            };
            let source_ata = derive_ata(&from_bytes, &mint_bytes, &token_program);
            let dest_ata = derive_ata(&to_bytes, &mint_bytes, &token_program);
            vec![
                // Always include create-ATA-idempotent — no-op if recipient
                // already has an ATA, costs sender ~0.002 SOL rent otherwise.
                spl::create_ata_idempotent(
                    from_bytes,
                    dest_ata,
                    to_bytes,
                    mint_bytes,
                    token_program,
                ),
                spl::transfer_checked(
                    source_ata,
                    mint_bytes,
                    dest_ata,
                    from_bytes,
                    lamports, // for SPL, `value` is the token amount in smallest unit
                    decimals,
                    token_program,
                ),
            ]
        }
        other => {
            return Err(CoreError::InvalidInput(format!(
                "Solana build_transaction got non-Solana token spec: {other:?}"
            )));
        }
    };

    let message_bytes = build_message(
        from_bytes,
        &instructions,
        &recent_blockhash,
        ix_version,
        &lookup_tables,
    );

    // tx_data carries the hex-encoded message plus metadata for finalize
    let tx_data_json = serde_json::json!({
        "message_bytes": hex::encode(&message_bytes),
        "from": from_str,
        "to": to_str,
        "lamports": lamports,
    });
    let tx_data =
        serde_json::to_vec(&tx_data_json).map_err(|e| CoreError::Serialization(e.to_string()))?;

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

/// Decode a Solana wire-format signed transaction and return a one-line summary.
/// Format: `[1B sig_count] [64B sig] [message...]`.
pub fn decode_solana_summary(raw_tx: &[u8]) -> Result<String, CoreError> {
    if raw_tx.len() < 1 + 64 {
        return Err(CoreError::Other(format!(
            "raw_tx too short: {} bytes",
            raw_tx.len()
        )));
    }
    let sig_count = raw_tx[0];
    let sig_hex = hex::encode(&raw_tx[1..65]);
    let msg = &raw_tx[65..];
    let msg_len = msg.len();
    // Try to extract recipient + lamports for legacy single-transfer messages.
    Ok(format!(
        "sig_count={sig_count} message_len={msg_len} sig_first8={}…",
        &sig_hex[..16]
    ))
}

/// Pre-broadcast sanity check: verify the Ed25519 signature against the
/// signing message and the derived sender pubkey. Aborts before broadcast if
/// the signature does not validate.
pub fn verify_solana_signature(
    sender_base58: &str,
    sig: &MpcSignature,
    sign_payload: &[u8],
) -> Result<(), CoreError> {
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};

    let MpcSignature::EdDsa { signature } = sig else {
        return Err(CoreError::InvalidInput(
            "Solana requires EdDSA signature for verification".into(),
        ));
    };
    if signature.len() != 64 {
        return Err(CoreError::Crypto(format!(
            "expected 64-byte EdDSA sig, got {}",
            signature.len()
        )));
    }
    let pubkey_bytes = decode_base58_32(sender_base58, "sender")?;
    let vk = VerifyingKey::from_bytes(&pubkey_bytes)
        .map_err(|e| CoreError::Crypto(format!("invalid sender pubkey: {e}")))?;
    let sig_array: [u8; 64] = signature
        .as_slice()
        .try_into()
        .map_err(|_| CoreError::Crypto("sig must be 64 bytes".into()))?;
    let signature = Signature::from_bytes(&sig_array);
    vk.verify(sign_payload, &signature)
        .map_err(|e| CoreError::Crypto(format!("Ed25519 verify failed: {e}")))?;
    Ok(())
}
