use mpc_wallet_core::error::CoreError;
use mpc_wallet_core::protocol::MpcSignature;

use crate::provider::{Chain, SignedTransaction, TransactionParams, UnsignedTransaction};

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

/// Build v0 versioned message bytes for a SOL transfer with optional ALTs.
///
/// v0 format:
///   [1]     version prefix = 0x80 (bit 7 set = versioned, bits 0-6 = version 0)
///   [1]     num_required_signatures
///   [1]     num_readonly_signed
///   [1]     num_readonly_unsigned
///   [cu16]  num_account_keys (static accounts only)
///   [32×N]  account_keys
///   [32]    recent_blockhash
///   [cu16]  num_instructions
///   [...]   instructions (same format as legacy)
///   [cu16]  num_address_table_lookups
///   per table:
///     [32]    table address
///     [cu16]  num_writable_indices
///     [u8×N]  writable_indices
///     [cu16]  num_readonly_indices
///     [u8×N]  readonly_indices
fn build_message_bytes_v0(
    from_bytes: &[u8; 32],
    to_bytes: &[u8; 32],
    lamports: u64,
    recent_blockhash: &[u8; 32],
    lookup_tables: &[AddressLookupTable],
) -> Vec<u8> {
    let mut msg = Vec::with_capacity(256);

    // Version prefix: 0x80 = versioned message, version 0
    msg.push(0x80);

    // Header (same as legacy for simple SOL transfer)
    msg.push(1u8); // num_required_signatures
    msg.push(0u8); // num_readonly_signed
    msg.push(1u8); // num_readonly_unsigned (system program)

    // Static account keys: 3 accounts (same as legacy)
    msg.extend_from_slice(&encode_compact_u16(3));
    msg.extend_from_slice(from_bytes);
    msg.extend_from_slice(to_bytes);
    msg.extend_from_slice(&[0u8; 32]); // system program

    // Recent blockhash
    msg.extend_from_slice(recent_blockhash);

    // Instructions: 1 instruction (same as legacy)
    msg.extend_from_slice(&encode_compact_u16(1));
    msg.push(2u8); // program_id_index = 2
    msg.extend_from_slice(&encode_compact_u16(2));
    msg.push(0u8); // from
    msg.push(1u8); // to
    msg.extend_from_slice(&encode_compact_u16(12));
    msg.extend_from_slice(&[2u8, 0u8, 0u8, 0u8]); // Transfer
    msg.extend_from_slice(&lamports.to_le_bytes());

    // Address table lookups
    msg.extend_from_slice(&encode_compact_u16(lookup_tables.len() as u16));
    for alt in lookup_tables {
        msg.extend_from_slice(&alt.address);
        // Writable indices
        msg.extend_from_slice(&encode_compact_u16(alt.writable_indices.len() as u16));
        msg.extend_from_slice(&alt.writable_indices);
        // Readonly indices
        msg.extend_from_slice(&encode_compact_u16(alt.readonly_indices.len() as u16));
        msg.extend_from_slice(&alt.readonly_indices);
    }

    msg
}

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
    let version = params
        .extra
        .as_ref()
        .and_then(|e| e.get("version"))
        .and_then(|v| v.as_str());

    // Build binary message
    let message_bytes = match version {
        Some("v0") => {
            // Parse lookup tables if present
            let lookup_tables = parse_lookup_tables(
                params.extra.as_ref().and_then(|e| e.get("lookup_tables")),
            )?;
            build_message_bytes_v0(&from_bytes, &to_bytes, lamports, &recent_blockhash, &lookup_tables)
        }
        _ => build_message_bytes(&from_bytes, &to_bytes, lamports, &recent_blockhash),
    };

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
