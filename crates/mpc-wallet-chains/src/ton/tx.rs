//! TON transaction building.
//!
//! Builds internal transfer messages and serializes them as Cell/BOC.

use sha2::{Digest, Sha256};

use mpc_wallet_core::error::CoreError;
use mpc_wallet_core::protocol::MpcSignature;

use crate::provider::{Chain, SignedTransaction, TransactionParams, UnsignedTransaction};
use crate::ton::address::validate_ton_address;
use crate::ton::cell;

/// Build an unsigned TON internal transfer message.
pub async fn build_ton_transaction(
    params: TransactionParams,
) -> Result<UnsignedTransaction, CoreError> {
    let value: u64 = params
        .value
        .parse()
        .map_err(|_| CoreError::InvalidInput(format!("invalid amount: {}", params.value)))?;

    // Parse destination address
    validate_ton_address(&params.to)?;
    let parts: Vec<&str> = params.to.splitn(2, ':').collect();
    let dest_workchain: i8 = parts[0].parse().unwrap_or(0);
    let dest_hash_bytes = hex::decode(parts[1])
        .map_err(|e| CoreError::InvalidInput(format!("invalid destination hash: {e}")))?;
    let mut dest_hash = [0u8; 32];
    dest_hash.copy_from_slice(&dest_hash_bytes);

    // Build transfer Cell
    let bounce = params
        .extra
        .as_ref()
        .and_then(|e| e["bounce"].as_bool())
        .unwrap_or(true);
    let transfer_cell = cell::build_transfer_cell(dest_workchain, &dest_hash, value, bounce);
    let boc = transfer_cell.to_boc();

    // Sign payload = SHA-256(cell hash)
    let sign_payload = Sha256::digest(transfer_cell.hash()).to_vec();

    Ok(UnsignedTransaction {
        chain: Chain::Ton,
        sign_payload,
        tx_data: boc,
    })
}

/// Finalize a TON transaction with Ed25519 signature.
pub fn finalize_ton_transaction(
    unsigned: &UnsignedTransaction,
    sig: &MpcSignature,
) -> Result<SignedTransaction, CoreError> {
    let sig_bytes = match sig {
        MpcSignature::EdDsa { signature } => signature.to_vec(),
        _ => {
            return Err(CoreError::InvalidInput(
                "TON requires EdDsa signature".into(),
            ))
        }
    };

    // Signed BOC: signature(64) || boc_data
    let mut raw_tx = Vec::with_capacity(64 + unsigned.tx_data.len());
    raw_tx.extend_from_slice(&sig_bytes);
    raw_tx.extend_from_slice(&unsigned.tx_data);

    let tx_hash = hex::encode(&unsigned.sign_payload);

    Ok(SignedTransaction {
        chain: Chain::Ton,
        raw_tx,
        tx_hash,
    })
}
