//! TRON transaction building.
//!
//! TRON uses Protobuf for transaction encoding. This is a simplified
//! representation that captures the essential transfer fields.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use mpc_wallet_core::error::CoreError;
use mpc_wallet_core::protocol::MpcSignature;

use crate::provider::{Chain, SignedTransaction, TransactionParams, UnsignedTransaction};

/// TRON transfer contract (simplified Protobuf).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TronTransferContract {
    /// Owner address (21 bytes: 0x41 + 20 bytes)
    pub owner_address: Vec<u8>,
    /// Destination address (21 bytes: 0x41 + 20 bytes)
    pub to_address: Vec<u8>,
    /// Amount in SUN (1 TRX = 1,000,000 SUN)
    pub amount: u64,
}

/// Build an unsigned TRON transaction.
pub async fn build_tron_transaction(
    params: TransactionParams,
) -> Result<UnsignedTransaction, CoreError> {
    let amount: u64 = params
        .value
        .parse()
        .map_err(|_| CoreError::InvalidInput(format!("invalid amount: {}", params.value)))?;

    // Build raw_data: simplified Protobuf-like encoding
    let mut raw_data = Vec::new();

    // Contract type tag (TransferContract = 1)
    raw_data.push(0x01);

    // Owner address from extra
    let owner_hex = params
        .extra
        .as_ref()
        .and_then(|e| e["owner_address"].as_str())
        .unwrap_or("41" /* placeholder */);
    let owner_bytes = hex::decode(owner_hex).unwrap_or_else(|_| vec![0x41; 21]);
    raw_data.extend_from_slice(&owner_bytes);

    // Destination address
    let to_bytes = bs58::decode(&params.to)
        .into_vec()
        .map(|v| v[..21].to_vec())
        .unwrap_or_else(|_| params.to.as_bytes().to_vec());
    raw_data.extend_from_slice(&to_bytes);

    // Amount (8 bytes BE)
    raw_data.extend_from_slice(&amount.to_be_bytes());

    // Timestamp
    let timestamp = params
        .extra
        .as_ref()
        .and_then(|e| e["timestamp"].as_u64())
        .unwrap_or(0);
    raw_data.extend_from_slice(&timestamp.to_be_bytes());

    // Expiration
    let expiration = params
        .extra
        .as_ref()
        .and_then(|e| e["expiration"].as_u64())
        .unwrap_or(timestamp + 60_000);
    raw_data.extend_from_slice(&expiration.to_be_bytes());

    // Sign payload = SHA-256(raw_data)
    let sign_payload = Sha256::digest(&raw_data).to_vec();

    Ok(UnsignedTransaction {
        chain: Chain::Tron,
        sign_payload,
        tx_data: raw_data,
    })
}

/// Finalize a TRON transaction with ECDSA signature.
pub fn finalize_tron_transaction(
    unsigned: &UnsignedTransaction,
    sig: &MpcSignature,
) -> Result<SignedTransaction, CoreError> {
    let (r, s, recovery_id) = match sig {
        MpcSignature::Ecdsa { r, s, recovery_id } => (r.clone(), s.clone(), *recovery_id),
        _ => {
            return Err(CoreError::InvalidInput(
                "TRON requires ECDSA signature".into(),
            ))
        }
    };

    // TRON signature: r(32) || s(32) || v(1)
    let mut raw_tx = unsigned.tx_data.clone();
    raw_tx.extend_from_slice(&r);
    raw_tx.extend_from_slice(&s);
    raw_tx.push(recovery_id);

    let tx_hash = hex::encode(&unsigned.sign_payload);

    Ok(SignedTransaction {
        chain: Chain::Tron,
        raw_tx,
        tx_hash,
    })
}
