//! Monero transaction building.
//!
//! Simplified Monero transaction prefix format. Full ring signature
//! and RingCT support requires a dedicated CryptoNote MPC protocol.

use serde::{Deserialize, Serialize};
use sha3::{Digest, Keccak256};

use mpc_wallet_core::error::CoreError;
use mpc_wallet_core::protocol::MpcSignature;

use crate::provider::{Chain, SignedTransaction, TransactionParams, UnsignedTransaction};

/// Monero transaction prefix (simplified).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MoneroTxPrefix {
    /// Transaction version (2 = RingCT)
    pub version: u8,
    /// Unlock time (0 = no lock)
    pub unlock_time: u64,
    /// Destination address
    pub dest: String,
    /// Amount in piconero (1 XMR = 10^12 piconero)
    pub amount: u64,
    /// Payment ID (optional)
    pub payment_id: Option<String>,
}

/// Build an unsigned Monero transaction.
pub async fn build_monero_transaction(
    params: TransactionParams,
) -> Result<UnsignedTransaction, CoreError> {
    let amount: u64 = params
        .value
        .parse()
        .map_err(|_| CoreError::InvalidInput(format!("invalid amount: {}", params.value)))?;

    let unlock_time = params
        .extra
        .as_ref()
        .and_then(|e| e["unlock_time"].as_u64())
        .unwrap_or(0);

    let payment_id = params
        .extra
        .as_ref()
        .and_then(|e| e["payment_id"].as_str())
        .map(String::from);

    let tx_prefix = MoneroTxPrefix {
        version: 2,
        unlock_time,
        dest: params.to.clone(),
        amount,
        payment_id,
    };

    // Serialize tx prefix
    let tx_data = serde_json::to_vec(&tx_prefix)
        .map_err(|e| CoreError::Protocol(format!("tx prefix serialization failed: {e}")))?;

    // Monero uses Keccak-256 for transaction hashing
    let sign_payload = Keccak256::digest(&tx_data).to_vec();

    Ok(UnsignedTransaction {
        chain: Chain::Monero,
        sign_payload,
        tx_data,
    })
}

/// Finalize a Monero transaction with Ed25519 signature.
pub fn finalize_monero_transaction(
    unsigned: &UnsignedTransaction,
    sig: &MpcSignature,
) -> Result<SignedTransaction, CoreError> {
    let sig_bytes = match sig {
        MpcSignature::EdDsa { signature } => signature.to_vec(),
        _ => {
            return Err(CoreError::InvalidInput(
                "Monero requires EdDsa signature".into(),
            ))
        }
    };

    let mut raw_tx = unsigned.tx_data.clone();
    raw_tx.extend_from_slice(&sig_bytes);

    let tx_hash = hex::encode(&unsigned.sign_payload);

    Ok(SignedTransaction {
        chain: Chain::Monero,
        raw_tx,
        tx_hash,
    })
}
