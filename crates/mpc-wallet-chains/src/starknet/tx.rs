//! Starknet transaction building.
//!
//! Implements a simplified InvokeTransaction v1 format.
//! Full Pedersen hash and STARK curve signing are planned.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use mpc_wallet_core::error::CoreError;
use mpc_wallet_core::protocol::MpcSignature;

use crate::provider::{Chain, SignedTransaction, TransactionParams, UnsignedTransaction};

/// Starknet InvokeTransaction v1 (simplified).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StarknetInvokeV1 {
    /// Sender contract address (felt252)
    pub sender_address: String,
    /// Calldata (array of felt252 values)
    pub calldata: Vec<String>,
    /// Maximum fee willing to pay
    pub max_fee: u64,
    /// Transaction nonce
    pub nonce: u64,
    /// Chain ID ("SN_MAIN" or "SN_GOERLI")
    pub chain_id: String,
    /// Version (1 for InvokeV1)
    pub version: u8,
}

/// Build an unsigned Starknet transaction.
pub async fn build_starknet_transaction(
    params: TransactionParams,
) -> Result<UnsignedTransaction, CoreError> {
    let value: u64 = params
        .value
        .parse()
        .map_err(|_| CoreError::InvalidInput(format!("invalid amount: {}", params.value)))?;

    let extra = params.extra.as_ref();
    let sender = extra
        .and_then(|e| e["sender_address"].as_str())
        .unwrap_or("0x0")
        .to_string();
    let nonce = extra.and_then(|e| e["nonce"].as_u64()).unwrap_or(0);
    let max_fee = extra.and_then(|e| e["max_fee"].as_u64()).unwrap_or(100_000);
    let chain_id = extra
        .and_then(|e| e["chain_id"].as_str())
        .unwrap_or("SN_MAIN")
        .to_string();

    let invoke = StarknetInvokeV1 {
        sender_address: sender,
        calldata: vec![params.to.clone(), value.to_string()],
        max_fee,
        nonce,
        chain_id,
        version: 1,
    };

    let tx_data = serde_json::to_vec(&invoke)
        .map_err(|e| CoreError::Protocol(format!("tx serialization failed: {e}")))?;

    // Simplified tx hash (Pedersen hash in production)
    let sign_payload = Sha256::digest(&tx_data).to_vec();

    Ok(UnsignedTransaction {
        chain: Chain::Starknet,
        sign_payload,
        tx_data,
    })
}

/// Finalize a Starknet transaction with signature.
pub fn finalize_starknet_transaction(
    unsigned: &UnsignedTransaction,
    sig: &MpcSignature,
) -> Result<SignedTransaction, CoreError> {
    let sig_bytes = match sig {
        MpcSignature::Ecdsa { r, s, .. } => {
            let mut bytes = Vec::with_capacity(64);
            bytes.extend_from_slice(r);
            bytes.extend_from_slice(s);
            bytes
        }
        _ => {
            return Err(CoreError::InvalidInput(
                "Starknet requires ECDSA-compatible signature (STARK curve planned)".into(),
            ))
        }
    };

    let mut raw_tx = unsigned.tx_data.clone();
    raw_tx.extend_from_slice(&sig_bytes);

    let tx_hash = hex::encode(&unsigned.sign_payload);

    Ok(SignedTransaction {
        chain: Chain::Starknet,
        raw_tx,
        tx_hash,
    })
}
