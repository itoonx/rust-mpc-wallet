//! Cosmos SDK transaction building.
//!
//! Implements a simplified Amino/JSON encoding for Cosmos MsgSend transactions.
//! Full Protobuf encoding (cosmos.tx.v1beta1) is a future enhancement.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use mpc_wallet_core::error::CoreError;
use mpc_wallet_core::protocol::MpcSignature;

use crate::provider::{Chain, SignedTransaction, TransactionParams, UnsignedTransaction};

/// Cosmos MsgSend — bank module transfer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CosmosMsgSend {
    pub from_address: String,
    pub to_address: String,
    pub amount: String,
    pub denom: String,
}

/// Cosmos SignDoc — the document that gets signed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CosmosSignDoc {
    pub chain_id: String,
    pub account_number: u64,
    pub sequence: u64,
    pub memo: String,
    pub msg: CosmosMsgSend,
    pub fee_amount: u64,
    pub gas_limit: u64,
}

/// Build an unsigned Cosmos transaction.
pub async fn build_cosmos_transaction(
    chain: Chain,
    chain_id: &str,
    denom: &str,
    params: TransactionParams,
) -> Result<UnsignedTransaction, CoreError> {
    let amount: u64 = params
        .value
        .parse()
        .map_err(|_| CoreError::InvalidInput(format!("invalid amount: {}", params.value)))?;

    let extra = params.extra.as_ref();
    let from_address = extra
        .and_then(|e| e["from_address"].as_str())
        .unwrap_or("")
        .to_string();
    let account_number = extra
        .and_then(|e| e["account_number"].as_u64())
        .unwrap_or(0);
    let sequence = extra.and_then(|e| e["sequence"].as_u64()).unwrap_or(0);
    let memo = extra
        .and_then(|e| e["memo"].as_str())
        .unwrap_or("")
        .to_string();
    let fee_amount = extra.and_then(|e| e["fee_amount"].as_u64()).unwrap_or(5000);
    let gas_limit = extra
        .and_then(|e| e["gas_limit"].as_u64())
        .unwrap_or(200_000);

    let sign_doc = CosmosSignDoc {
        chain_id: chain_id.to_string(),
        account_number,
        sequence,
        memo,
        msg: CosmosMsgSend {
            from_address,
            to_address: params.to.clone(),
            amount: amount.to_string(),
            denom: denom.to_string(),
        },
        fee_amount,
        gas_limit,
    };

    // Serialize SignDoc to JSON (Amino-compatible)
    let tx_data = serde_json::to_vec(&sign_doc)
        .map_err(|e| CoreError::Protocol(format!("SignDoc serialization failed: {e}")))?;

    // Sign payload = SHA-256(canonical JSON)
    let sign_payload = Sha256::digest(&tx_data).to_vec();

    Ok(UnsignedTransaction {
        chain,
        sign_payload,
        tx_data,
    })
}

/// Finalize a Cosmos transaction with ECDSA or EdDsa signature.
pub fn finalize_cosmos_transaction(
    unsigned: &UnsignedTransaction,
    sig: &MpcSignature,
    chain_name: &str,
) -> Result<SignedTransaction, CoreError> {
    let sig_bytes = match sig {
        MpcSignature::Ecdsa { r, s, .. } => {
            let mut bytes = Vec::with_capacity(64);
            bytes.extend_from_slice(r);
            bytes.extend_from_slice(s);
            bytes
        }
        MpcSignature::EdDsa { signature } => signature.to_vec(),
        _ => {
            return Err(CoreError::InvalidInput(format!(
                "{chain_name} requires ECDSA or EdDsa signature"
            )))
        }
    };

    let mut raw_tx = unsigned.tx_data.clone();
    raw_tx.extend_from_slice(&sig_bytes);

    let tx_hash = hex::encode(&unsigned.sign_payload);

    Ok(SignedTransaction {
        chain: unsigned.chain,
        raw_tx,
        tx_hash,
    })
}
