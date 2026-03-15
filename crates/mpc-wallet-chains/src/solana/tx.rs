use mpc_wallet_core::error::CoreError;
use mpc_wallet_core::protocol::MpcSignature;

use crate::provider::{Chain, SignedTransaction, TransactionParams, UnsignedTransaction};

/// Build an unsigned Solana transaction.
/// Solana transactions sign the raw message bytes (not a hash).
pub async fn build_solana_transaction(
    params: TransactionParams,
) -> Result<UnsignedTransaction, CoreError> {
    // Build a simple SOL transfer transaction
    // In production, this would use the Solana SDK for complex instructions
    let recent_blockhash = params
        .extra
        .as_ref()
        .and_then(|e| e.get("recent_blockhash"))
        .and_then(|v| v.as_str())
        .unwrap_or("11111111111111111111111111111111");

    let from_pubkey = params
        .extra
        .as_ref()
        .and_then(|e| e.get("from_pubkey"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| CoreError::InvalidInput("missing from_pubkey".into()))?;

    let lamports: u64 = params
        .value
        .parse()
        .map_err(|e| CoreError::InvalidInput(format!("invalid lamports value: {e}")))?;

    // Serialize minimal transaction data for signing
    let tx_info = serde_json::json!({
        "from": from_pubkey,
        "to": params.to,
        "lamports": lamports,
        "recent_blockhash": recent_blockhash,
    });

    let tx_data = serde_json::to_vec(&tx_info)
        .map_err(|e| CoreError::Serialization(e.to_string()))?;

    // The sign payload for Solana is the serialized message (not hashed)
    // In a real implementation, this would be the properly serialized Solana message
    let sign_payload = tx_data.clone();

    Ok(UnsignedTransaction {
        chain: Chain::Solana,
        sign_payload,
        tx_data,
    })
}

/// Finalize a Solana transaction with an EdDSA signature.
pub fn finalize_solana_transaction(
    unsigned: &UnsignedTransaction,
    sig: &MpcSignature,
) -> Result<SignedTransaction, CoreError> {
    let MpcSignature::EdDsa { signature } = sig else {
        return Err(CoreError::InvalidInput(
            "Solana requires EdDSA signature".into(),
        ));
    };

    // Combine signature + message into signed transaction
    let signed_data = serde_json::json!({
        "signature": hex::encode(signature),
        "message": hex::encode(&unsigned.tx_data),
    });

    let raw_tx = serde_json::to_vec(&signed_data)
        .map_err(|e| CoreError::Serialization(e.to_string()))?;

    // Transaction "hash" is the signature in base58
    let tx_hash = bs58::encode(signature).into_string();

    Ok(SignedTransaction {
        chain: Chain::Solana,
        raw_tx,
        tx_hash,
    })
}
