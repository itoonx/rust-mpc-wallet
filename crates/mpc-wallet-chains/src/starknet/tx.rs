//! Starknet transaction building.
//!
//! Implements a simplified InvokeTransaction v1 format.
//! Uses Pedersen hash for transaction hash computation (replacing SHA-256 placeholder).

use serde::{Deserialize, Serialize};
use starknet_crypto::{pedersen_hash, Felt};

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

/// Compute a Pedersen-based transaction hash for a StarkNet InvokeV1 transaction.
///
/// In the real StarkNet protocol, the tx hash is:
///   pedersen(tx_type, version, sender, entrypoint, calldata_hash, max_fee, chain_id, nonce)
///
/// This simplified version hashes the key transaction fields via chained Pedersen hashes.
fn compute_tx_hash(invoke: &StarknetInvokeV1) -> [u8; 32] {
    // "invoke" type marker.
    let tx_type = Felt::from_bytes_be_slice(b"invoke");
    let version = Felt::from(invoke.version as u64);
    let sender = Felt::from_bytes_be_slice(invoke.sender_address.as_bytes());
    let max_fee = Felt::from(invoke.max_fee);
    let chain_id = Felt::from_bytes_be_slice(invoke.chain_id.as_bytes());
    let nonce = Felt::from(invoke.nonce);

    // Hash the calldata array via chained Pedersen: h(h(h(0, c0), c1), c2)...
    let mut calldata_hash = Felt::ZERO;
    for cd in &invoke.calldata {
        let cd_felt = Felt::from_bytes_be_slice(cd.as_bytes());
        calldata_hash = pedersen_hash(&calldata_hash, &cd_felt);
    }
    // Include calldata length.
    calldata_hash = pedersen_hash(&calldata_hash, &Felt::from(invoke.calldata.len() as u64));

    // Chain all fields: h(h(h(h(h(h(tx_type, version), sender), calldata_hash), max_fee), chain_id), nonce)
    let h1 = pedersen_hash(&tx_type, &version);
    let h2 = pedersen_hash(&h1, &sender);
    let h3 = pedersen_hash(&h2, &calldata_hash);
    let h4 = pedersen_hash(&h3, &max_fee);
    let h5 = pedersen_hash(&h4, &chain_id);
    let h6 = pedersen_hash(&h5, &nonce);

    h6.to_bytes_be()
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

    // Compute transaction hash using Pedersen hash.
    let sign_payload = compute_tx_hash(&invoke).to_vec();

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
        MpcSignature::StarkSig { r, s } => {
            let mut bytes = Vec::with_capacity(64);
            bytes.extend_from_slice(r);
            bytes.extend_from_slice(s);
            bytes
        }
        MpcSignature::Ecdsa { r, s, .. } => {
            // Backward compatibility: accept ECDSA-format signatures too.
            let mut bytes = Vec::with_capacity(64);
            bytes.extend_from_slice(r);
            bytes.extend_from_slice(s);
            bytes
        }
        _ => {
            return Err(CoreError::InvalidInput(
                "Starknet requires StarkSig or ECDSA-compatible signature".into(),
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tx_hash_deterministic() {
        let invoke = StarknetInvokeV1 {
            sender_address: "0x1234".to_string(),
            calldata: vec!["0xdead".to_string(), "100".to_string()],
            max_fee: 100_000,
            nonce: 0,
            chain_id: "SN_MAIN".to_string(),
            version: 1,
        };
        let h1 = compute_tx_hash(&invoke);
        let h2 = compute_tx_hash(&invoke);
        assert_eq!(h1, h2, "tx hash must be deterministic");
    }

    #[test]
    fn test_tx_hash_changes_with_nonce() {
        let invoke1 = StarknetInvokeV1 {
            sender_address: "0x1234".to_string(),
            calldata: vec!["0xdead".to_string(), "100".to_string()],
            max_fee: 100_000,
            nonce: 0,
            chain_id: "SN_MAIN".to_string(),
            version: 1,
        };
        let invoke2 = StarknetInvokeV1 {
            sender_address: "0x1234".to_string(),
            calldata: vec!["0xdead".to_string(), "100".to_string()],
            max_fee: 100_000,
            nonce: 1,
            chain_id: "SN_MAIN".to_string(),
            version: 1,
        };
        assert_ne!(
            compute_tx_hash(&invoke1),
            compute_tx_hash(&invoke2),
            "different nonces must produce different hashes"
        );
    }

    #[tokio::test]
    async fn test_build_starknet_transaction() {
        let params = TransactionParams {
            to: "0xdead".to_string(),
            value: "100".to_string(),
            data: None,
            chain_id: None,
            extra: Some(serde_json::json!({
                "sender_address": "0x1234",
                "nonce": 5,
                "max_fee": 50000,
                "chain_id": "SN_GOERLI"
            })),
        };
        let unsigned = build_starknet_transaction(params).await.unwrap();
        assert_eq!(unsigned.chain, Chain::Starknet);
        assert_eq!(unsigned.sign_payload.len(), 32);
        assert!(!unsigned.tx_data.is_empty());
    }

    #[test]
    fn test_finalize_starknet_transaction_stark_sig() {
        let unsigned = UnsignedTransaction {
            chain: Chain::Starknet,
            sign_payload: vec![0x42; 32],
            tx_data: vec![0x01, 0x02, 0x03],
        };
        let sig = MpcSignature::StarkSig {
            r: vec![0xAA; 32],
            s: vec![0xBB; 32],
        };
        let signed = finalize_starknet_transaction(&unsigned, &sig).unwrap();
        assert_eq!(signed.chain, Chain::Starknet);
        // raw_tx = tx_data(3) + sig(64) = 67 bytes.
        assert_eq!(signed.raw_tx.len(), 67);
    }
}
