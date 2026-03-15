use mpc_wallet_core::error::CoreError;
use mpc_wallet_core::protocol::MpcSignature;

use crate::provider::{Chain, SignedTransaction, TransactionParams, UnsignedTransaction};

/// Build an unsigned EVM transaction (EIP-1559).
pub async fn build_evm_transaction(
    chain: Chain,
    chain_id: u64,
    params: TransactionParams,
) -> Result<UnsignedTransaction, CoreError> {
    use alloy::consensus::TxEip1559;
    use alloy::primitives::{Address, Bytes, TxKind, U256};

    let to_addr: Address = params
        .to
        .parse()
        .map_err(|e| CoreError::InvalidInput(format!("invalid to address: {e}")))?;

    let value = U256::from_str_radix(params.value.trim_start_matches("0x"), 16)
        .or_else(|_| {
            params
                .value
                .parse::<u128>()
                .map(U256::from)
                .map_err(|e| CoreError::InvalidInput(format!("invalid value: {e}")))
        })
        .map_err(|e| CoreError::InvalidInput(format!("invalid value: {e}")))?;

    let tx = TxEip1559 {
        chain_id,
        nonce: params
            .extra
            .as_ref()
            .and_then(|e| e.get("nonce"))
            .and_then(|v| v.as_u64())
            .unwrap_or(0),
        gas_limit: params
            .extra
            .as_ref()
            .and_then(|e| e.get("gas_limit"))
            .and_then(|v| v.as_u64())
            .unwrap_or(21000),
        max_fee_per_gas: params
            .extra
            .as_ref()
            .and_then(|e| e.get("max_fee_per_gas"))
            .and_then(|v| v.as_u64())
            .map(|v| v as u128)
            .unwrap_or(30_000_000_000), // 30 gwei default
        max_priority_fee_per_gas: params
            .extra
            .as_ref()
            .and_then(|e| e.get("max_priority_fee_per_gas"))
            .and_then(|v| v.as_u64())
            .map(|v| v as u128)
            .unwrap_or(1_000_000_000), // 1 gwei default
        to: TxKind::Call(to_addr),
        value,
        input: Bytes::from(params.data.unwrap_or_default()),
        access_list: Default::default(),
    };

    // Compute the signing hash (EIP-1559 signing payload)
    use alloy::consensus::SignableTransaction;
    let tx_clone = tx.clone();
    let sign_hash = tx_clone.signature_hash().to_vec();

    let tx_data =
        serde_json::to_vec(&tx).map_err(|e| CoreError::Serialization(e.to_string()))?;

    Ok(UnsignedTransaction {
        chain,
        sign_payload: sign_hash,
        tx_data,
    })
}

/// Finalize an EVM transaction by attaching the ECDSA signature.
pub fn finalize_evm_transaction(
    unsigned: &UnsignedTransaction,
    sig: &MpcSignature,
) -> Result<SignedTransaction, CoreError> {
    use alloy::consensus::{SignableTransaction, TxEip1559, TxEnvelope};
    use alloy::eips::Encodable2718;
    use alloy::primitives::{Signature, B256};

    let MpcSignature::Ecdsa { r, s, recovery_id } = sig else {
        return Err(CoreError::InvalidInput(
            "EVM requires ECDSA signature".into(),
        ));
    };

    let tx: TxEip1559 = serde_json::from_slice(&unsigned.tx_data)
        .map_err(|e| CoreError::Serialization(e.to_string()))?;

    // Build the signature
    let r_b256 = B256::from_slice(r);
    let s_b256 = B256::from_slice(s);
    let parity = *recovery_id & 1 == 1;
    let alloy_sig = Signature::from_scalars_and_parity(r_b256, s_b256, parity);

    // Create signed transaction
    let signed = tx.into_signed(alloy_sig);
    let envelope = TxEnvelope::Eip1559(signed);

    // Encode using EIP-2718
    let raw_tx = envelope.encoded_2718();
    let tx_hash = format!("0x{}", hex::encode(envelope.tx_hash()));

    Ok(SignedTransaction {
        chain: unsigned.chain,
        raw_tx,
        tx_hash,
    })
}
