//! UTXO transaction building for Litecoin, Dogecoin, Zcash.
//!
//! Builds legacy P2PKH transactions with proper serialization format:
//! version(4) || vin_count || [prev_txid(32) || vout(4) || scriptSig || sequence(4)] || vout_count || [value(8) || scriptPubKey] || locktime(4)

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use mpc_wallet_core::error::CoreError;
use mpc_wallet_core::protocol::MpcSignature;

use crate::provider::{Chain, SignedTransaction, TransactionParams, UnsignedTransaction};

/// A simplified UTXO transaction input.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UtxoInput {
    pub prev_txid: String,
    pub vout: u32,
    pub amount: u64,
}

/// A simplified UTXO transaction output.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UtxoOutput {
    pub address: String,
    pub amount: u64,
}

/// Build an unsigned UTXO transaction.
///
/// Reads inputs from `params.extra["inputs"]` as array of `{prev_txid, vout, amount}`.
/// Creates outputs from `params.to` + `params.value`.
/// Sign payload = double SHA-256 of the serialized unsigned tx.
pub async fn build_utxo_transaction(
    chain: Chain,
    params: TransactionParams,
) -> Result<UnsignedTransaction, CoreError> {
    let value: u64 = params
        .value
        .parse()
        .map_err(|_| CoreError::InvalidInput(format!("invalid amount: {}", params.value)))?;

    // Serialize transaction data
    let mut tx_data = Vec::new();

    // Version (4 bytes, little-endian) — version 2 for all UTXO chains
    tx_data.extend_from_slice(&2u32.to_le_bytes());

    // Parse inputs from extra
    let inputs: Vec<UtxoInput> = if let Some(extra) = &params.extra {
        if let Some(inputs_val) = extra.get("inputs") {
            serde_json::from_value(inputs_val.clone()).unwrap_or_default()
        } else {
            // Default: single empty input placeholder
            vec![UtxoInput {
                prev_txid: "0".repeat(64),
                vout: 0,
                amount: value,
            }]
        }
    } else {
        vec![UtxoInput {
            prev_txid: "0".repeat(64),
            vout: 0,
            amount: value,
        }]
    };

    // Input count (compact size)
    tx_data.push(inputs.len() as u8);

    // Serialize inputs
    for input in &inputs {
        // Previous txid (32 bytes, reversed)
        let txid_bytes = hex::decode(&input.prev_txid)
            .map_err(|e| CoreError::InvalidInput(format!("invalid prev_txid: {e}")))?;
        let mut reversed = txid_bytes;
        reversed.reverse();
        tx_data.extend_from_slice(&reversed);
        // Vout (4 bytes LE)
        tx_data.extend_from_slice(&input.vout.to_le_bytes());
        // scriptSig placeholder (empty for unsigned)
        tx_data.push(0x00); // scriptSig length = 0
                            // Sequence (4 bytes)
        tx_data.extend_from_slice(&0xFFFFFFFFu32.to_le_bytes());
    }

    // Output count
    tx_data.push(1u8);

    // Output: value (8 bytes LE) + scriptPubKey placeholder
    tx_data.extend_from_slice(&value.to_le_bytes());
    // P2PKH scriptPubKey placeholder (25 bytes)
    let addr_hash = Sha256::digest(params.to.as_bytes());
    tx_data.push(25); // scriptPubKey length
    tx_data.push(0x76); // OP_DUP
    tx_data.push(0xA9); // OP_HASH160
    tx_data.push(0x14); // Push 20 bytes
    tx_data.extend_from_slice(&addr_hash[..20]);
    tx_data.push(0x88); // OP_EQUALVERIFY
    tx_data.push(0xAC); // OP_CHECKSIG

    // Locktime (4 bytes)
    tx_data.extend_from_slice(&0u32.to_le_bytes());

    // Sign payload = double SHA-256
    let first = Sha256::digest(&tx_data);
    let sign_payload = Sha256::digest(first).to_vec();

    Ok(UnsignedTransaction {
        chain,
        sign_payload,
        tx_data,
    })
}

/// Finalize a UTXO transaction with an ECDSA signature.
pub fn finalize_utxo_transaction(
    unsigned: &UnsignedTransaction,
    sig: &MpcSignature,
    coin_name: &str,
) -> Result<SignedTransaction, CoreError> {
    let (r, s) = match sig {
        MpcSignature::Ecdsa { r, s, .. } => (r.clone(), s.clone()),
        _ => {
            return Err(CoreError::InvalidInput(format!(
                "{coin_name} requires ECDSA signature"
            )))
        }
    };

    // Build signed tx: unsigned tx data + DER signature appended
    let mut raw_tx = unsigned.tx_data.clone();
    // DER-encoded signature: 0x30 [len] 0x02 [r_len] [r] 0x02 [s_len] [s] [sighash_type]
    let der_sig = {
        let mut sig = vec![0x30, (r.len() + s.len() + 4) as u8, 0x02, r.len() as u8];
        sig.extend_from_slice(&r);
        sig.push(0x02);
        sig.push(s.len() as u8);
        sig.extend_from_slice(&s);
        sig.push(0x01); // SIGHASH_ALL
        sig
    };
    raw_tx.extend_from_slice(&der_sig);

    let tx_hash = hex::encode(&unsigned.sign_payload);

    Ok(SignedTransaction {
        chain: unsigned.chain,
        raw_tx,
        tx_hash,
    })
}
