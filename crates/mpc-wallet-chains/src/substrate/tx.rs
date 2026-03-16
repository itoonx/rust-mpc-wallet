//! Substrate SCALE-encoded extrinsic building.
//!
//! Implements a simplified SCALE extrinsic format for balance transfers.
//! Full runtime-aware extrinsic building requires metadata parsing.

use blake2::{digest::consts::U32, Blake2b, Digest};
use serde::{Deserialize, Serialize};

use mpc_wallet_core::error::CoreError;
use mpc_wallet_core::protocol::MpcSignature;

use crate::provider::{Chain, SignedTransaction, TransactionParams, UnsignedTransaction};

type Blake2b256 = Blake2b<U32>;

/// Substrate extrinsic payload for a balance transfer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubstrateTransferPayload {
    /// Pallet index (5 = Balances on most Substrate chains)
    pub pallet_index: u8,
    /// Call index (0 = transfer, 7 = transfer_allow_death)
    pub call_index: u8,
    /// Destination account ID (32 bytes)
    pub dest: Vec<u8>,
    /// Transfer amount
    pub value: u128,
    /// Nonce
    pub nonce: u32,
    /// Era (0 = immortal)
    pub era: u8,
    /// Tip
    pub tip: u128,
    /// Spec version
    pub spec_version: u32,
    /// Transaction version
    pub tx_version: u32,
    /// Genesis hash (32 bytes)
    pub genesis_hash: Vec<u8>,
    /// Block hash (32 bytes, same as genesis for immortal era)
    pub block_hash: Vec<u8>,
}

/// SCALE compact encoding for u128 values.
pub fn encode_compact(value: u128) -> Vec<u8> {
    if value < 0x40 {
        vec![(value << 2) as u8]
    } else if value < 0x4000 {
        let v = (value << 2) | 0x01;
        (v as u16).to_le_bytes().to_vec()
    } else if value < 0x4000_0000 {
        let v = (value << 2) | 0x02;
        (v as u32).to_le_bytes().to_vec()
    } else {
        let bytes = value.to_le_bytes();
        let len = bytes.iter().rposition(|&b| b != 0).map_or(1, |p| p + 1);
        let mut result = vec![((len - 4) << 2 | 0x03) as u8];
        result.extend_from_slice(&bytes[..len]);
        result
    }
}

/// Build an unsigned Substrate extrinsic.
pub async fn build_substrate_transaction(
    chain: Chain,
    params: TransactionParams,
) -> Result<UnsignedTransaction, CoreError> {
    let value: u128 = params
        .value
        .parse()
        .map_err(|_| CoreError::InvalidInput(format!("invalid amount: {}", params.value)))?;

    let extra = params.extra.as_ref();
    let nonce = extra.and_then(|e| e["nonce"].as_u64()).unwrap_or(0) as u32;
    let spec_version = extra.and_then(|e| e["spec_version"].as_u64()).unwrap_or(1) as u32;
    let tx_version = extra.and_then(|e| e["tx_version"].as_u64()).unwrap_or(1) as u32;

    // Build call data: pallet_index(1) || call_index(1) || dest(33) || compact_value
    let mut call_data = Vec::new();
    call_data.push(0x05); // Balances pallet
    call_data.push(0x07); // transfer_allow_death
                          // MultiAddress::Id prefix
    call_data.push(0x00);
    // Destination (32 bytes from address or hex)
    let dest_bytes = hex::decode(params.to.strip_prefix("0x").unwrap_or(&params.to))
        .unwrap_or_else(|_| params.to.as_bytes()[..32.min(params.to.len())].to_vec());
    let mut dest_padded = [0u8; 32];
    let copy_len = dest_bytes.len().min(32);
    dest_padded[..copy_len].copy_from_slice(&dest_bytes[..copy_len]);
    call_data.extend_from_slice(&dest_padded);
    // Compact-encoded value
    call_data.extend_from_slice(&encode_compact(value));

    // Build signing payload: call_data || era || nonce || tip || spec_version || tx_version || genesis_hash || block_hash
    let mut signing_payload = call_data.clone();
    signing_payload.push(0x00); // immortal era
    signing_payload.extend_from_slice(&encode_compact(nonce as u128));
    signing_payload.extend_from_slice(&encode_compact(0u128)); // tip = 0
    signing_payload.extend_from_slice(&spec_version.to_le_bytes());
    signing_payload.extend_from_slice(&tx_version.to_le_bytes());
    signing_payload.extend_from_slice(&[0u8; 32]); // genesis_hash placeholder
    signing_payload.extend_from_slice(&[0u8; 32]); // block_hash placeholder

    // Blake2b-256 hash of the signing payload
    let sign_payload = Blake2b256::digest(&signing_payload).to_vec();

    // Store call_data as tx_data (used in finalization)
    Ok(UnsignedTransaction {
        chain,
        sign_payload,
        tx_data: call_data,
    })
}

/// Finalize a Substrate extrinsic with Ed25519 signature.
pub fn finalize_substrate_transaction(
    unsigned: &UnsignedTransaction,
    sig: &MpcSignature,
    chain_name: &str,
) -> Result<SignedTransaction, CoreError> {
    let sig_bytes = match sig {
        MpcSignature::EdDsa { signature } => signature.to_vec(),
        _ => {
            return Err(CoreError::InvalidInput(format!(
                "{chain_name} requires EdDsa signature (Ed25519)"
            )))
        }
    };

    // Build signed extrinsic: [sig_type(0x00=Ed25519)] || sig(64) || call_data
    let mut raw_tx = Vec::new();
    raw_tx.push(0x00); // Ed25519 signature type
    raw_tx.extend_from_slice(&sig_bytes);
    raw_tx.extend_from_slice(&unsigned.tx_data);

    let tx_hash = hex::encode(&unsigned.sign_payload);

    Ok(SignedTransaction {
        chain: unsigned.chain,
        raw_tx,
        tx_hash,
    })
}
