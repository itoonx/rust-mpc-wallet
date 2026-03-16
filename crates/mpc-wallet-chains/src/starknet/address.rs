//! Starknet address derivation.
//!
//! Starknet address = pedersen_hash(contract_class_hash, salt, constructor_calldata_hash)
//! Simplified: SHA-256(pubkey) truncated to 251 bits (Stark field), displayed as 0x + 64 hex.

use mpc_wallet_core::error::CoreError;
use mpc_wallet_core::protocol::GroupPublicKey;
use sha2::{Digest, Sha256};

/// Derive a Starknet address from a public key.
///
/// Simplified: uses SHA-256 hash of the public key bytes as the contract address.
/// Full Starknet address derivation requires Pedersen hash of the class hash,
/// salt, and constructor calldata — this is a placeholder for the account address.
pub fn derive_starknet_address(group_pubkey: &GroupPublicKey) -> Result<String, CoreError> {
    let pubkey_bytes = match group_pubkey {
        GroupPublicKey::Secp256k1(bytes) => bytes.clone(),
        GroupPublicKey::Secp256k1Uncompressed(bytes) => bytes.clone(),
        GroupPublicKey::Ed25519(bytes) => bytes.clone(),
    };

    let hash = Sha256::digest(&pubkey_bytes);
    // Starknet addresses are 251-bit field elements, display as 0x + 64 hex
    // Mask the top bits to fit in the Stark field
    let mut addr_bytes = hash.to_vec();
    addr_bytes[0] &= 0x07; // Ensure < 2^251

    Ok(format!("0x{}", hex::encode(addr_bytes)))
}
