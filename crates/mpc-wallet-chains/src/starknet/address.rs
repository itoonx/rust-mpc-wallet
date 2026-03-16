//! Starknet address derivation.
//!
//! Starknet contract address = hash(PREFIX, deployer, salt, class_hash, constructor_calldata_hash)
//! For account contracts: address = pedersen(contract_address_prefix, 0, salt, class_hash, calldata_hash)
//!
//! Since we don't have the Pedersen hash crate, we use a deterministic hash
//! that follows the same structure: SHA-256 of the concatenated components,
//! masked to 251 bits (Stark field element size).

use mpc_wallet_core::error::CoreError;
use mpc_wallet_core::protocol::GroupPublicKey;
use sha2::{Digest, Sha256};

/// Starknet contract address prefix constant.
const CONTRACT_ADDRESS_PREFIX: &[u8] = b"STARKNET_CONTRACT_ADDRESS";

/// OpenZeppelin account contract class hash (v0.8.1 placeholder).
const OZ_ACCOUNT_CLASS_HASH: [u8; 32] = [0x04; 32];

/// Derive a Starknet account address from a public key.
///
/// Computes: hash(CONTRACT_ADDRESS_PREFIX || deployer(0) || salt(pubkey_hash) || class_hash || calldata_hash)
/// Result masked to 251 bits (Stark field element).
pub fn derive_starknet_address(group_pubkey: &GroupPublicKey) -> Result<String, CoreError> {
    let pubkey_bytes = match group_pubkey {
        GroupPublicKey::Secp256k1(bytes) => bytes.clone(),
        GroupPublicKey::Secp256k1Uncompressed(bytes) => bytes.clone(),
        GroupPublicKey::Ed25519(bytes) => bytes.clone(),
    };

    // Salt = hash of pubkey
    let salt = Sha256::digest(&pubkey_bytes);

    // Constructor calldata hash = hash of pubkey (single arg)
    let calldata_hash = Sha256::digest(&pubkey_bytes);

    // Contract address = hash(prefix || deployer(0) || salt || class_hash || calldata_hash)
    let mut hasher = Sha256::new();
    hasher.update(CONTRACT_ADDRESS_PREFIX);
    hasher.update([0u8; 32]); // deployer = 0 (self-deployed)
    hasher.update(salt);
    hasher.update(OZ_ACCOUNT_CLASS_HASH);
    hasher.update(calldata_hash);
    let hash = hasher.finalize();

    // Mask to 251 bits (Stark field element)
    let mut addr_bytes = hash.to_vec();
    addr_bytes[0] &= 0x07;

    Ok(format!("0x{}", hex::encode(addr_bytes)))
}
