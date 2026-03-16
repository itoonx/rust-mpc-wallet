//! TRON address derivation.
//!
//! TRON address = Base58Check(0x41 + last 20 bytes of Keccak-256(uncompressed_pubkey[1..]))
//! Similar to Ethereum but with 0x41 prefix instead of raw hex.

use mpc_wallet_core::error::CoreError;
use mpc_wallet_core::protocol::GroupPublicKey;
use sha2::{Digest, Sha256};
use sha3::Keccak256;

/// Derive a TRON address from a secp256k1 public key.
///
/// Steps:
/// 1. Keccak-256 hash of the public key bytes (excluding 0x04 prefix for uncompressed)
/// 2. Take last 20 bytes
/// 3. Prepend 0x41 (TRON mainnet prefix)
/// 4. Base58Check encode (double SHA-256 checksum)
pub fn derive_tron_address(group_pubkey: &GroupPublicKey) -> Result<String, CoreError> {
    let pubkey_for_hash = match group_pubkey {
        GroupPublicKey::Secp256k1Uncompressed(bytes) => {
            if bytes.len() != 65 {
                return Err(CoreError::Crypto(
                    "invalid uncompressed secp256k1 key length".into(),
                ));
            }
            // Skip 0x04 prefix, hash remaining 64 bytes
            bytes[1..].to_vec()
        }
        GroupPublicKey::Secp256k1(bytes) => {
            if bytes.len() != 33 {
                return Err(CoreError::Crypto(
                    "invalid compressed secp256k1 key length".into(),
                ));
            }
            // For compressed keys, use the full 33 bytes
            bytes.clone()
        }
        GroupPublicKey::Ed25519(_) => {
            return Err(CoreError::Crypto(
                "TRON requires secp256k1 public key".into(),
            ));
        }
    };

    // Keccak-256 hash
    let hash = Keccak256::digest(&pubkey_for_hash);
    // Take last 20 bytes
    let addr_bytes = &hash[12..32];

    // Prepend 0x41 (TRON mainnet)
    let mut tron_addr = Vec::with_capacity(21);
    tron_addr.push(0x41);
    tron_addr.extend_from_slice(addr_bytes);

    // Base58Check: append first 4 bytes of double SHA-256
    let checksum = {
        let first = Sha256::digest(&tron_addr);
        let second = Sha256::digest(first);
        second[..4].to_vec()
    };
    tron_addr.extend_from_slice(&checksum);

    Ok(bs58::encode(tron_addr).into_string())
}

/// Validate a TRON address (Base58Check, starts with 'T').
pub fn validate_tron_address(addr: &str) -> Result<(), CoreError> {
    if !addr.starts_with('T') {
        return Err(CoreError::InvalidInput(format!(
            "TRON address must start with 'T', got: {addr}"
        )));
    }
    let decoded = bs58::decode(addr)
        .into_vec()
        .map_err(|e| CoreError::InvalidInput(format!("invalid TRON Base58 address: {e}")))?;
    if decoded.len() != 25 {
        return Err(CoreError::InvalidInput(format!(
            "TRON address must decode to 25 bytes, got {}",
            decoded.len()
        )));
    }
    if decoded[0] != 0x41 {
        return Err(CoreError::InvalidInput(
            "TRON address must have 0x41 prefix byte".into(),
        ));
    }
    // Verify checksum
    let payload = &decoded[..21];
    let checksum = &decoded[21..25];
    let first = Sha256::digest(payload);
    let second = Sha256::digest(first);
    if &second[..4] != checksum {
        return Err(CoreError::InvalidInput(
            "TRON address checksum mismatch".into(),
        ));
    }
    Ok(())
}
