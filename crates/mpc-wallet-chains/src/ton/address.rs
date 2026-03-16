//! TON address derivation.
//!
//! TON raw address = `workchain_id:sha256(state_init)`
//! User-friendly address = Base64url with flags + checksum (CRC16-CCITT)

use mpc_wallet_core::error::CoreError;
use mpc_wallet_core::protocol::GroupPublicKey;
use sha2::{Digest, Sha256};

/// Derive a TON raw address from an Ed25519 public key.
///
/// Raw format: `0:hex(sha256(pubkey))`
/// The workchain_id is 0 (basechain).
pub fn derive_ton_address(group_pubkey: &GroupPublicKey) -> Result<String, CoreError> {
    let pubkey_bytes = match group_pubkey {
        GroupPublicKey::Ed25519(bytes) => {
            if bytes.len() != 32 {
                return Err(CoreError::Crypto(
                    "invalid Ed25519 public key length".into(),
                ));
            }
            bytes.clone()
        }
        _ => {
            return Err(CoreError::Crypto("TON requires Ed25519 public key".into()));
        }
    };

    // Simplified: hash pubkey to get address hash
    // In production, this would hash the StateInit (code + data cells)
    let hash = Sha256::digest(&pubkey_bytes);

    // Raw address: workchain:hash
    Ok(format!("0:{}", hex::encode(hash)))
}

/// Validate a TON raw address format: `workchain_id:64_hex_chars`.
pub fn validate_ton_address(addr: &str) -> Result<(), CoreError> {
    let parts: Vec<&str> = addr.splitn(2, ':').collect();
    if parts.len() != 2 {
        return Err(CoreError::InvalidInput(format!(
            "TON address must be 'workchain:hash', got: {addr}"
        )));
    }
    let _workchain: i8 = parts[0]
        .parse()
        .map_err(|_| CoreError::InvalidInput(format!("invalid TON workchain_id: {}", parts[0])))?;
    let hash_hex = parts[1];
    if hash_hex.len() != 64 {
        return Err(CoreError::InvalidInput(format!(
            "TON address hash must be 64 hex chars, got {}",
            hash_hex.len()
        )));
    }
    hex::decode(hash_hex)
        .map_err(|e| CoreError::InvalidInput(format!("TON address invalid hex: {e}")))?;
    Ok(())
}
