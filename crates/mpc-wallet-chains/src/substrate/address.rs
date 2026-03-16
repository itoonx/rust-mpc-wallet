//! Substrate SS58 address derivation.
//!
//! SS58 address = Base58Check(prefix_byte(s) || account_id(32))
//! Account ID for Ed25519 = raw 32-byte public key.
//! Each Substrate chain has its own SS58 prefix number.

use mpc_wallet_core::error::CoreError;
use mpc_wallet_core::protocol::GroupPublicKey;
use sha2::{Digest, Sha256};

/// SS58 address prefix constant.
const SS58_PREFIX: &[u8] = b"SS58PRE";

/// Derive an SS58 address from an Ed25519 public key.
///
/// Format: Base58(prefix_byte || pubkey_32 || checksum_2)
/// Checksum = first 2 bytes of SHA-256(SS58_PREFIX || prefix_byte || pubkey_32)
pub fn derive_substrate_address(
    group_pubkey: &GroupPublicKey,
    ss58_prefix: u16,
) -> Result<String, CoreError> {
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
            return Err(CoreError::Crypto(
                "Substrate requires Ed25519 public key (Sr25519 MPC not yet supported)".into(),
            ));
        }
    };

    // Build payload: prefix byte(s) || pubkey
    let mut payload = Vec::new();
    if ss58_prefix < 64 {
        payload.push(ss58_prefix as u8);
    } else {
        // Two-byte prefix encoding for prefix >= 64
        let first = ((ss58_prefix & 0b0000_0000_1111_1100) >> 2) as u8 | 0b01000000;
        let second = (ss58_prefix >> 8) as u8 | ((ss58_prefix & 0b11) << 6) as u8;
        payload.push(first);
        payload.push(second);
    }
    payload.extend_from_slice(&pubkey_bytes);

    // Compute checksum: first 2 bytes of SHA-256(SS58_PREFIX || payload)
    let mut hasher = Sha256::new();
    hasher.update(SS58_PREFIX);
    hasher.update(&payload);
    let hash = hasher.finalize();
    let checksum = &hash[..2];

    // Full address bytes: payload || checksum
    payload.extend_from_slice(checksum);

    Ok(bs58::encode(payload).into_string())
}
