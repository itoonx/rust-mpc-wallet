//! Cosmos address derivation.
//!
//! Cosmos address = bech32(hrp, RIPEMD-160(SHA-256(pubkey)))
//! Each Cosmos chain has its own bech32 human-readable prefix (HRP).

use mpc_wallet_core::error::CoreError;
use mpc_wallet_core::protocol::GroupPublicKey;
use ripemd::Ripemd160;
use sha2::{Digest, Sha256};

/// Derive a Cosmos bech32 address from a secp256k1 or Ed25519 public key.
///
/// Standard Cosmos: bech32(hrp, RIPEMD-160(SHA-256(compressed_pubkey)))
pub fn derive_cosmos_address(
    group_pubkey: &GroupPublicKey,
    hrp: &str,
) -> Result<String, CoreError> {
    let pubkey_bytes = match group_pubkey {
        GroupPublicKey::Secp256k1(bytes) => {
            if bytes.len() != 33 {
                return Err(CoreError::Crypto(
                    "invalid compressed secp256k1 key length".into(),
                ));
            }
            bytes.clone()
        }
        GroupPublicKey::Ed25519(bytes) => {
            if bytes.len() != 32 {
                return Err(CoreError::Crypto(
                    "invalid Ed25519 public key length".into(),
                ));
            }
            bytes.clone()
        }
        GroupPublicKey::Secp256k1Uncompressed(bytes) => {
            if bytes.len() != 65 {
                return Err(CoreError::Crypto(
                    "invalid uncompressed secp256k1 key length".into(),
                ));
            }
            bytes[..33].to_vec()
        }
    };

    // RIPEMD-160(SHA-256(pubkey)) — standard Cosmos address derivation
    let sha_hash = Sha256::digest(&pubkey_bytes);
    let ripemd_hash = Ripemd160::digest(sha_hash);

    let hrp = bech32::Hrp::parse(hrp)
        .map_err(|e| CoreError::Other(format!("invalid bech32 HRP: {e}")))?;
    let encoded = bech32::encode::<bech32::Bech32>(hrp, &ripemd_hash)
        .map_err(|e| CoreError::Other(format!("bech32 encoding failed: {e}")))?;

    Ok(encoded)
}
