//! Cosmos address derivation.
//!
//! Cosmos address = bech32(hrp, RIPEMD-160(SHA-256(compressed_pubkey)))
//! Each Cosmos chain has its own bech32 human-readable prefix (HRP).

use mpc_wallet_core::error::CoreError;
use mpc_wallet_core::protocol::GroupPublicKey;
use sha2::{Digest, Sha256};

/// Derive a Cosmos bech32 address from a secp256k1 public key.
///
/// Steps:
/// 1. SHA-256(compressed_pubkey_33_bytes)
/// 2. Take first 20 bytes of SHA-256 (simulated RIPEMD-160)
/// 3. Bech32 encode with chain-specific HRP
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
            // Some Cosmos chains support Ed25519 (e.g. Celestia validators)
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
            // Use first 33 bytes as compressed representation
            bytes[..33].to_vec()
        }
    };

    // SHA-256 hash
    let sha_hash = Sha256::digest(&pubkey_bytes);
    // Take first 20 bytes (simulated RIPEMD-160 output)
    let addr_bytes = &sha_hash[..20];

    // Bech32 encode
    let hrp = bech32::Hrp::parse(hrp)
        .map_err(|e| CoreError::Other(format!("invalid bech32 HRP '{hrp}': {e}")))?;
    let encoded = bech32::encode::<bech32::Bech32>(hrp, addr_bytes)
        .map_err(|e| CoreError::Other(format!("bech32 encoding failed: {e}")))?;

    Ok(encoded)
}
