use bitcoin::key::UntweakedPublicKey;
use bitcoin::{Address, Network};
use mpc_wallet_core::error::CoreError;
use mpc_wallet_core::protocol::GroupPublicKey;

/// Derive a P2TR (Taproot) bech32m address from a secp256k1 group public key.
pub fn derive_taproot_address(
    group_pubkey: &GroupPublicKey,
    network: Network,
) -> Result<String, CoreError> {
    let pubkey_bytes = match group_pubkey {
        GroupPublicKey::Secp256k1(bytes) => {
            // Compressed 33-byte key — extract x-only (32 bytes, skip prefix)
            if bytes.len() != 33 {
                return Err(CoreError::Crypto(
                    "invalid compressed secp256k1 key length".into(),
                ));
            }
            bytes[1..].to_vec()
        }
        GroupPublicKey::Secp256k1Uncompressed(bytes) => {
            // Uncompressed 65-byte key — extract x coordinate (bytes 1..33)
            if bytes.len() != 65 {
                return Err(CoreError::Crypto(
                    "invalid uncompressed secp256k1 key length".into(),
                ));
            }
            bytes[1..33].to_vec()
        }
        _ => {
            return Err(CoreError::Crypto(
                "cannot derive Taproot address from Ed25519 key".into(),
            ));
        }
    };

    let x_only_bytes: [u8; 32] = pubkey_bytes
        .try_into()
        .map_err(|_| CoreError::Crypto("invalid x-only pubkey length".into()))?;

    let x_only = UntweakedPublicKey::from_slice(&x_only_bytes)
        .map_err(|e| CoreError::Crypto(format!("invalid x-only pubkey: {e}")))?;

    let secp = bitcoin::secp256k1::Secp256k1::new();
    let address = Address::p2tr(&secp, x_only, None, network);

    Ok(address.to_string())
}
