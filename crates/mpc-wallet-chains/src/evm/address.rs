use k256::elliptic_curve::sec1::ToEncodedPoint;
use mpc_wallet_core::error::CoreError;
use mpc_wallet_core::protocol::GroupPublicKey;
use sha3::{Digest, Keccak256};

/// Derive an EVM address from a secp256k1 group public key.
/// EVM address = last 20 bytes of keccak256(uncompressed_pubkey[1..])
pub fn derive_evm_address(group_pubkey: &GroupPublicKey) -> Result<String, CoreError> {
    let uncompressed = match group_pubkey {
        GroupPublicKey::Secp256k1Uncompressed(bytes) => {
            if bytes.len() != 65 {
                return Err(CoreError::Crypto(
                    "invalid uncompressed secp256k1 key length".into(),
                ));
            }
            bytes.clone()
        }
        GroupPublicKey::Secp256k1(bytes) => {
            // Decompress the key
            let point = k256::PublicKey::from_sec1_bytes(bytes)
                .map_err(|e| CoreError::Crypto(format!("invalid secp256k1 key: {e}")))?;
            point
                .to_encoded_point(false)
                .as_bytes()
                .to_vec()
        }
        GroupPublicKey::Ed25519(_) => {
            return Err(CoreError::Crypto(
                "cannot derive EVM address from Ed25519 key".into(),
            ));
        }
    };

    // Hash the public key bytes (skip the 0x04 prefix)
    let hash = Keccak256::digest(&uncompressed[1..]);
    // Take the last 20 bytes
    let address_bytes = &hash[12..];
    // Format as checksummed address
    Ok(format!("0x{}", checksum_encode(address_bytes)))
}

/// EIP-55 checksum encoding.
fn checksum_encode(address_bytes: &[u8]) -> String {
    let hex_addr = hex::encode(address_bytes);
    let hash = Keccak256::digest(hex_addr.as_bytes());
    let hash_hex = hex::encode(hash);

    hex_addr
        .chars()
        .enumerate()
        .map(|(i, c)| {
            if c.is_ascii_alphabetic() {
                let hash_nibble = u8::from_str_radix(&hash_hex[i..i + 1], 16).unwrap_or(0);
                if hash_nibble >= 8 {
                    c.to_ascii_uppercase()
                } else {
                    c.to_ascii_lowercase()
                }
            } else {
                c
            }
        })
        .collect()
}
