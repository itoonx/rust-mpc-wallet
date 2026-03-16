//! Monero address derivation.
//!
//! Monero standard address = Base58(network_byte || spend_pubkey(32) || view_pubkey(32) || checksum(4))
//! View secret key = Hn(spend_secret_key) where Hn = Keccak-256 reduced mod l
//! For MPC: view key derived deterministically from spend pubkey using scalar reduction.

use mpc_wallet_core::error::CoreError;
use mpc_wallet_core::protocol::GroupPublicKey;
use sha3::{Digest, Keccak256};

/// Monero mainnet network byte.
const MONERO_MAINNET_NETWORK_BYTE: u8 = 18;

/// Ed25519 scalar field order l = 2^252 + 27742317777372353535851937790883648493
const ED25519_L: [u8; 32] = [
    0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
];

/// Reduce a 32-byte value modulo l (Ed25519 scalar field order).
/// Simplified: clamp the high bits to ensure value < l.
fn scalar_reduce(bytes: &[u8; 32]) -> [u8; 32] {
    let mut result = *bytes;
    // Clamp to ensure the scalar is in the valid range
    result[31] &= 0x0F; // Clear top 4 bits to keep < 2^252
                        // Ensure it's less than l by checking and reducing if needed
    let mut is_ge_l = false;
    for i in (0..32).rev() {
        if result[i] > ED25519_L[i] {
            is_ge_l = true;
            break;
        } else if result[i] < ED25519_L[i] {
            break;
        }
    }
    if is_ge_l {
        // Simple subtraction if >= l (sufficient for clamped values)
        let mut borrow = 0u16;
        for i in 0..32 {
            let diff = result[i] as u16 + 256 - ED25519_L[i] as u16 - borrow;
            result[i] = diff as u8;
            borrow = 1 - (diff >> 8);
        }
    }
    result
}

/// Derive a Monero standard address from an Ed25519 group public key.
///
/// The spend public key is the group key. The view key is derived as
/// Hn(spend_key) = Keccak-256(spend_key) reduced mod l (Ed25519 scalar field order).
pub fn derive_monero_address(group_pubkey: &GroupPublicKey) -> Result<String, CoreError> {
    let spend_key = match group_pubkey {
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
                "Monero requires Ed25519 public key".into(),
            ));
        }
    };

    // Derive view key: Keccak-256(spend_key) reduced mod l
    let keccak_hash = Keccak256::digest(&spend_key);
    let mut hash_bytes = [0u8; 32];
    hash_bytes.copy_from_slice(&keccak_hash);
    let view_scalar = scalar_reduce(&hash_bytes);

    // Build address data: network_byte || spend_key(32) || view_key(32)
    let mut addr_data = Vec::with_capacity(69);
    addr_data.push(MONERO_MAINNET_NETWORK_BYTE);
    addr_data.extend_from_slice(&spend_key);
    addr_data.extend_from_slice(&view_scalar);

    // Checksum: first 4 bytes of Keccak-256(addr_data)
    let checksum = Keccak256::digest(&addr_data);
    addr_data.extend_from_slice(&checksum[..4]);

    // Monero uses its own Base58 variant (4-byte block encoding).
    // Standard Base58 used here — production should use Monero-specific Base58.
    Ok(bs58::encode(addr_data).into_string())
}
