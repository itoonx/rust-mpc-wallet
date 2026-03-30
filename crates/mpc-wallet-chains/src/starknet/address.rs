//! Starknet address derivation using Pedersen hash.
//!
//! Starknet contract address = pedersen(
//!     CONTRACT_ADDRESS_PREFIX,
//!     deployer_address,
//!     salt,
//!     class_hash,
//!     constructor_calldata_hash
//! ) masked to 251 bits.
//!
//! For account contracts deployed via CREATE:
//! - deployer = 0 (self-deployed)
//! - salt = pedersen(0, public_key) -- deterministic from pubkey
//! - class_hash = OZ account class hash
//! - calldata_hash = pedersen(public_key) -- single constructor arg

use mpc_wallet_core::error::CoreError;
use mpc_wallet_core::protocol::GroupPublicKey;
use starknet_crypto::{pedersen_hash, Felt};

/// Starknet contract address prefix as a Felt.
/// This is the Pedersen hash of "STARKNET_CONTRACT_ADDRESS".
/// In the actual StarkNet protocol, this is a well-known constant.
fn contract_address_prefix() -> Felt {
    // The literal string "STARKNET_CONTRACT_ADDRESS" encoded as a Felt.
    Felt::from_bytes_be_slice(b"STARKNET_CONTRACT_ADDRESS")
}

/// OpenZeppelin account contract class hash (v0.8.1 placeholder).
/// In production, use the actual deployed class hash.
fn oz_account_class_hash() -> Felt {
    // Placeholder: 0x04040404...04 (32 bytes of 0x04).
    Felt::from_bytes_be(&[0x04; 32])
}

/// Derive a Starknet account address from a public key.
///
/// Computes: pedersen(prefix, deployer, salt, class_hash, calldata_hash) & MASK_251
///
/// Where:
/// - prefix = CONTRACT_ADDRESS_PREFIX
/// - deployer = 0 (self-deployed)
/// - salt = pedersen(0, pubkey_felt)
/// - class_hash = OZ account class hash
/// - calldata_hash = pedersen(0, pubkey_felt) (single constructor arg)
pub fn derive_starknet_address(group_pubkey: &GroupPublicKey) -> Result<String, CoreError> {
    let pubkey_bytes = group_pubkey.as_bytes();
    let pubkey_felt = Felt::from_bytes_be_slice(pubkey_bytes);

    // Salt = pedersen(0, public_key) -- deterministic from pubkey.
    let salt = pedersen_hash(&Felt::ZERO, &pubkey_felt);

    // Constructor calldata hash: for a single-arg constructor (public_key),
    // hash = pedersen(0, public_key).
    let calldata_hash = pedersen_hash(&Felt::ZERO, &pubkey_felt);

    let prefix = contract_address_prefix();
    let deployer = Felt::ZERO;
    let class_hash = oz_account_class_hash();

    // Contract address = pedersen(pedersen(pedersen(pedersen(prefix, deployer), salt), class_hash), calldata_hash)
    // This is the chain of Pedersen hashes as specified in the StarkNet address computation.
    let h1 = pedersen_hash(&prefix, &deployer);
    let h2 = pedersen_hash(&h1, &salt);
    let h3 = pedersen_hash(&h2, &class_hash);
    let h4 = pedersen_hash(&h3, &calldata_hash);

    // Mask to 251 bits (Stark field element).
    let mut addr_bytes = h4.to_bytes_be();
    addr_bytes[0] &= 0x07;

    Ok(format!("0x{}", hex::encode(addr_bytes)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use mpc_wallet_core::protocol::GroupPublicKey;

    #[test]
    fn test_starknet_address_deterministic() {
        let pubkey = GroupPublicKey::StarkCurve(vec![0x42; 32]);
        let addr1 = derive_starknet_address(&pubkey).unwrap();
        let addr2 = derive_starknet_address(&pubkey).unwrap();
        assert_eq!(addr1, addr2, "address derivation must be deterministic");
    }

    #[test]
    fn test_starknet_address_format() {
        let pubkey = GroupPublicKey::StarkCurve(vec![0x01; 32]);
        let addr = derive_starknet_address(&pubkey).unwrap();
        assert!(addr.starts_with("0x"), "address must start with 0x");
        assert_eq!(addr.len(), 66, "address must be 0x + 64 hex chars");
    }

    #[test]
    fn test_starknet_address_within_field() {
        let pubkey = GroupPublicKey::StarkCurve(vec![0xFF; 32]);
        let addr = derive_starknet_address(&pubkey).unwrap();
        // First byte after 0x must have top 5 bits cleared (251-bit mask).
        let first_byte = u8::from_str_radix(&addr[2..4], 16).unwrap();
        assert!(first_byte <= 0x07, "address must be masked to 251 bits");
    }

    #[test]
    fn test_starknet_address_different_keys() {
        let pubkey1 = GroupPublicKey::StarkCurve(vec![0x01; 32]);
        let pubkey2 = GroupPublicKey::StarkCurve(vec![0x02; 32]);
        let addr1 = derive_starknet_address(&pubkey1).unwrap();
        let addr2 = derive_starknet_address(&pubkey2).unwrap();
        assert_ne!(
            addr1, addr2,
            "different keys must produce different addresses"
        );
    }
}
