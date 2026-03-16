//! UTXO chain address derivation.
//!
//! Derives P2PKH (Pay-to-Public-Key-Hash) addresses for UTXO chains
//! using Hash160 = RIPEMD-160(SHA-256(pubkey)) with Base58Check encoding.

use mpc_wallet_core::error::CoreError;
use mpc_wallet_core::protocol::GroupPublicKey;
use ripemd::Ripemd160;
use sha2::{Digest, Sha256};

use super::UtxoChainConfig;

/// Derive a P2PKH address from a secp256k1 public key.
///
/// Address = Base58Check(version_byte || Hash160(pubkey))
/// where Hash160 = RIPEMD-160(SHA-256(pubkey))
pub fn derive_utxo_p2pkh_address(
    group_pubkey: &GroupPublicKey,
    config: &UtxoChainConfig,
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
        GroupPublicKey::Secp256k1Uncompressed(bytes) => {
            if bytes.len() != 65 {
                return Err(CoreError::Crypto(
                    "invalid uncompressed secp256k1 key length".into(),
                ));
            }
            bytes.clone()
        }
        _ => {
            return Err(CoreError::Crypto(format!(
                "{} requires secp256k1 public key",
                config.coin_name
            )));
        }
    };

    // Hash160 = RIPEMD-160(SHA-256(pubkey))
    let sha256_hash = Sha256::digest(&pubkey_bytes);
    let hash160 = Ripemd160::digest(sha256_hash);

    // Prepend version byte
    let mut addr_bytes = Vec::with_capacity(25);
    addr_bytes.push(config.p2pkh_version);
    addr_bytes.extend_from_slice(&hash160);

    // Checksum = first 4 bytes of double SHA-256
    let checksum = {
        let first = Sha256::digest(&addr_bytes);
        let second = Sha256::digest(first);
        second[..4].to_vec()
    };
    addr_bytes.extend_from_slice(&checksum);

    Ok(bs58::encode(addr_bytes).into_string())
}
