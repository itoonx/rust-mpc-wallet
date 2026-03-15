use blake2::digest::{consts::U32, Digest};
use blake2::Blake2b;
use mpc_wallet_core::error::CoreError;
use mpc_wallet_core::protocol::GroupPublicKey;

type Blake2b256 = Blake2b<U32>;

/// Derive a Sui address from an Ed25519 group public key.
/// Sui address = 0x + hex(Blake2b-256(0x00 || pubkey))[0..32]
pub fn derive_sui_address(group_pubkey: &GroupPublicKey) -> Result<String, CoreError> {
    match group_pubkey {
        GroupPublicKey::Ed25519(bytes) => {
            if bytes.len() != 32 {
                return Err(CoreError::Crypto(
                    "invalid Ed25519 public key length".into(),
                ));
            }

            // Sui address: Blake2b-256(flag_byte || pubkey_bytes)
            // flag_byte = 0x00 for Ed25519
            let mut hasher = Blake2b256::new();
            hasher.update([0x00]); // Ed25519 flag
            hasher.update(bytes);
            let hash = hasher.finalize();

            Ok(format!("0x{}", hex::encode(hash)))
        }
        _ => Err(CoreError::Crypto(
            "Sui requires Ed25519 public key".into(),
        )),
    }
}
