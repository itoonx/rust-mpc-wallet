use mpc_wallet_core::error::CoreError;
use mpc_wallet_core::protocol::GroupPublicKey;

/// Derive a Solana address (base58 public key) from an Ed25519 group public key.
pub fn derive_solana_address(group_pubkey: &GroupPublicKey) -> Result<String, CoreError> {
    match group_pubkey {
        GroupPublicKey::Ed25519(bytes) => {
            if bytes.len() != 32 {
                return Err(CoreError::Crypto(
                    "invalid Ed25519 public key length".into(),
                ));
            }
            Ok(bs58::encode(bytes).into_string())
        }
        _ => Err(CoreError::Crypto(
            "Solana requires Ed25519 public key".into(),
        )),
    }
}
