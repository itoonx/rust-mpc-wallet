use bitcoin::key::UntweakedPublicKey;
use bitcoin::{Address, CompressedPublicKey, Network};
use mpc_wallet_core::error::CoreError;
use mpc_wallet_core::protocol::GroupPublicKey;

/// Hex-encoded 33-byte compressed secp256k1 pubkey. Accepts either the
/// compressed or uncompressed variant of `GroupPublicKey` and normalizes
/// to compressed form. Used in Bitcoin presign extras and BIP-143 sighash
/// witness construction.
pub fn compressed_pubkey_hex(group_pubkey: &GroupPublicKey) -> Result<String, CoreError> {
    match group_pubkey {
        GroupPublicKey::Secp256k1(bytes) if bytes.len() == 33 => Ok(hex::encode(bytes)),
        GroupPublicKey::Secp256k1Uncompressed(bytes) if bytes.len() == 65 => {
            let parity = if bytes[64] & 1 == 0 { 0x02 } else { 0x03 };
            let mut out = Vec::with_capacity(33);
            out.push(parity);
            out.extend_from_slice(&bytes[1..33]);
            Ok(hex::encode(out))
        }
        _ => Err(CoreError::Crypto(
            "compressed_pubkey_hex: expected secp256k1 group public key".into(),
        )),
    }
}

/// Derive a P2WPKH (native SegWit, bech32 `tb1q…` / `bc1q…`) address from a
/// secp256k1 group public key. This is the path used for live ECDSA-signed txs
/// (BIP-141 + BIP-143). For Taproot, see [`derive_taproot_address`].
pub fn derive_p2wpkh_address(
    group_pubkey: &GroupPublicKey,
    network: Network,
) -> Result<String, CoreError> {
    let compressed = match group_pubkey {
        GroupPublicKey::Secp256k1(bytes) if bytes.len() == 33 => bytes.clone(),
        GroupPublicKey::Secp256k1Uncompressed(bytes) if bytes.len() == 65 => {
            // Re-compress: 0x02/0x03 prefix from y parity + x bytes.
            let parity = if bytes[64] & 1 == 0 { 0x02 } else { 0x03 };
            let mut out = Vec::with_capacity(33);
            out.push(parity);
            out.extend_from_slice(&bytes[1..33]);
            out
        }
        _ => {
            return Err(CoreError::Crypto(
                "P2WPKH requires a 33-byte compressed (or 65-byte uncompressed) secp256k1 key"
                    .into(),
            ));
        }
    };
    let pk = CompressedPublicKey::from_slice(&compressed)
        .map_err(|e| CoreError::Crypto(format!("invalid compressed pubkey: {e}")))?;
    let address = Address::p2wpkh(&pk, network);
    Ok(address.to_string())
}

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
