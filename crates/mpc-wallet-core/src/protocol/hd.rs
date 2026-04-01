//! BIP32 HD wallet derivation for MPC threshold signing.
//!
//! Non-hardened derivation only -- each party computes locally:
//!   child_share_i = parent_share_i + tweak
//!   child_pubkey  = parent_pubkey  + tweak * G
//! No inter-party communication needed.
//!
//! Hardened derivation requires the full private key and is fundamentally
//! incompatible with threshold MPC (the key is never reconstructed).

use hmac::{Hmac, Mac};
use k256::{
    elliptic_curve::{ops::Reduce, sec1::ToEncodedPoint, PrimeField},
    ProjectivePoint, Scalar, U256,
};
use sha2::Sha512;

use crate::error::CoreError;

type HmacSha512 = Hmac<Sha512>;

/// BIP32 non-hardened child key derivation for secp256k1.
///
/// Returns `(tweak_scalar, child_chain_code)`.
///
/// `tweak = parse256(HMAC-SHA512(chain_code, compressed_pubkey || index)[0..32])`
/// `child_chain_code = HMAC-SHA512(...)[32..64]`
///
/// # Errors
///
/// Returns error if `index >= 0x80000000` (hardened derivation not supported in MPC).
pub fn bip32_derive_non_hardened(
    chain_code: &[u8; 32],
    parent_pubkey_compressed: &[u8], // 33 bytes SEC1
    index: u32,
) -> Result<(Scalar, [u8; 32]), CoreError> {
    if index >= 0x80000000 {
        return Err(CoreError::Protocol(
            "BIP32 hardened derivation not supported in MPC (requires full private key)".into(),
        ));
    }

    let mut mac = HmacSha512::new_from_slice(chain_code)
        .map_err(|_| CoreError::Crypto("HMAC-SHA512 init failed".into()))?;
    mac.update(parent_pubkey_compressed);
    mac.update(&index.to_be_bytes());
    let result = mac.finalize().into_bytes();

    // Left 32 bytes = tweak scalar
    let tweak_bytes: [u8; 32] = result[..32]
        .try_into()
        .expect("HMAC-SHA512 always produces 64 bytes");
    let tweak = <Scalar as Reduce<U256>>::reduce_bytes(k256::FieldBytes::from_slice(&tweak_bytes));

    // Right 32 bytes = child chain code
    let child_chain_code: [u8; 32] = result[32..64]
        .try_into()
        .expect("HMAC-SHA512 always produces 64 bytes");

    Ok((tweak, child_chain_code))
}

/// Tweak a compressed SEC1 secp256k1 public key by adding `tweak * G`.
///
/// Returns the new compressed SEC1 bytes (33 bytes).
pub fn tweak_public_key(
    compressed_pubkey: &[u8],
    tweak_point: &ProjectivePoint,
) -> Result<Vec<u8>, CoreError> {
    let parent = k256::PublicKey::from_sec1_bytes(compressed_pubkey)
        .map_err(|e| CoreError::Crypto(format!("invalid SEC1 pubkey: {e}")))?;
    let child_point = parent.to_projective() + tweak_point;
    let child_affine = child_point.to_affine();
    let child_pk = k256::PublicKey::from_affine(child_affine)
        .map_err(|e| CoreError::Crypto(format!("child pubkey at infinity: {e}")))?;
    Ok(child_pk.to_encoded_point(true).as_bytes().to_vec())
}

/// Tweak a secret scalar by adding `tweak`.
///
/// Returns the new scalar as big-endian 32-byte representation.
pub fn tweak_secret_scalar(secret_bytes: &[u8], tweak: &Scalar) -> Result<Vec<u8>, CoreError> {
    let parent_scalar = Scalar::from_repr(*k256::FieldBytes::from_slice(secret_bytes))
        .into_option()
        .ok_or_else(|| CoreError::Crypto("invalid secret scalar encoding".into()))?;
    let child_scalar = parent_scalar + tweak;
    Ok(child_scalar.to_repr().to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hardened_index_rejected() {
        let chain_code = [0u8; 32];
        let pubkey = vec![0x02; 33]; // dummy compressed
        let result = bip32_derive_non_hardened(&chain_code, &pubkey, 0x80000000);
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(err_msg.contains("hardened"));
    }

    #[test]
    fn test_non_hardened_derivation_deterministic() {
        // Use a real compressed pubkey (generator point)
        let generator = ProjectivePoint::GENERATOR.to_affine();
        let gen_pk = k256::PublicKey::from_affine(generator).unwrap();
        let gen_bytes = gen_pk.to_encoded_point(true).as_bytes().to_vec();

        let chain_code = [0xABu8; 32];

        let (tweak1, cc1) = bip32_derive_non_hardened(&chain_code, &gen_bytes, 0).unwrap();
        let (tweak2, cc2) = bip32_derive_non_hardened(&chain_code, &gen_bytes, 0).unwrap();

        // Same inputs => same outputs
        assert_eq!(tweak1, tweak2);
        assert_eq!(cc1, cc2);

        // Different index => different outputs
        let (tweak3, cc3) = bip32_derive_non_hardened(&chain_code, &gen_bytes, 1).unwrap();
        assert_ne!(tweak1, tweak3);
        assert_ne!(cc1, cc3);
    }

    #[test]
    fn test_tweak_public_key_produces_valid_key() {
        let generator = ProjectivePoint::GENERATOR.to_affine();
        let gen_pk = k256::PublicKey::from_affine(generator).unwrap();
        let gen_bytes = gen_pk.to_encoded_point(true).as_bytes().to_vec();

        let tweak = Scalar::from(42u64);
        let tweak_point = ProjectivePoint::GENERATOR * tweak;

        let child_bytes = tweak_public_key(&gen_bytes, &tweak_point).unwrap();
        assert_eq!(child_bytes.len(), 33);
        // Should be different from parent
        assert_ne!(child_bytes, gen_bytes);
        // Should be a valid SEC1 key
        k256::PublicKey::from_sec1_bytes(&child_bytes).unwrap();
    }

    #[test]
    fn test_tweak_secret_scalar() {
        use k256::elliptic_curve::PrimeField;
        let secret = Scalar::from(100u64);
        let tweak = Scalar::from(42u64);
        let child_bytes = tweak_secret_scalar(&secret.to_repr(), &tweak).unwrap();
        let child = Scalar::from_repr(*k256::FieldBytes::from_slice(&child_bytes))
            .into_option()
            .unwrap();
        assert_eq!(child, Scalar::from(142u64));
    }

    #[test]
    fn test_max_non_hardened_index_accepted() {
        let generator = ProjectivePoint::GENERATOR.to_affine();
        let gen_pk = k256::PublicKey::from_affine(generator).unwrap();
        let gen_bytes = gen_pk.to_encoded_point(true).as_bytes().to_vec();
        let chain_code = [0x01u8; 32];

        // 0x7FFFFFFF is the max non-hardened index
        let result = bip32_derive_non_hardened(&chain_code, &gen_bytes, 0x7FFFFFFF);
        assert!(result.is_ok());
    }
}
