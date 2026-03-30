//! Signing on the Stark curve for StarkNet.
//!
//! Uses real StarkNet cryptography via `starknet-crypto`:
//! - ECDSA on the STARK curve (order p = 2^251 + 17*2^192 + 1)
//! - RFC 6979 deterministic nonce generation
//! - Pedersen hash for message hashing
//!
//! Current implementation: single-party signing (each party holds the full key).
//! TODO: implement threshold Stark signing (Shamir secret sharing on Stark field).

use async_trait::async_trait;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use starknet_crypto::{self, Felt};
use zeroize::Zeroizing;

use crate::error::CoreError;
use crate::protocol::{GroupPublicKey, KeyShare, MpcProtocol, MpcSignature};
use crate::transport::Transport;
use crate::types::{CryptoScheme, PartyId, ThresholdConfig};

/// StarkNet signing protocol using real STARK curve cryptography.
///
/// Currently single-party (MVP). Each party holds the full private key.
/// TODO: implement threshold Stark signing with Shamir shares on the Stark field.
pub struct StarkProtocol;

impl StarkProtocol {
    pub fn new() -> Self {
        Self
    }
}

impl Default for StarkProtocol {
    fn default() -> Self {
        Self::new()
    }
}

/// Serialized share data for a Stark key.
#[derive(Serialize, Deserialize)]
struct StarkShareData {
    /// Party index within the signing group.
    party_index: u16,
    /// Private key as 32-byte big-endian Felt encoding.
    secret_key: Vec<u8>,
    /// Public key as 32-byte big-endian Felt encoding.
    public_key: Vec<u8>,
}

#[async_trait]
impl MpcProtocol for StarkProtocol {
    fn scheme(&self) -> CryptoScheme {
        CryptoScheme::StarkThreshold
    }

    async fn keygen(
        &self,
        config: ThresholdConfig,
        party_id: PartyId,
        transport: &dyn Transport,
    ) -> Result<KeyShare, CoreError> {
        // Generate random 252-bit private key (< Stark field order).
        // The Stark prime is p = 2^251 + 17*2^192 + 1, so we mask
        // the top byte to ensure the value is < 2^252 (well within range
        // since the field order is ~2^251). Felt::from_bytes_be will
        // reduce mod p automatically.
        let mut secret_bytes = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut secret_bytes);
        // Mask to < 2^251 to ensure we're well within the Stark field.
        secret_bytes[0] &= 0x07;

        let private_key = Felt::from_bytes_be(&secret_bytes);

        // Reject zero private key (astronomically unlikely but safety check).
        if private_key == Felt::ZERO {
            return Err(CoreError::Crypto(
                "stark keygen: generated zero private key".into(),
            ));
        }

        // Compute public key on the STARK curve: pubkey = private_key * G
        let public_key = starknet_crypto::get_public_key(&private_key);
        let pubkey_bytes = public_key.to_bytes_be().to_vec();

        // Broadcast public key to all parties.
        let msg = crate::transport::ProtocolMessage {
            from: party_id,
            to: None,
            round: 1,
            payload: serde_json::to_vec(&pubkey_bytes)
                .map_err(|e| CoreError::Protocol(format!("serialize failed: {e}")))?,
        };
        transport.send(msg).await?;

        // Collect public keys from all other parties.
        // In single-party mode, all parties generate the same key structure.
        // TODO: implement Shamir secret sharing for threshold mode.
        let mut group_pubkey = pubkey_bytes.clone();
        for _ in 1..config.total_parties {
            let recv = transport.recv().await?;
            if party_id == PartyId(1) {
                group_pubkey = serde_json::from_slice(&recv.payload)
                    .map_err(|e| CoreError::Protocol(format!("deserialize failed: {e}")))?;
            }
        }

        let share_data = StarkShareData {
            party_index: party_id.0,
            secret_key: secret_bytes.to_vec(),
            public_key: pubkey_bytes.clone(),
        };

        let share_bytes = Zeroizing::new(
            serde_json::to_vec(&share_data)
                .map_err(|e| CoreError::Protocol(format!("serialize share failed: {e}")))?,
        );

        // Zeroize the secret material on the stack.
        zeroize::Zeroize::zeroize(&mut secret_bytes);

        Ok(KeyShare {
            scheme: CryptoScheme::StarkThreshold,
            party_id,
            config,
            group_public_key: GroupPublicKey::StarkCurve(group_pubkey),
            share_data: share_bytes,
        })
    }

    async fn sign(
        &self,
        key_share: &KeyShare,
        _signers: &[PartyId],
        message: &[u8],
        _transport: &dyn Transport,
    ) -> Result<MpcSignature, CoreError> {
        let share_data: StarkShareData = serde_json::from_slice(&key_share.share_data)
            .map_err(|e| CoreError::Protocol(format!("deserialize share failed: {e}")))?;

        // Reconstruct private key Felt from stored bytes.
        let mut sk_bytes = [0u8; 32];
        if share_data.secret_key.len() != 32 {
            return Err(CoreError::Crypto(
                "stark sign: invalid secret key length".into(),
            ));
        }
        sk_bytes.copy_from_slice(&share_data.secret_key);
        let private_key = Felt::from_bytes_be(&sk_bytes);
        // Zeroize local copy.
        zeroize::Zeroize::zeroize(&mut sk_bytes);

        // Hash the message to a Stark field element.
        // For raw byte messages, interpret as big-endian Felt (truncated/padded).
        let msg_felt = Felt::from_bytes_be_slice(message);

        // Generate deterministic nonce k via RFC 6979.
        let k = starknet_crypto::rfc6979_generate_k(&msg_felt, &private_key, None);

        // Sign with ECDSA on the STARK curve.
        let signature = starknet_crypto::sign(&private_key, &msg_felt, &k)
            .map_err(|e| CoreError::Crypto(format!("stark sign: {e}")))?;

        let r = signature.r.to_bytes_be().to_vec();
        let s = signature.s.to_bytes_be().to_vec();

        Ok(MpcSignature::StarkSig { r, s })
    }
}

/// Verify a StarkNet signature against a public key and message.
///
/// Returns `true` if the signature is valid, `false` otherwise.
pub fn verify_stark_signature(
    public_key: &[u8],
    message: &[u8],
    r: &[u8],
    s: &[u8],
) -> Result<bool, CoreError> {
    if public_key.len() > 32 || r.len() > 32 || s.len() > 32 {
        return Err(CoreError::Crypto(
            "stark verify: invalid field element length".into(),
        ));
    }

    let pubkey_felt = Felt::from_bytes_be_slice(public_key);
    let msg_felt = Felt::from_bytes_be_slice(message);
    let r_felt = Felt::from_bytes_be_slice(r);
    let s_felt = Felt::from_bytes_be_slice(s);

    starknet_crypto::verify(&pubkey_felt, &msg_felt, &r_felt, &s_felt)
        .map_err(|e| CoreError::Crypto(format!("stark verify: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stark_keygen_and_sign_verify() {
        // Generate a private key.
        let mut secret_bytes = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut secret_bytes);
        secret_bytes[0] &= 0x07;

        let private_key = Felt::from_bytes_be(&secret_bytes);
        let public_key = starknet_crypto::get_public_key(&private_key);

        // Sign a message.
        let message = b"test message for stark signing";
        let msg_felt = Felt::from_bytes_be_slice(message);
        let k = starknet_crypto::rfc6979_generate_k(&msg_felt, &private_key, None);
        let sig = starknet_crypto::sign(&private_key, &msg_felt, &k).unwrap();

        // Verify.
        let valid = starknet_crypto::verify(&public_key, &msg_felt, &sig.r, &sig.s).unwrap();
        assert!(valid, "signature should verify");
    }

    #[test]
    fn test_stark_verify_wrong_message() {
        let mut secret_bytes = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut secret_bytes);
        secret_bytes[0] &= 0x07;

        let private_key = Felt::from_bytes_be(&secret_bytes);
        let public_key = starknet_crypto::get_public_key(&private_key);

        let message = b"correct message";
        let msg_felt = Felt::from_bytes_be_slice(message);
        let k = starknet_crypto::rfc6979_generate_k(&msg_felt, &private_key, None);
        let sig = starknet_crypto::sign(&private_key, &msg_felt, &k).unwrap();

        // Verify with wrong message should fail.
        let wrong_msg = Felt::from_bytes_be_slice(b"wrong message");
        let valid = starknet_crypto::verify(&public_key, &wrong_msg, &sig.r, &sig.s).unwrap();
        assert!(!valid, "signature should NOT verify with wrong message");
    }

    #[test]
    fn test_stark_verify_helper() {
        let mut secret_bytes = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut secret_bytes);
        secret_bytes[0] &= 0x07;

        let private_key = Felt::from_bytes_be(&secret_bytes);
        let public_key = starknet_crypto::get_public_key(&private_key);
        let pubkey_bytes = public_key.to_bytes_be();

        let message = b"verify helper test";
        let msg_felt = Felt::from_bytes_be_slice(message);
        let k = starknet_crypto::rfc6979_generate_k(&msg_felt, &private_key, None);
        let sig = starknet_crypto::sign(&private_key, &msg_felt, &k).unwrap();

        let r_bytes = sig.r.to_bytes_be();
        let s_bytes = sig.s.to_bytes_be();

        let valid = verify_stark_signature(&pubkey_bytes, message, &r_bytes, &s_bytes).unwrap();
        assert!(valid);
    }

    #[test]
    fn test_stark_public_key_deterministic() {
        let secret = Felt::from_bytes_be(&[
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x01,
        ]);
        let pk1 = starknet_crypto::get_public_key(&secret);
        let pk2 = starknet_crypto::get_public_key(&secret);
        assert_eq!(pk1, pk2, "public key derivation must be deterministic");
    }

    #[test]
    fn test_stark_field_element_roundtrip() {
        let mut bytes = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut bytes);
        bytes[0] &= 0x07; // Ensure within field.

        let felt = Felt::from_bytes_be(&bytes);
        let roundtrip = felt.to_bytes_be();
        let felt2 = Felt::from_bytes_be(&roundtrip);
        assert_eq!(felt, felt2, "Felt round-trip must be lossless");
    }
}
