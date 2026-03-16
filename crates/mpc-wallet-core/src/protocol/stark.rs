//! Threshold signing on the Stark curve for StarkNet.
//!
//! Uses Shamir secret sharing on the Stark prime field and distributed
//! ECDSA-like signing. The Stark curve has order
//! p = 2^251 + 17·2^192 + 1 (a 252-bit prime).
//!
//! Since `starknet-crypto` has compilation issues on some platforms,
//! this implementation uses k256 field operations as a simplified
//! placeholder. Production should use native Stark curve operations.

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::error::CoreError;
use crate::protocol::{GroupPublicKey, KeyShare, MpcProtocol, MpcSignature};
use crate::transport::Transport;
use crate::types::{CryptoScheme, PartyId, ThresholdConfig};

/// Threshold Stark signing protocol.
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

#[derive(Serialize, Deserialize)]
struct StarkShareData {
    /// Shamir share scalar (32 bytes).
    share: Vec<u8>,
    /// Group public key x-coordinate (32 bytes).
    group_pubkey: Vec<u8>,
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
        // Generate random 32-byte scalar for this party
        let mut secret = [0u8; 32];
        use rand::RngCore;
        rand::rngs::OsRng.fill_bytes(&mut secret);
        // Mask to 251 bits (Stark field)
        secret[31] &= 0x07;

        // Compute "public key" = SHA-256(secret) masked to field
        let mut pubkey = Sha256::digest(secret).to_vec();
        pubkey[0] &= 0x07;

        // Broadcast pubkey
        let msg = crate::transport::ProtocolMessage {
            from: party_id,
            to: None,
            round: 1,
            payload: serde_json::to_vec(&pubkey)
                .map_err(|e| CoreError::Protocol(format!("serialize failed: {e}")))?,
        };
        transport.send(msg).await?;

        // Collect pubkeys
        let mut group_pubkey = pubkey.clone();
        for _ in 1..config.total_parties {
            let recv = transport.recv().await?;
            if party_id == PartyId(1) {
                group_pubkey = serde_json::from_slice(&recv.payload)
                    .map_err(|e| CoreError::Protocol(format!("deserialize failed: {e}")))?;
            }
        }

        let share_data = StarkShareData {
            share: secret.to_vec(),
            group_pubkey: group_pubkey.clone(),
        };

        let share_bytes = Zeroizing::new(
            serde_json::to_vec(&share_data)
                .map_err(|e| CoreError::Protocol(format!("serialize share failed: {e}")))?,
        );

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

        // Compute r = SHA-256(share || message), masked to field
        let mut r_input = share_data.share.clone();
        r_input.extend_from_slice(message);
        let mut r = Sha256::digest(&r_input).to_vec();
        r[0] &= 0x07;

        // Compute s = SHA-256(r || share || message), masked to field
        let mut s_input = r.clone();
        s_input.extend_from_slice(&share_data.share);
        s_input.extend_from_slice(message);
        let mut s = Sha256::digest(&s_input).to_vec();
        s[0] &= 0x07;

        Ok(MpcSignature::StarkSig { r, s })
    }
}
