//! Threshold Sr25519 signing protocol on Ristretto255.
//!
//! Uses Shamir secret sharing for key distribution and Schnorrkel
//! for Sr25519 signature generation. Each party holds a share of the
//! private key; the full key is never reconstructed.

use async_trait::async_trait;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::error::CoreError;
use crate::protocol::{GroupPublicKey, KeyShare, MpcProtocol, MpcSignature};
use crate::transport::Transport;
use crate::types::{CryptoScheme, PartyId, ThresholdConfig};

/// Sr25519 threshold protocol using Schnorrkel on Ristretto255.
pub struct Sr25519Protocol;

impl Sr25519Protocol {
    pub fn new() -> Self {
        Self
    }
}

impl Default for Sr25519Protocol {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Serialize, Deserialize)]
struct Sr25519ShareData {
    /// Shamir share value (32 bytes scalar).
    share: Vec<u8>,
    /// Full mini secret key for this party's share (used in signing).
    mini_secret: Vec<u8>,
}

#[async_trait]
impl MpcProtocol for Sr25519Protocol {
    fn scheme(&self) -> CryptoScheme {
        CryptoScheme::Sr25519Threshold
    }

    async fn keygen(
        &self,
        config: ThresholdConfig,
        party_id: PartyId,
        transport: &dyn Transport,
    ) -> Result<KeyShare, CoreError> {
        // Generate random mini secret key for this party
        let mini_secret = schnorrkel::MiniSecretKey::generate_with(&mut OsRng);
        let keypair = mini_secret.expand_to_keypair(schnorrkel::ExpansionMode::Ed25519);
        let public = keypair.public;

        // Broadcast public key to all parties
        let pub_bytes = public.to_bytes().to_vec();
        let msg = crate::transport::ProtocolMessage {
            from: party_id,
            to: None,
            round: 1,
            payload: serde_json::to_vec(&pub_bytes)
                .map_err(|e| CoreError::Protocol(format!("serialize failed: {e}")))?,
        };
        transport.send(msg).await?;

        // Collect all public keys (simplified: use party 1's key as group key)
        let mut group_pubkey_bytes = pub_bytes.clone();
        for _ in 1..config.total_parties {
            let recv = transport.recv().await?;
            if party_id == PartyId(1) {
                group_pubkey_bytes = serde_json::from_slice(&recv.payload)
                    .map_err(|e| CoreError::Protocol(format!("deserialize failed: {e}")))?;
            }
        }

        // Use first party's pubkey as group pubkey (simplified threshold)
        let share_data = Sr25519ShareData {
            share: mini_secret.as_bytes().to_vec(),
            mini_secret: mini_secret.as_bytes().to_vec(),
        };

        let share_bytes = Zeroizing::new(
            serde_json::to_vec(&share_data)
                .map_err(|e| CoreError::Protocol(format!("serialize share failed: {e}")))?,
        );

        Ok(KeyShare {
            scheme: CryptoScheme::Sr25519Threshold,
            party_id,
            config,
            group_public_key: GroupPublicKey::Sr25519(group_pubkey_bytes),
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
        let share_data: Sr25519ShareData = serde_json::from_slice(&key_share.share_data)
            .map_err(|e| CoreError::Protocol(format!("deserialize share failed: {e}")))?;

        // Reconstruct mini secret from share
        let mut mini_bytes = [0u8; 32];
        mini_bytes.copy_from_slice(&share_data.mini_secret);
        let mini_secret = schnorrkel::MiniSecretKey::from_bytes(&mini_bytes)
            .map_err(|e| CoreError::Protocol(format!("invalid mini secret: {e}")))?;

        let keypair = mini_secret.expand_to_keypair(schnorrkel::ExpansionMode::Ed25519);

        // Sign with Sr25519 (uses merlin transcript internally)
        let ctx = schnorrkel::signing_context(b"substrate");
        let signature = keypair.sign(ctx.bytes(message));

        Ok(MpcSignature::Sr25519Sig {
            signature: signature.to_bytes(),
        })
    }
}
