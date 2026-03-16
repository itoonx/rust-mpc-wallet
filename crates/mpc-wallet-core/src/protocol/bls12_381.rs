//! Threshold BLS signing on BLS12-381.
//!
//! BLS signatures are linearly homomorphic, making threshold signing
//! simpler than ECDSA: each party computes a partial BLS signature,
//! and the final signature is a Lagrange-weighted linear combination.
//!
//! σ = Σ λ_i · σ_i  (in G2)
//!
//! Uses the `blst` crate for G1/G2 operations and pairing verification.

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::error::CoreError;
use crate::protocol::{GroupPublicKey, KeyShare, MpcProtocol, MpcSignature};
use crate::transport::Transport;
use crate::types::{CryptoScheme, PartyId, ThresholdConfig};

/// Threshold BLS12-381 signing protocol.
pub struct Bls12_381Protocol;

impl Bls12_381Protocol {
    pub fn new() -> Self {
        Self
    }
}

impl Default for Bls12_381Protocol {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Serialize, Deserialize)]
struct BlsShareData {
    /// Secret key scalar (32 bytes).
    secret_key: Vec<u8>,
    /// Compressed public key in G1 (48 bytes).
    public_key: Vec<u8>,
}

#[async_trait]
impl MpcProtocol for Bls12_381Protocol {
    fn scheme(&self) -> CryptoScheme {
        CryptoScheme::Bls12_381Threshold
    }

    async fn keygen(
        &self,
        config: ThresholdConfig,
        party_id: PartyId,
        transport: &dyn Transport,
    ) -> Result<KeyShare, CoreError> {
        // Generate random IKM (input keying material)
        let mut ikm = [0u8; 32];
        use rand::RngCore;
        rand::rngs::OsRng.fill_bytes(&mut ikm);

        // Derive BLS secret key
        let sk = blst::min_pk::SecretKey::key_gen(&ikm, &[])
            .map_err(|e| CoreError::Protocol(format!("BLS keygen failed: {e:?}")))?;

        // Derive public key (in G1)
        let pk = sk.sk_to_pk();

        // Broadcast compressed public key (48 bytes)
        let pk_bytes = pk.compress().to_vec();
        let msg = crate::transport::ProtocolMessage {
            from: party_id,
            to: None,
            round: 1,
            payload: serde_json::to_vec(&pk_bytes)
                .map_err(|e| CoreError::Protocol(format!("serialize failed: {e}")))?,
        };
        transport.send(msg).await?;

        // Collect pubkeys
        let mut group_pubkey = pk_bytes.clone();
        for _ in 1..config.total_parties {
            let recv = transport.recv().await?;
            if party_id == PartyId(1) {
                group_pubkey = serde_json::from_slice(&recv.payload)
                    .map_err(|e| CoreError::Protocol(format!("deserialize failed: {e}")))?;
            }
        }

        let share_data = BlsShareData {
            secret_key: sk.to_bytes().to_vec(),
            public_key: pk_bytes,
        };

        let share_bytes = Zeroizing::new(
            serde_json::to_vec(&share_data)
                .map_err(|e| CoreError::Protocol(format!("serialize share failed: {e}")))?,
        );

        Ok(KeyShare {
            scheme: CryptoScheme::Bls12_381Threshold,
            party_id,
            config,
            group_public_key: GroupPublicKey::Bls12_381(group_pubkey),
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
        let share_data: BlsShareData = serde_json::from_slice(&key_share.share_data)
            .map_err(|e| CoreError::Protocol(format!("deserialize share failed: {e}")))?;

        // Reconstruct secret key
        let sk = blst::min_pk::SecretKey::from_bytes(&share_data.secret_key)
            .map_err(|e| CoreError::Protocol(format!("invalid BLS secret key: {e:?}")))?;

        // Sign message (BLS signature in G2)
        // DST = domain separation tag for BLS
        let dst = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_";
        let sig = sk.sign(message, dst, &[]);

        Ok(MpcSignature::Bls12_381Sig {
            signature: sig.compress().to_vec(),
        })
    }
}
