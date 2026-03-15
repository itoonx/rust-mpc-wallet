pub mod frost_ed25519;
pub mod frost_secp256k1;
pub mod gg20;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::error::CoreError;
use crate::transport::Transport;
use crate::types::{CryptoScheme, PartyId, ThresholdConfig};

/// Helper for serde of [u8; 64] arrays.
mod serde_byte_array_64 {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8; 64], serializer: S) -> Result<S::Ok, S::Error> {
        bytes.as_slice().serialize(serializer)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<[u8; 64], D::Error> {
        let v: Vec<u8> = Vec::deserialize(deserializer)?;
        v.try_into()
            .map_err(|_| serde::de::Error::custom("expected exactly 64 bytes"))
    }
}

/// A share of a distributed key held by a single party.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyShare {
    /// The cryptographic scheme this key share belongs to.
    pub scheme: CryptoScheme,
    /// The party that holds this share.
    pub party_id: PartyId,
    /// Threshold configuration.
    pub config: ThresholdConfig,
    /// The group public key (shared across all parties).
    pub group_public_key: GroupPublicKey,
    /// Opaque serialized key share data (protocol-specific).
    pub share_data: Vec<u8>,
}

/// The group public key derived from the distributed key generation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum GroupPublicKey {
    /// Compressed secp256k1 public key (33 bytes).
    Secp256k1(Vec<u8>),
    /// Uncompressed secp256k1 public key (65 bytes).
    Secp256k1Uncompressed(Vec<u8>),
    /// Ed25519 public key (32 bytes).
    Ed25519(Vec<u8>),
}

impl GroupPublicKey {
    /// Get the raw bytes of the public key.
    pub fn as_bytes(&self) -> &[u8] {
        match self {
            GroupPublicKey::Secp256k1(b) => b,
            GroupPublicKey::Secp256k1Uncompressed(b) => b,
            GroupPublicKey::Ed25519(b) => b,
        }
    }
}

/// Signature produced by the MPC signing protocol.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MpcSignature {
    /// ECDSA signature (for EVM chains).
    Ecdsa {
        r: Vec<u8>,
        s: Vec<u8>,
        recovery_id: u8,
    },
    /// Schnorr signature (BIP-340, for Bitcoin Taproot).
    Schnorr {
        #[serde(with = "serde_byte_array_64")]
        signature: [u8; 64],
    },
    /// EdDSA signature (for Solana/Sui).
    EdDsa {
        #[serde(with = "serde_byte_array_64")]
        signature: [u8; 64],
    },
}

/// Core trait for MPC protocol implementations.
#[async_trait]
pub trait MpcProtocol: Send + Sync {
    /// Returns the cryptographic scheme this protocol implements.
    fn scheme(&self) -> CryptoScheme;

    /// Run distributed key generation.
    async fn keygen(
        &self,
        config: ThresholdConfig,
        party_id: PartyId,
        transport: &dyn Transport,
    ) -> Result<KeyShare, CoreError>;

    /// Run distributed signing.
    async fn sign(
        &self,
        key_share: &KeyShare,
        signers: &[PartyId],
        message: &[u8],
        transport: &dyn Transport,
    ) -> Result<MpcSignature, CoreError>;
}
