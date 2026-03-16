/// FROST threshold EdDSA protocol implementation for Ed25519 (Solana, Sui).
pub mod frost_ed25519;
/// FROST threshold Schnorr protocol implementation for secp256k1 with Taproot tweaks (Bitcoin).
pub mod frost_secp256k1;
/// GG20 threshold ECDSA protocol implementation for secp256k1 (EVM chains).
pub mod gg20;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

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

/// Custom serde helpers for `Zeroizing<Vec<u8>>`.
///
/// Serializes as a plain byte sequence and deserializes by wrapping in `Zeroizing::new(...)`,
/// ensuring that deserialized key material is automatically wiped from memory on drop.
mod serde_zeroizing_vec {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use zeroize::Zeroizing;

    /// Serialize `Zeroizing<Vec<u8>>` as a plain byte sequence.
    pub fn serialize<S: Serializer>(
        val: &Zeroizing<Vec<u8>>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        let bytes: &Vec<u8> = val.as_ref();
        bytes.serialize(serializer)
    }

    /// Deserialize a byte sequence into `Zeroizing<Vec<u8>>`, ensuring the bytes
    /// are wiped from heap memory when the returned value is dropped.
    pub fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Zeroizing<Vec<u8>>, D::Error> {
        let v: Vec<u8> = Vec::deserialize(deserializer)?;
        Ok(Zeroizing::new(v))
    }
}

/// A share of a distributed key held by a single party.
///
/// # Security
///
/// `share_data` contains the serialized secret key material for this party.
/// It is wrapped in [`Zeroizing<Vec<u8>>`] so the bytes are wiped from heap
/// memory when this `KeyShare` is dropped (SEC-004 root fix, T-S4-00).
///
/// **Do NOT clone this struct unnecessarily.** Every clone creates a new heap
/// allocation of key material — though the clone is also a `Zeroizing` wrapper
/// and will be wiped on drop.
///
/// **Do NOT derive `Debug` on this struct.** A manual `Debug` implementation
/// redacts `share_data` to prevent key bytes from appearing in logs (SEC-015 fix).
#[derive(Clone, Serialize, Deserialize)]
pub struct KeyShare {
    /// The cryptographic scheme this key share belongs to.
    pub scheme: CryptoScheme,
    /// The party that holds this share.
    pub party_id: PartyId,
    /// Threshold configuration.
    pub config: ThresholdConfig,
    /// The group public key (shared across all parties).
    pub group_public_key: GroupPublicKey,
    /// Serialized secret key share bytes (protocol-specific, zeroized on drop).
    ///
    /// Contains the serialized form of the inner share struct
    /// (e.g., `Gg20DistributedShareData`, `FrostEd25519ShareData`).
    /// The `Zeroizing` wrapper ensures bytes are cleared from heap memory
    /// when this `KeyShare` is dropped.
    ///
    /// # SEC-004 status
    /// Root fix applied in T-S4-00: field type changed from `Vec<u8>` to
    /// `Zeroizing<Vec<u8>>`. Protocol implementations must also wrap their
    /// keygen output in `Zeroizing::new(...)` (enforced in T-S4-01).
    #[serde(with = "serde_zeroizing_vec")]
    pub share_data: Zeroizing<Vec<u8>>,
}

/// Manual `Debug` implementation that redacts `share_data` to prevent secret key
/// bytes from appearing in log output (SEC-015 fix).
impl std::fmt::Debug for KeyShare {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeyShare")
            .field("scheme", &self.scheme)
            .field("party_id", &self.party_id)
            .field("config", &self.config)
            .field("group_public_key", &self.group_public_key)
            .field("share_data", &"[REDACTED]")
            .finish()
    }
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
        /// Big-endian `r` scalar of the ECDSA signature.
        r: Vec<u8>,
        /// Big-endian `s` scalar of the ECDSA signature.
        s: Vec<u8>,
        /// Recovery ID (0 or 1) needed to recover the public key from the signature.
        recovery_id: u8,
    },
    /// Schnorr signature (BIP-340, for Bitcoin Taproot).
    Schnorr {
        /// 64-byte BIP-340 Schnorr signature (`r || s`, big-endian).
        #[serde(with = "serde_byte_array_64")]
        signature: [u8; 64],
    },
    /// EdDSA signature (for Solana/Sui).
    EdDsa {
        /// 64-byte Ed25519 signature in the standard `R || S` encoding.
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
    ///
    /// Each party calls this with its own `party_id`. Communication between parties
    /// is coordinated via `transport`. Returns a [`KeyShare`] containing the party's
    /// secret share (wrapped in `Zeroizing`) and the shared group public key.
    async fn keygen(
        &self,
        config: ThresholdConfig,
        party_id: PartyId,
        transport: &dyn Transport,
    ) -> Result<KeyShare, CoreError>;

    /// Run distributed signing.
    ///
    /// Signs `message` using the threshold protocol, involving `signers` parties.
    /// No single party reconstructs the full private key. Returns the combined
    /// [`MpcSignature`] once all required parties have contributed their share.
    async fn sign(
        &self,
        key_share: &KeyShare,
        signers: &[PartyId],
        message: &[u8],
        transport: &dyn Transport,
    ) -> Result<MpcSignature, CoreError>;

    /// Run proactive key refresh (Epic H1, FR-H.1).
    ///
    /// Generates new key shares for all participating parties while keeping
    /// the group public key unchanged. Old shares should be zeroized after
    /// a successful refresh.
    ///
    /// # Default implementation
    /// Returns `CoreError::Protocol("refresh not implemented")` — protocols
    /// must override this method to support key refresh.
    ///
    /// # Arguments
    /// - `key_share` — the party's current key share (will be replaced).
    /// - `signers` — the set of parties participating in the refresh.
    /// - `transport` — message transport for inter-party communication.
    async fn refresh(
        &self,
        key_share: &KeyShare,
        signers: &[PartyId],
        transport: &dyn Transport,
    ) -> Result<KeyShare, CoreError> {
        let _ = (key_share, signers, transport);
        Err(CoreError::Protocol(format!(
            "{:?} does not support key refresh yet",
            self.scheme()
        )))
    }
}
