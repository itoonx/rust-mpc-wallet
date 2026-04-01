/// Threshold BLS12-381 protocol (Filecoin, Ethereum validators).
pub mod bls12_381;
/// CGGMP21 threshold ECDSA protocol on secp256k1 (next-gen, UC-secure).
pub mod cggmp21;
/// Shared helpers for secp256k1-based threshold protocols (GG20, CGGMP21).
pub mod common;
/// FROST threshold EdDSA protocol implementation for Ed25519 (Solana, Sui).
pub mod frost_ed25519;
/// FROST threshold Schnorr protocol implementation for secp256k1 with Taproot tweaks (Bitcoin).
pub mod frost_secp256k1;
/// GG20 threshold ECDSA protocol implementation for secp256k1 (EVM chains).
pub mod gg20;
/// Encrypted request context — IP, device, fingerprint for sign audit trail.
pub mod request_context;
/// Sign authorization proof — MPC nodes independently verify gateway decisions.
pub mod sign_authorization;
/// Threshold Sr25519 protocol on Ristretto255 (Substrate/Polkadot).
pub mod sr25519;
/// Threshold signing on Stark curve (StarkNet).
pub mod stark;

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
    /// Sr25519 public key on Ristretto255 (32 bytes).
    Sr25519(Vec<u8>),
    /// Stark curve public key (32 bytes).
    StarkCurve(Vec<u8>),
    /// BLS12-381 public key (48 bytes compressed G1).
    Bls12_381(Vec<u8>),
}

impl GroupPublicKey {
    /// Get the raw bytes of the public key.
    pub fn as_bytes(&self) -> &[u8] {
        match self {
            GroupPublicKey::Secp256k1(b) => b,
            GroupPublicKey::Secp256k1Uncompressed(b) => b,
            GroupPublicKey::Ed25519(b) => b,
            GroupPublicKey::Sr25519(b) => b,
            GroupPublicKey::StarkCurve(b) => b,
            GroupPublicKey::Bls12_381(b) => b,
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
    /// Sr25519 signature on Ristretto255 (for Substrate/Polkadot).
    Sr25519Sig {
        /// 64-byte Sr25519 Schnorr signature.
        #[serde(with = "serde_byte_array_64")]
        signature: [u8; 64],
    },
    /// STARK curve signature (for StarkNet).
    StarkSig {
        /// Stark field element r.
        r: Vec<u8>,
        /// Stark field element s.
        s: Vec<u8>,
    },
    /// BLS12-381 signature (for Filecoin, Ethereum validators).
    Bls12_381Sig {
        /// Compressed G2 point (96 bytes).
        signature: Vec<u8>,
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

    /// Proactive key refresh: generate new shares while preserving the group public key.
    ///
    /// Each participating party generates a random zero-constant polynomial,
    /// exchanges evaluations with other parties, and adds the aggregated delta
    /// to their existing Shamir share. The group public key remains unchanged
    /// because all zero-constant polynomials evaluate to 0 at x=0.
    ///
    /// The default implementation returns an error indicating that the protocol
    /// does not support key refresh. Override this in protocols that do.
    async fn refresh(
        &self,
        _key_share: &KeyShare,
        _signers: &[PartyId],
        _transport: &dyn Transport,
    ) -> Result<KeyShare, CoreError> {
        Err(CoreError::Protocol(
            "key refresh not supported by this protocol".into(),
        ))
    }

    /// Reshare key shares to a new threshold configuration (Epic H2).
    ///
    /// Unlike `refresh` which keeps the same (t,n), `reshare` can:
    /// - Change threshold: e.g., 2-of-3 -> 3-of-5
    /// - Add new parties
    /// - Remove old parties
    ///
    /// The group public key MUST remain unchanged.
    ///
    /// # Arguments
    ///
    /// * `key_share` - The existing key share held by this party (old parties only;
    ///   new-only parties should use a dummy share with zeroed share_data).
    /// * `old_signers` - The set of old parties participating in resharing (must
    ///   satisfy the old threshold).
    /// * `new_config` - The new threshold configuration (t_new, n_new).
    /// * `new_parties` - The set of new party IDs that will receive shares.
    /// * `transport` - Transport layer for inter-party communication.
    ///
    /// The default implementation returns an error indicating that the protocol
    /// does not support key resharing. Override this in protocols that do.
    async fn reshare(
        &self,
        _key_share: &KeyShare,
        _old_signers: &[PartyId],
        _new_config: ThresholdConfig,
        _new_parties: &[PartyId],
        _transport: &dyn Transport,
    ) -> Result<KeyShare, CoreError> {
        Err(CoreError::Protocol(format!(
            "{:?} does not support key resharing yet",
            self.scheme()
        )))
    }
}
