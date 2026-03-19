//! SGX Enclave abstraction layer.
//!
//! Defines the [`EnclaveProvider`] trait for secure enclave operations:
//! loading key shares into enclave memory, performing MPC signing within
//! the enclave boundary, producing attestation reports, and securely
//! destroying enclave-held key material.
//!
//! The mock implementation ([`mock::MockEnclaveProvider`]) provides a
//! software-only version for testing and development.

pub mod mock;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::error::CoreError;
use crate::protocol::MpcSignature;
use crate::types::PartyId;

/// Serde helper for `[u8; 64]` arrays (report_data).
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

/// Opaque handle to a key share loaded inside an enclave.
///
/// The handle is a unique identifier that references enclave-internal
/// memory. The actual key material never leaves the enclave boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct EnclaveHandle(pub u64);

/// SGX attestation report returned by the enclave.
///
/// In production, this would be a genuine Intel SGX remote attestation
/// report (EPID or DCAP). The mock implementation returns deterministic
/// values derived from known seeds.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestationReport {
    /// MRENCLAVE measurement: SHA-256 hash of the enclave binary.
    pub mrenclave: [u8; 32],
    /// MRSIGNER measurement: SHA-256 hash of the enclave signer identity.
    pub mrsigner: [u8; 32],
    /// Timestamp (Unix seconds) when the report was generated.
    pub timestamp: u64,
    /// 64-byte report data (user-defined payload bound to the attestation).
    #[serde(with = "serde_byte_array_64")]
    pub report_data: [u8; 64],
}

/// Trait for SGX enclave operations.
///
/// Implementations provide key share loading, MPC signing, attestation,
/// and secure destruction of enclave-held secrets.
#[async_trait]
pub trait EnclaveProvider: Send + Sync {
    /// Load an encrypted key share into the enclave.
    ///
    /// Decrypts `encrypted_share` using `password` (AES-256-GCM + Argon2id)
    /// and stores the plaintext share in enclave-protected memory.
    /// Returns an opaque [`EnclaveHandle`] for subsequent operations.
    async fn load_share(
        &self,
        encrypted_share: &[u8],
        password: &str,
    ) -> Result<EnclaveHandle, CoreError>;

    /// Perform a partial MPC signature inside the enclave.
    ///
    /// Uses the key share referenced by `handle` to compute a partial
    /// signature over `message` with the given set of `signers`.
    async fn sign(
        &self,
        handle: EnclaveHandle,
        message: &[u8],
        signers: &[PartyId],
    ) -> Result<MpcSignature, CoreError>;

    /// Produce an attestation report for remote verification.
    ///
    /// In production, this would trigger an Intel SGX attestation flow.
    /// The mock implementation returns a deterministic report.
    async fn attestation_report(&self) -> Result<AttestationReport, CoreError>;

    /// Destroy the key share referenced by `handle`.
    ///
    /// Zeroizes the in-enclave memory and invalidates the handle.
    /// Calling destroy on an already-destroyed handle is a no-op.
    async fn destroy(&self, handle: EnclaveHandle) -> Result<(), CoreError>;
}
