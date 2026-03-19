//! Enclave support: attestation verification and TEE provider abstraction.
//!
//! This module provides the [`EnclaveProvider`] trait for interacting with
//! Trusted Execution Environments (TEEs), the [`AttestationReport`] struct
//! representing a remote attestation quote, and the [`AttestationVerifier`]
//! for validating enclave identity and freshness.

pub mod attestation;

use crate::error::CoreError;

/// Opaque handle to an enclave instance.
///
/// Wraps a unique identifier (e.g., enclave ID or file descriptor) that
/// the runtime uses to route operations to the correct TEE context.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct EnclaveHandle {
    /// Unique identifier for this enclave instance.
    pub id: String,
}

/// Remote attestation report produced by a TEE.
///
/// Contains the measurement hashes and metadata needed to verify that
/// code is running inside a genuine, unmodified enclave.
#[derive(Debug, Clone)]
pub struct AttestationReport {
    /// MRENCLAVE: SHA-256 hash of the enclave code and initial data.
    /// Uniquely identifies the exact binary loaded into the enclave.
    pub mrenclave: [u8; 32],

    /// MRSIGNER: SHA-256 hash of the enclave signer's public key.
    /// Identifies who signed/built the enclave binary.
    pub mrsigner: [u8; 32],

    /// Unix timestamp (seconds) when the report was generated.
    pub timestamp: u64,

    /// Arbitrary user-supplied data bound into the attestation report.
    /// Typically contains a nonce or a hash of the session transcript
    /// to prevent replay and ensure freshness.
    pub report_data: Vec<u8>,
}

/// Trait for TEE providers (SGX, TDX, Nitro, etc.).
///
/// Implementors provide enclave lifecycle management and attestation
/// generation. Verification of received reports is handled separately
/// by [`attestation::AttestationVerifier`].
pub trait EnclaveProvider: Send + Sync {
    /// Generate an attestation report for this enclave, binding `user_data`
    /// into the report's `report_data` field.
    fn generate_attestation(&self, user_data: &[u8]) -> Result<AttestationReport, CoreError>;

    /// Return the handle for this enclave instance.
    fn handle(&self) -> &EnclaveHandle;
}
